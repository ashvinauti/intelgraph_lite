import json
import threading
import urllib.request
from types import SimpleNamespace

import pytest

from iglite import cases, demo, export, respond
from iglite.api import make_server
from iglite.cli import main
from iglite.config import load
from iglite.extract import treat_as_public
from iglite.notify import Notifier, message, send_teams


@pytest.fixture
def incident(tmp_path):
    """The demo network a minute in: four malicious alerts, a suspicious scanner."""
    engine, watch, network = demo.build(str(tmp_path / "demo.db"))
    engine.config.auto_case = False  # tests file alerts by hand unless they say otherwise
    with engine.store.transaction() as db:  # start without the demo's own seeded case
        for table in ("cases", "case_indicators", "case_events"):
            db.execute(f"DELETE FROM {table}")  # noqa: S608
    for ip, name in demo.DEVICES.items():
        network.gw.add(demo.Lease(ip, name))
    network.incidents(60)
    watch.scan()
    try:
        yield engine
    finally:
        engine.store.close()
        treat_as_public([])


def _alert(engine, key):
    return next(a for a in engine.store.alerts() if a["key"] == key)


# -- cases ---------------------------------------------------------------------------------


def test_case_groups_alerts_with_timeline_and_report(incident):
    store = incident.store
    c2 = _alert(incident, f"ip:{demo.C2_IP}")
    case_id = cases.create(store, "", severity="high", alerts=[c2["id"]])
    d = cases.detail(store, case_id)
    assert d["title"] == f"Malicious {demo.C2_IP} on Smart-Plug"
    assert [i["key"] for i in d["indicators"]] == [f"ip:{demo.C2_IP}", "host:10.42.0.61"]
    assert [x["name"] for x in d["devices"]] == ["Smart-Plug"]
    assert {"T1571", "T1071"} <= {t["id"] for t in d["techniques"]}

    cases.note(store, case_id, "Plug unplugged by the owner")
    cases.update(store, case_id, status="investigating")
    with pytest.raises(ValueError):
        cases.update(store, case_id, status="done")
    kinds = [e["kind"] for e in cases.detail(store, case_id)["timeline"]]
    assert kinds == ["created", "alert", "note", "status"]

    md = cases.report(store, case_id)
    assert md.startswith(f"# Case {case_id}: Malicious {demo.C2_IP}")
    assert "Plug unplugged" in md and "T1571" in md and "Smart-Plug (10.42.0.61)" in md

    cases.detach_alert(store, case_id, c2["id"])
    assert cases.detail(store, case_id)["alerts"] == []


def test_new_alerts_join_the_open_case_that_holds_their_device(incident):
    store = incident.store
    phish = _alert(incident, f"domain:{demo.PHISH}")  # on the Kids-iPad
    case_id = cases.create(store, "iPad compromise", indicators=["host:10.42.0.23"])
    assert cases.auto_attach(store, phish["id"]) == case_id
    assert store.alert(phish["id"])["case_id"] == case_id
    assert cases.auto_attach(store, _alert(incident, f"ip:{demo.C2_IP}")["id"]) is None  # other device
    cases.update(store, case_id, status="closed")
    other = store.add_alert(f"domain:{demo.PHISH}", "malicious", 90, json.dumps({"device": "10.42.0.23"}))
    assert cases.auto_attach(store, other) is None  # closed cases take nothing new


def test_engine_files_alerts_automatically(tmp_path):
    engine, watch, network = demo.build(str(tmp_path / "d.db"))
    try:
        case_id = cases.create(engine.store, "Botnet", indicators=[f"ip:{demo.C2_IP}"])
        network.incidents(60)
        watch.scan()
        assert [a["key"] for a in engine.store.case_alerts(case_id)] == [f"ip:{demo.C2_IP}"]
    finally:
        engine.store.close()
        treat_as_public([])


def test_cli_case(incident, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: incident)
    monkeypatch.setattr(incident.store, "close", lambda: None)
    alert = _alert(incident, f"domain:{demo.MINER}")
    assert main(["case", "new", "TV", "mining", "--alert", str(alert["id"]), "--severity", "low"]) == 0
    assert "Opened case #1" in capsys.readouterr().out
    assert main(["case", "note", "1", "Factory reset", "planned"]) == 0
    assert main(["case", "status", "1", "investigating"]) == 0
    assert main(["case", "list"]) == 0
    assert "investigating" in capsys.readouterr().out
    out = tmp_path / "case.md"
    assert main(["case", "report", "1", "-o", str(out)]) == 0
    assert "Factory reset planned" in out.read_text()
    with pytest.raises(SystemExit, match="no case 9"):
        main(["case", "note", "9", "x"])


# -- blocking ----------------------------------------------------------------------------


def test_block_reaches_feeds_cases_and_firewall(incident):
    store = incident.store
    case_id = cases.create(store, "Botnet", indicators=[f"ip:{demo.C2_IP}"])
    calls = []
    incident.config.enforce = "nftables"
    incident.config.block_hosts = None
    fake = lambda argv, **kw: (calls.append((argv, kw["input"])), SimpleNamespace(returncode=0, stderr=""))[1]  # noqa: E731
    real = respond.LocalEnforcer
    respond_enforcer = lambda cfg: real(cfg, run=fake)  # noqa: E731
    import iglite.respond as r

    original, r.LocalEnforcer = r.LocalEnforcer, respond_enforcer
    try:
        res = respond.block(incident, demo.C2_IP, note="C2 server")
        assert res["added"] and res["enforcement"]["ok"]
        res = respond.block(incident, "10.42.0.61", device=True)
        assert res["kind"] == "device"
    finally:
        r.LocalEnforcer = original
    script = calls[-1][1]
    assert f"elements = {{ {demo.C2_IP} }}" in script and "elements = { 10.42.0.61 }" in script
    assert script.startswith("table inet iglite\ndelete table inet iglite\n")
    assert demo.C2_IP in export.blocklist(store, "ip").split()
    assert f"Blocked ip:{demo.C2_IP}: C2 server" in [
        e["text"] for e in cases.detail(store, case_id)["timeline"]
    ]
    assert {d["ip"]: d["quarantined"] for d in incident.watcher().devices()}["10.42.0.61"] is True

    respond.unblock(incident, demo.C2_IP)
    assert demo.C2_IP in export.blocklist(store, "ip").split()  # still malicious, still listed
    with pytest.raises(KeyError):
        respond.unblock(incident, demo.C2_IP)
    with pytest.raises(ValueError):
        respond.block(incident, "T1071")
    with pytest.raises(ValueError):
        respond.block(incident, "not-an-ip", device=True)


def test_hand_blocks_are_listed_even_when_not_malicious(incident):
    respond.block(incident, "static-cdn.example")
    assert "static-cdn.example" in export.blocklist(incident.store, "domain").split()


def test_domain_blocks_go_to_a_dnsmasq_hosts_file(incident, tmp_path):
    hosts = tmp_path / "blocked.hosts"
    incident.config.block_hosts = str(hosts)
    reloads = []
    enf = respond.LocalEnforcer(incident.config, reload_dns=lambda: reloads.append(1) or 1)
    incident.store.add_block("indicator", f"domain:{demo.PHISH}")
    incident.store.add_block("indicator", f"url:{demo.DROPPER_URL}")
    status = enf.apply(incident.store)
    assert status["ok"] and reloads
    text = hosts.read_text()
    assert f"0.0.0.0 {demo.PHISH}\n" in text and f"0.0.0.0 {demo.DROPPER}\n" in text


def test_nftables_failure_is_reported_not_raised(incident):
    incident.config.enforce = "nftables"
    enf = respond.LocalEnforcer(
        incident.config, run=lambda *a, **k: SimpleNamespace(returncode=1, stderr="Operation not permitted")
    )
    status = enf.apply(incident.store)
    assert not status["ok"] and "Operation not permitted" in status["detail"]


# -- path finder -------------------------------------------------------------------------


def test_path_links_a_device_to_the_report_without_using_hubs(incident):
    store = incident.store
    found = store.path(
        "host:10.42.0.52", f"url:{demo.DROPPER_URL}", avoid=("tag:", "technique:", "host:gateway")
    )
    keys = [n["key"] for n in found["nodes"]]
    assert keys[0] == "host:10.42.0.52" and keys[-1] == f"url:{demo.DROPPER_URL}"
    assert not any(k.startswith(("tag:", "technique:", "host:gateway")) for k in keys)
    assert found["hops"] == len(found["edges"]) == len(keys) - 1
    # devices only meet through the gateway, which is skipped
    assert store.path("host:10.42.0.52", "host:10.42.0.31", avoid=("host:gateway",), max_hops=2) is None
    assert store.path("host:10.42.0.52", "host:10.42.0.31")["hops"] == 2


def test_cli_path(incident, capsys, monkeypatch):
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: incident)
    monkeypatch.setattr(incident.store, "close", lambda: None)
    with pytest.raises(SystemExit, match="not in the graph"):  # devices are host:..., not IPs
        main(["path", "10.42.0.61", demo.C2_IP])
    capsys.readouterr()
    assert main(["path", "host:10.42.0.61", demo.C2_IP]) == 0
    assert "--connected_to-->" in capsys.readouterr().out


# -- notifications -----------------------------------------------------------------------


def test_notifications_go_to_every_channel_and_respect_the_floor(incident):
    sent = []
    cfg = incident.config
    cfg.offline = False
    cfg.notify = {"slack": "https://slack.example/hook", "webhook": "https://hooks.example/x"}
    cfg.dashboard_url = "http://10.42.0.1:8765"
    senders = {
        "slack": lambda url, msg, **k: sent.append(("slack", url, msg["title"])),
        "webhook": lambda url, msg, **k: (_ for _ in ()).throw(OSError("down")),
    }
    n = Notifier(cfg, incident.store, senders)
    mal = _alert(incident, f"ip:{demo.C2_IP}")
    results = n.send_now(message(mal, None, cfg.dashboard_url))
    assert sent == [
        ("slack", "https://slack.example/hook", f"Malicious ip: {demo.C2_IP} (score {mal['score']})")
    ]
    assert [r["ok"] for r in results] == [True, False] and "down" in results[1]["detail"]
    sus = incident.store.add_alert(f"ip:{demo.SCANNER}", "suspicious", 40, "{}")
    assert not n.on_alert(sus)  # below the malicious floor
    cfg.notify_per_hour = 1
    assert n.on_alert(mal["id"]) and not n.on_alert(mal["id"])  # hourly cap
    cfg.offline = True
    assert not Notifier(cfg, incident.store, senders).on_alert(mal["id"])


def test_teams_payload_is_an_adaptive_card(monkeypatch):
    posted = {}
    monkeypatch.setattr("iglite.notify._post", lambda url, payload: posted.update(payload))
    alert = {
        "key": "domain:bad.example",
        "verdict": "malicious",
        "score": 90,
        "context": {"device_name": "Laptop", "device": "10.0.0.5", "query": True, "attack": ["T1566"]},
    }
    send_teams("https://teams.example", message(alert, 3, "http://gw:8765"))
    card = posted["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["actions"][0]["url"] == "http://gw:8765/#live"
    texts = [b["text"] for b in card["body"]]
    assert "Laptop (10.0.0.5) looked up bad.example" in texts and "Filed in case #3" in texts


def test_notify_settings_come_from_the_environment():
    cfg = load(
        env={
            "IGLITE_NOTIFY_SLACK": "https://s",
            "IGLITE_SMTP_HOST": "smtp.example",
            "IGLITE_DASHBOARD_URL": "http://x",
        }
    )
    assert (
        cfg.notify == {"slack": "https://s"}
        and cfg.smtp == {"host": "smtp.example"}
        and cfg.dashboard_url == "http://x"
    )


# -- API ---------------------------------------------------------------------------------


def test_api_cases_blocks_path(incident):
    incident.config.api_token = None
    srv = make_server(incident, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(path, body=None):
        req = urllib.request.Request(
            base + path, data=json.dumps(body).encode() if body is not None else None
        )
        try:
            with opener.open(req, timeout=5) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if resp.headers[
                    "Content-Type"
                ] == "application/json" else raw.decode()
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        alert = _alert(incident, f"domain:{demo.DROPPER}")
        status, case = call("/api/cases", {"alerts": [alert["id"]], "severity": "critical"})
        assert status == 200 and case["severity"] == "critical" and case["alerts"][0]["id"] == alert["id"]
        assert call("/api/case/note", {"id": case["id"], "text": "Laptop reimaged"})[0] == 200
        assert call("/api/case/update", {"id": case["id"], "status": "nope"})[0] == 400
        assert call("/api/case?id=99")[0] == 404
        status, cases_list = call("/api/cases")
        assert [c["alerts"] for c in cases_list] == [1]
        status, md = call(f"/api/case/report?id={case['id']}")
        assert "Laptop reimaged" in md

        status, res = call("/api/block", {"value": demo.DROPPER, "case_id": case["id"]})
        assert status == 200 and res["value"] == f"domain:{demo.DROPPER}"
        status, info = call(f"/api/indicator?key=domain:{demo.DROPPER}")
        assert info["blocked"] and info["cases"][0]["id"] == case["id"]
        assert call("/api/unblock", {"value": "1.1.1.1"})[0] == 404

        status, path = call(f"/api/path?from=host:10.42.0.52&to=url:{demo.DROPPER_URL}")
        assert path["found"] and path["nodes"][0]["key"] == "host:10.42.0.52"
        assert call("/api/notify/test", {})[0] == 400  # nothing configured
    finally:
        srv.shutdown()
        srv.server_close()


def test_an_existing_database_is_upgraded_in_place(tmp_path):
    import sqlite3

    from iglite.store import Store

    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL); INSERT INTO meta VALUES ('schema_version', '5');"
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY, at REAL NOT NULL, key TEXT NOT NULL, verdict TEXT NOT NULL,"
        " score INTEGER NOT NULL, context TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'open');"
        "INSERT INTO alerts (at, key, verdict, score) VALUES (1, 'ip:203.0.113.9', 'malicious', 90);"
    )
    db.commit()
    db.close()
    store = Store(path)
    case_id = cases.create(store, "", alerts=[1])
    assert store.alert(1)["case_id"] == case_id
    store.close()
