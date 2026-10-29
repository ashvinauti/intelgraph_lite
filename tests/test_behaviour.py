import json
import threading
import time
import urllib.request

import pytest

from iglite import cases, demo
from iglite.api import make_server
from iglite.behaviour import beacon, randomness, site
from iglite.cli import main
from iglite.extract import treat_as_public
from iglite.notify import Notifier

# -- the building blocks ---------------------------------------------------------------------


def test_site_and_randomness():
    assert site("a.b.example.co.uk") == "example.co.uk" and site("r3.googlevideo.com") == "googlevideo.com"
    for generated in ("xq7vk2zp9tl.com", "kz8qw3vxn5rt.net", "a1b2c3d4e5f6.com"):
        assert randomness(generated) >= 0.7, generated
    for real in (
        "stackoverflow.com",
        "microsoftonline.com",
        "cloudflareinsights.com",
        "account-verify-login.com",
        "d3kq1x7z9.cloudfront.net",
        "wikipedia.org",
        "xn--80ak6aa92e.com",
    ):
        assert randomness(real) < 0.7, real


def test_beacon_needs_steady_repeated_check_ins():
    now = 1_000_000.0
    steady = [now - 600 + 60 * i for i in range(10)]
    b = beacon(steady, now)
    assert b["period"] == 60 and b["count"] == 10 and b["jitter"] == 0
    assert beacon(steady[:5], now) is None  # too few
    jittery = [now - 600 + t for t in (0, 5, 70, 80, 200, 330, 340, 500, 590)]
    assert beacon(jittery, now) is None
    batched = [now - 300 + 30 * (i // 3) for i in range(30)]  # a 30 s scan sees three at a time
    assert beacon(batched, now)["period"] == 30
    assert beacon([now - 7200 + 10 * i for i in range(10)], now) is None  # over an hour ago


# -- on the demo network ---------------------------------------------------------------------


@pytest.fixture
def home(tmp_path):
    """The demo network with a week of seeded habits, then a minute of incidents."""
    engine, watch, network = demo.build(str(tmp_path / "demo.db"))
    for ip, name in demo.DEVICES.items():
        network.gw.add(demo.Lease(ip, name))
    try:
        yield engine, watch, network
    finally:
        engine.store.close()
        treat_as_public([])


def _found(engine):
    return {(a["who"], a["kind"], a["remote"]): a for a in engine.store.anomalies(limit=1000)}


def test_ordinary_days_raise_nothing(home):
    engine, watch, network = home
    for _ in range(5):
        network.background()
        watch.scan()
    assert engine.store.anomalies() == []
    assert engine.behaviour().status()["learning"] == 0


def test_each_incident_shows_up_once_and_the_right_way(home):
    engine, watch, network = home
    network.background()
    network.incidents(60)
    watch.scan()
    found = _found(engine)
    plug = found[("host:10.42.0.61", "new_port", "port:4444/tcp")]
    assert (
        plug["severity"] == "high"
        and "Metasploit" in plug["detail"]
        and "never contacted before" in plug["detail"]
    )
    assert (
        found[("host:10.42.0.31", "new_port", "port:3333/tcp")]["severity"] == "high"
    )  # the TV's mining pool
    assert (
        found[("host:10.42.0.70", "new_inbound", "port:22/tcp")]["severity"] == "high"
    )  # scanner reaches the NAS
    assert found[("host:10.42.0.23", "new_destination", f"domain:{demo.PHISH}")]["severity"] == "medium"
    assert found[("host:10.42.0.88", "new_port", "port:8443/tcp")]  # the doorbell's new server
    dga = [k for k in found if k[1] == "dga"]
    assert sorted(k[2] for k in dga) == sorted(f"domain:{d}" for d in demo.DGA_DOMAINS)
    assert all(found[k]["severity"] == "high" and k[0] == "host:10.42.0.40" for k in dga)
    # no duplicates: the generated names aren't "new destinations" too, the plug's C2 isn't twice
    assert not any(k[1] == "new_destination" and k[2] in {d[2] for d in dga} for k in found)
    assert ("host:10.42.0.61", "new_destination", f"ip:{demo.C2_IP}") not in found
    # generated names get behaviour evidence in their score
    reasons = engine.assess(f"domain:{demo.DGA_DOMAINS[0]}").as_dict()["reasons"]
    assert any(r["source"] == "behaviour" for r in reasons)

    # the same thing again within a day: counted, not repeated
    network.gw.add(demo.Flow("10.42.0.61", demo.C2_IP, 51111, 4444, "tcp", "pass"))
    engine.behaviour().profiles.clear()
    before = len(found)
    watch.scan()
    assert len(_found(engine)) == before


def test_beaconing_is_caught_without_any_intelligence(home):
    engine, watch, network = home
    gw = network.gw
    now = time.time()
    key = ("10.42.0.88", "tcp", demo.DOORBELL_C2, 8443, False)
    with gw._lock:
        for i in range(8):
            gw._start(key, 50000 + i, now - 80 + 10 * i)
    engine.store.upsert_node(demo.Indicator(demo.Kind.IP, demo.DOORBELL_C2))
    assert engine.store.node(f"ip:{demo.DOORBELL_C2}")["verdict"] in (None, "unknown")  # no feed knows it
    new = engine.behaviour().observe([], [], gw.recent_starts(now=now), now)
    b = next(a for a in new if a["kind"] == "beaconing")
    assert b["who"] == "host:10.42.0.88" and b["severity"] == "high" and b["context"]["period"] == 10
    assert "every 10 s" in b["detail"]
    node = engine.store.node(f"ip:{demo.DOORBELL_C2}")
    assert node["verdict"] == "suspicious"  # behaviour evidence moved its score
    # a common service checking in regularly is normal (push notifications, time sync)
    with gw._lock:
        for i in range(8):
            gw._start(("10.42.0.11", "tcp", "198.51.100.11", 443, False), 40000 + i, now - 80 + 10 * i)
    gw.add(demo.DnsEvent(None, "video-stream.example", ("198.51.100.11",)))
    gw.add(demo.Flow("10.42.0.11", "198.51.100.11", 40999, 443, "tcp", "pass"))  # the latest check-in
    watch.scan()
    assert not any(
        a["kind"] == "beaconing" and a["who"] == "host:10.42.0.11" for a in engine.store.anomalies()
    )


def test_this_is_normal_is_learned(home):
    engine, watch, network = home
    network.incidents(60)
    watch.scan()
    a = _found(engine)[("host:10.42.0.70", "new_inbound", "port:22/tcp")]
    assert engine.store.set_anomaly_status(a["id"], "normal")
    engine.store.prune_behaviour(0)  # even after pruning, "normal" is a rule
    beh = engine.behaviour()
    beh.REPEAT_AFTER = 0  # would otherwise be a repeat
    beh.profiles.clear()
    engine.store.log_connections([])  # nothing else changes
    network.gw.add(demo.Flow(demo.SCANNER, "10.42.0.70", 40099, 22, "tcp", "pass"))
    watch.scan()
    rows = [x for x in engine.store.anomalies(limit=1000) if x["kind"] == "new_inbound"]
    assert len(rows) == 1 and rows[0]["status"] == "normal"


def test_new_devices_learn_first_but_generated_names_count_at_once(home):
    engine, watch, network = home
    network.gw.add(demo.Lease("10.42.0.99", "New-Tablet"))
    network.gw.add(demo.Flow("10.42.0.99", "203.0.113.150", 50000, 6667, "tcp", "pass"))
    network.gw.add(demo.DnsEvent("10.42.0.99", "zk4xq9vtr7mw.example"))
    watch.scan()
    found = _found(engine)
    assert ("host:10.42.0.99", "dga", "domain:zk4xq9vtr7mw.example") in found
    assert not any(k[0] == "host:10.42.0.99" and k[1] == "new_port" for k in found)  # still learning
    assert engine.behaviour().profile("host:10.42.0.99").learning


def test_odd_hours_and_traffic_spikes(make_engine):
    engine = make_engine()
    store = engine.store
    t = time.localtime()
    three_am = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 3, 30, 0, 0, 0, -1))
    now = three_am if three_am < time.time() else three_am - 86400
    who = "host:192.168.1.50"
    for d in range(1, 11):  # ten days, busy 9:00 to 17:00 only
        day0 = time.mktime(time.localtime(now - d * 86400)[:3] + (0, 0, 0, 0, 0, -1))
        store.log_connections(
            [(day0 + 9 * 3600, who, "203.0.113.5", 443, "tcp", False, "office.example", 10)]
        )
        store.add_activity((who, int((day0 + h * 3600) // 3600), 40, 5) for h in range(9, 17))
    rows = [(now, who, "203.0.113.5", 443, "tcp", False, "office.example", 600)]
    new = engine.behaviour().observe(rows, [], {}, now)
    kinds = {a["kind"]: a for a in new}
    assert (
        kinds["odd_hour"]["remote"] == "hour:3"
        and "quiet every day for 10 days" in kinds["odd_hour"]["detail"]
    )
    assert kinds["volume_spike"]["context"]["p95"] == 40
    assert "new_port" not in kinds and "new_destination" not in kinds  # known server and port
    assert engine.behaviour().observe(rows, [], {}, now + 60) == []  # once per hour


def test_anomalies_reach_cases_and_notifications(home):
    engine, watch, network = home
    case_id = cases.create(engine.store, "Doorbell acting up", indicators=["host:10.42.0.88"])
    sent = []
    engine.config.offline = False
    engine.config.notify = {"webhook": "https://hooks.example/x"}
    engine._notifier = Notifier(
        engine.config, engine.store, {"webhook": lambda url, msg, **k: sent.append(msg)}
    )
    network.incidents(60)
    watch.scan()
    events = [e["text"] for e in cases.detail(engine.store, case_id)["timeline"] if e["kind"] == "behaviour"]
    assert any("8443" in e for e in events)
    deadline = time.time() + 5
    while time.time() < deadline and not sent:
        time.sleep(0.05)
    titles = {m["title"] for m in sent}
    assert any(t.startswith("Behaviour: New port on Smart-Plug (high)") for t in titles)
    assert not any("(medium)" in t for t in titles)  # behaviour_notify = high
    engine.config.behaviour_notify = "off"
    assert not engine.notifier().on_anomaly(engine.store.anomalies()[0])


def test_api_and_cli(home, capsys, monkeypatch):
    engine, watch, network = home
    network.incidents(60)
    watch.scan()
    engine.config.api_token = None
    srv = make_server(engine, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def call(path, body=None):
        req = urllib.request.Request(
            base + path, data=json.dumps(body).encode() if body is not None else None
        )
        try:
            with opener.open(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        status, r = call("/api/behaviour?status=open&severity=high")
        assert status == 200 and r["status"]["devices"] == 8 and r["status"]["high"] >= 7
        assert {a["label"] for a in r["anomalies"]} >= {
            "New port",
            "New inbound connection",
            "Generated-looking domain",
        }
        plug = next(d for d in r["devices"] if d["who"] == "host:10.42.0.61")
        assert (
            plug["name"] == "Smart-Plug"
            and not plug["learning"]
            and plug["narrow"]
            and len(plug["hours"]) == 24
        )
        assert plug["worst"] == "high"
        one = call("/api/behaviour?who=10.42.0.40&anomalies_only=1")[1]
        assert one["devices"] == [] and {a["who"] for a in one["anomalies"]} == {"host:10.42.0.40"}
        aid = one["anomalies"][0]["id"]
        assert call("/api/behaviour/anomaly", {"id": aid, "status": "normal"})[1]["status"] == "normal"
        assert call("/api/behaviour/anomaly", {"id": aid, "status": "nope"})[0] == 400
        assert call("/api/behaviour/anomaly", {"id": 99999, "status": "open"})[0] == 404
        info = call(f"/api/indicator?key=ip:{demo.C2_IP}")[1]
        assert any(a["kind"] == "new_port" for a in info["anomalies"])
    finally:
        srv.shutdown()
        srv.server_close()

    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    assert main(["behaviour"]) == 0
    out = capsys.readouterr().out
    assert "Smart-Plug" in out and "New port" in out and "Metasploit" in out
    assert main(["behaviour", "devices"]) == 0
    out = capsys.readouterr().out
    assert "host:10.42.0.61" in out and "baseline from" in out and "narrow" in out
    first = engine.store.anomalies()[0]["id"]
    assert main(["behaviour", "mark", str(first), "dismissed"]) == 0
    assert engine.store.anomaly(first)["status"] == "dismissed"
    with pytest.raises(SystemExit):
        main(["behaviour", "mark", "abc", "normal"])
