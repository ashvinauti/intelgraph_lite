"""False-positive controls: freshness, shared infrastructure, analyst feedback, alert policy."""

import json
import sqlite3
import threading
import urllib.error
import urllib.request

import pytest

from iglite.api import make_server
from iglite.cli import main
from iglite.extract import classify
from iglite.model import Evidence, Relation, Verdict
from iglite.netwatch import Connection, NetWatch, Snapshot
from iglite.scoring import assess, freshness
from iglite.store import Store

TRUST = {"a": 0.8, "b": 0.8}
NOW = 1_800_000_000.0
DAY = 86400


def ev(src, verdict=Verdict.MALICIOUS, age_days=None):
    return Evidence(
        src, verdict, f"{src} flags it", 1.0, None, None if age_days is None else NOW - age_days * DAY
    )


# -- freshness ---------------------------------------------------------------------


def test_freshness_halves_per_half_life_with_a_floor():
    assert freshness(None, NOW) == 1.0
    assert freshness(NOW - 180 * DAY, NOW) == pytest.approx(0.5)
    assert freshness(NOW - 3650 * DAY, NOW) == 0.1


def test_stale_corroboration_no_longer_convicts():
    fresh = assess([ev("a", age_days=1), ev("b", age_days=1)], TRUST, now=NOW)
    stale = assess([ev("a", age_days=730), ev("b", age_days=730)], TRUST, now=NOW)
    assert fresh.verdict is Verdict.MALICIOUS
    assert stale.verdict is not Verdict.MALICIOUS
    assert "last seen 2 years ago" in stale.reasons[0].detail


def test_benign_evidence_does_not_fade():
    old_good = Evidence("a", Verdict.BENIGN, "allowlisted", 1.0, None, NOW - 3650 * DAY)
    assert assess([old_good], TRUST, now=NOW).reasons[0].contribution == pytest.approx(-2.4)


# -- shared infrastructure ---------------------------------------------------------------


def test_shared_infrastructure_halves_ip_reputation():
    plain = assess([ev("a"), ev("b")], TRUST, now=NOW)
    shared = assess([ev("a"), ev("b")], TRUST, shared_infra="Cloudflare", now=NOW)
    assert plain.verdict is Verdict.MALICIOUS and shared.verdict is Verdict.SUSPICIOUS
    assert any(r.source == "context" and "Cloudflare" in r.detail for r in shared.reasons)


def test_engine_detects_shared_infrastructure(make_engine):
    engine = make_engine()
    ip = classify("104.16.1.1")
    engine.store.upsert_node(ip, {"rdap.net_name": "CLOUDFLARENET"})
    assert engine.shared_infra(engine.store.node(ip.key)) == "Cloudflare"
    engine.store.upsert_node(classify("45.155.205.1"), {"internetdb.tags": ["cdn"]})
    assert engine.shared_infra(engine.store.node("ip:45.155.205.1")) == "CDN"
    engine.store.upsert_node(classify("45.155.205.2"), {"rdap.net_name": "SMALL-HOSTER"})
    assert engine.shared_infra(engine.store.node("ip:45.155.205.2")) is None
    engine.store.upsert_node(classify("cloudflare.com"))
    assert engine.shared_infra(engine.store.node("domain:cloudflare.com")) is None  # IPs only


# -- analyst feedback ----------------------------------------------------------------------


@pytest.fixture
def flagged(make_engine, lists):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    engine.investigate([classify("203.0.113.66"), classify("http://evil.example/payload.bin")], depth=1)
    assert engine.assess("ip:203.0.113.66").verdict is Verdict.MALICIOUS
    return engine


def test_mark_false_positive_overrides_and_is_explained(flagged):
    a = flagged.set_feedback("ip:203.0.113.66", "false_positive", "our office VPN gateway")
    assert (a.verdict, a.override) == (Verdict.BENIGN, "false_positive") and a.score <= 5
    assert a.reasons[0].source == "analyst" and "office VPN" in a.reasons[0].detail
    assert any(r.source == "bad" for r in a.reasons)  # evidence still visible
    assert flagged.store.node("ip:203.0.113.66")["verdict"] == "benign"  # persisted

    a = flagged.set_feedback("ip:203.0.113.66", None)
    assert a.verdict is Verdict.MALICIOUS and a.override is None
    with pytest.raises(KeyError):
        flagged.set_feedback("ip:9.9.9.9", "false_positive")
    with pytest.raises(ValueError):
        flagged.set_feedback("ip:203.0.113.66", "maybe")


def test_false_positive_stops_guilt_by_association(flagged):
    domain = "domain:evil.example"
    flagged.store.add_relation(
        Relation(classify("evil.example"), "resolves_to", classify("203.0.113.66")), "test"
    )
    assert any(r.source == "graph" for r in flagged.assess(domain).reasons)
    flagged.set_feedback("ip:203.0.113.66", "false_positive")
    assert not any(r.source == "graph" and "203.0.113.66" in r.detail for r in flagged.assess(domain).reasons)


def test_confirm_and_per_source_stats(flagged):
    flagged.set_feedback("ip:203.0.113.66", "false_positive")
    a = flagged.set_feedback("domain:evil.example", "confirmed")
    assert a.verdict is Verdict.MALICIOUS and a.score >= 95
    stats = flagged.store.source_feedback_stats()
    assert stats["bad"] == {"false_positives": 1, "confirmed": 1}
    assert stats["other"] == {"false_positives": 1, "confirmed": 0}


# -- alerting policy -------------------------------------------------------------------------


def snapshot(*conns):
    return lambda: Snapshot(list(conns))


def conn(ip, process="app.exe"):
    return Connection("tcp", "192.168.1.5:5000", ip, 443, "ESTABLISHED", 7, process)


@pytest.fixture
def public(monkeypatch):
    monkeypatch.setattr("iglite.netwatch.is_public", lambda ind: not ind.value.startswith("192.168."))


def test_weak_signals_show_but_do_not_alert(make_engine, lists, public):
    engine = make_engine(blocklists={"bad": lists["bad"]})  # one list -> score 52
    watch = NetWatch(engine, collector=snapshot(conn("203.0.113.66")))
    assert watch.scan()["alerts"] == 0
    assert watch.rows[0]["verdict"] == "suspicious"  # still visible in the table


def test_suppression_rules(flagged, public):
    watch = NetWatch(flagged, collector=snapshot(conn("203.0.113.66", "VPNClient.exe")))
    flagged.store.add_suppression("process", "vpnclient.exe", "company VPN")
    assert watch.scan()["alerts"] == 0 and watch.rows[0]["suppressed"] is True
    rule = flagged.store.suppressions()[0]["id"]
    flagged.store.remove_suppression(rule)
    flagged.store.add_suppression("indicator", "ip:203.0.113.66")
    assert NetWatch(flagged, collector=watch.collector).scan()["alerts"] == 0
    flagged.store.remove_suppression(flagged.store.suppressions()[0]["id"])
    assert NetWatch(flagged, collector=watch.collector).scan()["alerts"] == 1


def test_marking_resolves_open_alerts_and_prevents_new_ones(flagged, public):
    watch = NetWatch(flagged, collector=snapshot(conn("203.0.113.66")))
    assert watch.scan()["alerts"] == 1
    flagged.set_feedback("ip:203.0.113.66", "false_positive")
    assert flagged.store.alerts()[0]["status"] == "false_positive"
    assert NetWatch(flagged, collector=watch.collector).scan()["alerts"] == 0
    flagged.set_feedback("ip:203.0.113.66", None)
    assert flagged.store.alerts()[0]["status"] == "open"


# -- sources -------------------------------------------------------------------------------


def test_otx_known_good_signals_count_against(transport):
    from iglite.config import Config
    from iglite.fetch import Fetcher
    from iglite.sources.base import Context
    from iglite.sources.cti import OTX

    transport.add(
        "https://otx.alienvault.com/api/v1/indicators/domain/popular.example/general",
        body={
            "pulse_info": {
                "pulses": [{"name": "Old phishing list", "modified": "2019-03-01T00:00:00", "tags": []}]
            },
            "validation": [
                {"source": "majestic", "message": "Whitelisted domain popular.example", "name": "Whitelisted"}
            ],
            "false_positive": [{"report_date": "2024-01-01"}],
        },
    )
    ctx = Context(Fetcher(Store(), transport=transport), Config(db=":memory:", keys={"otx": "k"}))
    f = OTX().lookup(classify("popular.example"), ctx)
    bad = next(e for e in f.evidence if e.verdict is Verdict.MALICIOUS)
    assert bad.last_seen == pytest.approx(1551398400)
    good = [e for e in f.evidence if e.source == "otx_validation"]
    assert {e.verdict for e in good} == {Verdict.BENIGN} and len(good) == 2
    a = assess(f.evidence, {"otx": 0.6, "otx_validation": 0.6})
    assert a.verdict is Verdict.BENIGN


def test_vpn_and_proxy_tags_are_not_evidence(transport):
    from iglite.config import Config
    from iglite.fetch import Fetcher
    from iglite.sources.base import Context
    from iglite.sources.osint import InternetDB

    transport.add(
        "https://internetdb.shodan.io/45.155.205.9", body={"ip": "45.155.205.9", "tags": ["vpn", "proxy"]}
    )
    f = InternetDB().lookup(
        classify("45.155.205.9"), Context(Fetcher(Store(), transport=transport), Config())
    )
    assert f.evidence == [] and f.attributes["tags"] == ["proxy", "vpn"]


# -- storage migration -----------------------------------------------------------------------


def test_old_database_is_upgraded_in_place(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
        INSERT INTO meta VALUES ('schema_version', '3');
        CREATE TABLE evidence (id INTEGER PRIMARY KEY, node TEXT NOT NULL, source TEXT NOT NULL,
            verdict TEXT NOT NULL, confidence REAL NOT NULL, detail TEXT NOT NULL, url TEXT, observed_at REAL NOT NULL);
        INSERT INTO evidence (node, source, verdict, confidence, detail, observed_at)
            VALUES ('ip:1.2.3.4', 'x', 'malicious', 1.0, 'old row', 1);
        CREATE TABLE alerts (id INTEGER PRIMARY KEY, at REAL NOT NULL, key TEXT NOT NULL, verdict TEXT NOT NULL,
            score INTEGER NOT NULL, context TEXT NOT NULL DEFAULT '{}');
        INSERT INTO alerts (at, key, verdict, score) VALUES (1, 'ip:1.2.3.4', 'malicious', 90);
    """)
    db.commit()
    db.close()
    store = Store(path)
    assert store.evidence("ip:1.2.3.4")[0].last_seen is None
    assert store.alerts()[0]["status"] == "open"
    assert store._query("SELECT v FROM meta WHERE k='schema_version'")[0][0] == "4"


# -- API and CLI -------------------------------------------------------------------------------


def test_feedback_and_suppression_api(flagged):
    srv = make_server(flagged, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        s, body = call(
            "/api/feedback", {"key": "203.0.113.66", "verdict": "false_positive", "note": "lab box"}
        )
        assert s == 200 and body["assessment"]["override"] == "false_positive"
        assert call("/api/indicator?key=ip:203.0.113.66")[1]["assessment"]["verdict"] == "benign"
        assert call("/api/feedback")[1]["sources"]["bad"]["false_positives"] == 1
        src = {x["name"]: x for x in call("/api/sources")[1]}
        assert src["bad"]["false_positives"] == 1
        assert (
            call("/api/feedback", {"key": "203.0.113.66", "verdict": "clear"})[1]["assessment"]["override"]
            is None
        )
        assert call("/api/feedback", {"key": "203.0.113.66", "verdict": "nope"})[0] == 400
        assert call("/api/feedback", {"key": "ip:9.9.9.9", "verdict": "confirmed"})[0] == 404

        rule = call("/api/suppressions", {"kind": "process", "value": "Teams.exe"})[1]["id"]
        assert call("/api/suppressions")[1][0]["value"] == "teams.exe"
        assert call("/api/suppressions", {"kind": "user", "value": "x"})[0] == 400
        assert call("/api/suppressions/delete", {"id": rule})[1] == {"ok": True}
        assert call("/api/suppressions/delete", {"id": rule})[0] == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_marking(tmp_path, lists, capsys, monkeypatch):
    cfg = tmp_path / "iglite.toml"
    cfg.write_text(
        f'disabled = ["dns", "crtsh", "rdap", "internetdb"]\n[blocklists]\nbad = "{lists["bad"]}"\n'
        f'other = "{lists["other"]}"\n'
    )
    monkeypatch.delenv("IGLITE_CONFIG", raising=False)
    base = ["-c", str(cfg), "--db", str(tmp_path / "t.db")]
    assert main([*base, "investigate", "203.0.113.66", "--depth", "0"]) == 0
    assert main([*base, "fp", "203.0.113.66", "--note", "test lab"]) == 0
    assert "BENIGN" in capsys.readouterr().out
    assert main([*base, "feedback"]) == 0
    out = capsys.readouterr().out
    assert "FALSE POS" in out and "test lab" in out and "bad" in out
    assert main([*base, "suppress", "process", "Teams.exe", "--note", "chat app"]) == 0
    assert main([*base, "suppress", "list"]) == 0
    assert "teams.exe" in capsys.readouterr().out
    assert main([*base, "unmark", "203.0.113.66"]) == 0
    assert "MALICIOUS" in capsys.readouterr().out
