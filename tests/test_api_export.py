import json
import threading
import urllib.error
import urllib.request

import pytest

from iglite import export
from iglite.api import make_server
from iglite.cli import main
from iglite.extract import classify


@pytest.fixture
def populated(make_engine, lists):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    engine.investigate([classify(v) for v in ("203.0.113.66", "hxxp://evil[.]example/payload.bin")], depth=1)
    return engine


def test_stix_bundle_is_stable_and_valid(populated):
    b1 = json.loads(export.to_stix(populated.store))
    b2 = json.loads(export.to_stix(populated.store))
    indicators = [o for o in b1["objects"] if o["type"] == "indicator"]
    assert any(o["pattern"] == "[ipv4-addr:value = '203.0.113.66']" for o in indicators)
    assert {o["id"] for o in indicators} == {o["id"] for o in b2["objects"] if o["type"] == "indicator"}
    for o in b1["objects"]:
        assert o["spec_version"] == "2.1"
        assert o["created"].endswith("Z")


def test_csv_and_json_exports(populated):
    rows = export.to_csv(populated.store, {"malicious"}).strip().splitlines()
    assert rows[0].startswith("kind,value,verdict")
    assert any("203.0.113.66" in r for r in rows[1:])
    graph = json.loads(export.to_json(populated.store))
    assert graph["nodes"] and graph["edges"]


@pytest.fixture
def server(populated):
    populated.config.api_token = "s3cret"
    srv = make_server(populated, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def call(base, path, body=None, token="s3cret"):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_api_requires_token(server):
    assert call(server, "/api/stats", token=None)[0] == 401
    assert call(server, "/api/stats", token="wrong")[0] == 401
    assert call(server, "/api/stats")[0] == 200


def test_api_dashboard_and_queries(server):
    status, page = call(server, "/", token=None)
    assert status == 200 and b"IntelGraph Lite" in page
    status, body = call(server, "/api/indicators?verdict=malicious")
    assert [n["key"] for n in json.loads(body)] == ["ip:203.0.113.66"]
    status, body = call(server, "/api/indicator?key=203.0.113.66")
    detail = json.loads(body)
    assert detail["assessment"]["verdict"] == "malicious" and len(detail["evidence"]) == 2
    status, body = call(server, "/api/graph?key=url:http://evil.example/payload.bin&depth=1")
    assert len(json.loads(body)["nodes"]) == 2


def test_api_investigate_and_validation(server):
    status, body = call(server, "/api/investigate", {"text": "see evil[.]example", "depth": 0})
    assert status == 200 and "domain:evil.example" in json.loads(body)["assessments"]
    assert call(server, "/api/investigate", {"indicators": ["???"]})[0] == 400
    assert call(server, "/api/investigate", {"indicators": ["1.2.3.4"], "depth": "x"})[0] == 400
    assert call(server, "/api/indicator?key=ip:9.9.9.9")[0] == 404
    assert call(server, "/api/nope")[0] == 404


def test_cli_end_to_end(tmp_path, lists, capsys, monkeypatch):
    cfg = tmp_path / "iglite.toml"
    cfg.write_text(
        f'disabled = ["dns", "crtsh", "rdap", "internetdb"]\n[blocklists]\nbad = "{lists["bad"]}"\n'
        f'other = "{lists["other"]}"\n'
    )
    db = str(tmp_path / "t.db")
    report = tmp_path / "report.txt"
    report.write_text("Beacon to 203.0.113[.]66 observed.")
    monkeypatch.delenv("IGLITE_CONFIG", raising=False)
    assert main(["-c", str(cfg), "--db", db, "ingest", str(report), "--investigate", "--depth", "0"]) == 0
    assert "MALICIOUS" in capsys.readouterr().out
    assert main(["-c", str(cfg), "--db", db, "show", "203.0.113.66"]) == 0
    out = capsys.readouterr().out
    assert "listed in bad" in out and "mentions" in out
    assert main(["-c", str(cfg), "--db", db, "export", "stix", "-o", str(tmp_path / "b.json")]) == 0
    assert json.loads((tmp_path / "b.json").read_text())["type"] == "bundle"
    assert main(["-c", str(cfg), "--db", db, "prune", "--days", "0"]) == 0
