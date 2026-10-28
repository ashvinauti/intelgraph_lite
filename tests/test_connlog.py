import csv
import io
import json
import threading
import time
import urllib.request

import pytest

from iglite import demo
from iglite.api import make_server
from iglite.cli import main
from iglite.extract import treat_as_public
from iglite.netwatch import Connection, NetWatch, Snapshot


@pytest.fixture
def net(tmp_path):
    engine, watch, network = demo.build(str(tmp_path / "demo.db"))
    for ip, name in demo.DEVICES.items():
        network.gw.add(demo.Lease(ip, name))
    network.incidents(60)
    network.background()
    watch.scan()
    try:
        yield engine, watch, network
    finally:
        engine.store.close()
        treat_as_public([])


def test_every_connection_and_lookup_is_logged(net):
    engine, watch, network = net
    store = engine.store
    res = store.connection_log(who="host:10.42.0.61", text=demo.C2_IP)
    row = res["rows"][0]
    assert (row["remote_ip"], row["remote_port"], row["proto"], row["inbound"]) == (
        demo.C2_IP,
        4444,
        "tcp",
        False,
    )
    assert row["verdict"] == "malicious" and row["who_name"] == "Smart-Plug"
    hits = row["hits"]  # the first beacon and its repeat at 60 s: 2 flow records
    dns = store.connection_log(dns=True, text=demo.PHISH)["rows"]
    assert [(r["who"], r["domain"], r["hits"]) for r in dns] == [("host:10.42.0.23", demo.PHISH, 1)]
    inbound = store.connection_log(text=demo.SCANNER)["rows"][0]
    assert inbound["inbound"] and inbound["who"] == "host:10.42.0.70"

    # a scan with nothing new adds nothing (flows still in the window aren't counted twice)
    before = store.connection_log_stats()
    watch.scan()
    assert store.connection_log(text=demo.C2_IP)["rows"][0]["hits"] == hits
    assert store.connection_log_stats()["connections"] == before["connections"]

    # the plug beacons again: same row for the day, more hits
    network.gw.add(demo.Flow("10.42.0.61", demo.C2_IP, 50999, 4444, "tcp", "pass"))
    watch.scan()
    assert store.connection_log(text=demo.C2_IP)["rows"][0]["hits"] == hits + 1


def test_log_filters_days_and_retention(make_engine):
    store = make_engine().store
    day = 86400
    t0 = time.time() - 40 * day
    store.log_connections(
        [
            (t0, "host:10.0.0.5", "203.0.113.9", 443, "tcp", False, "a.example", 3),
            (
                t0 + 60,
                "host:10.0.0.5",
                "203.0.113.9",
                443,
                "tcp",
                False,
                "",
                2,
            ),  # same day: merged, names kept
            (t0 + 2 * day, "host:10.0.0.5", "203.0.113.9", 443, "tcp", False, "a.example", 1),  # another day
            (time.time(), "process:firefox", "198.51.100.7", 443, "tcp", False, "b.example", 1),
        ]
    )
    rows = store.connection_log(who="host:10.0.0.5")["rows"]
    assert [(r["hits"], r["names"]) for r in rows] == [(1, "a.example"), (5, "a.example")]
    assert store.connection_log(since=time.time() - day)["total"] == 1
    assert store.connection_log(text="FIREFOX")["total"] == 1  # by program, case-insensitive
    assert store.connection_log(verdicts=["unknown"])["total"] == 3
    assert store.prune_connection_log(30) == 2
    assert store.connection_log_stats()["connections"] == 1


def test_this_computer_mode_logs_programs_and_skips_loopback(make_engine):
    engine = make_engine()
    snap = Snapshot(
        [
            Connection(
                "tcp", "192.168.1.5:50000", "203.0.113.20", 443, "ESTABLISHED", 4242, "Firefox", count=2
            ),
            Connection("tcp", "127.0.0.1:50001", "127.0.0.1", 631, "ESTABLISHED", 77, "cupsd"),
        ],
        {"203.0.113.20": ["shop.example"]},
    )
    watch = NetWatch(engine, interval=30, collector=lambda: snap)
    watch.max_new = 0
    watch.scan()
    watch.scan()
    rows = engine.store.connection_log()["rows"]
    assert [(r["who"], r["remote_ip"], r["names"], r["hits"]) for r in rows] == [
        ("process:firefox", "203.0.113.20", "shop.example", 4)  # 2 sockets x 2 snapshots
    ]
    engine.config.connection_log = False
    watch.scan()
    assert engine.store.connection_log()["rows"][0]["hits"] == 4


def _serve(engine):
    engine.config.api_token = None
    srv = make_server(engine, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def get(path):
        with opener.open(base + path, timeout=5) as resp:
            raw = resp.read()
            return json.loads(raw) if resp.headers["Content-Type"] == "application/json" else raw.decode()

    return srv, get


def test_api_log_csv_and_live_graph(net):
    engine, watch, network = net
    srv, get = _serve(engine)
    try:
        res = get("/api/connlog?verdict=malicious,suspicious")
        assert {r["remote_ip"] for r in res["rows"]} >= {demo.C2_IP}
        rows = get("/api/connlog?hide_common=1&limit=1000")["rows"]
        assert any(r["common"] for r in rows) and all(
            r["common"] is None for r in rows if r["remote_ip"] == demo.C2_IP
        )
        lookups = get("/api/connlog?dns=1&who=host:10.42.0.31")["rows"]
        assert demo.MINER in {r["domain"] for r in lookups}
        table = list(csv.reader(io.StringIO(get("/api/connlog.csv?q=" + demo.C2_IP))))
        assert table[0][:3] == ["first_seen", "last_seen", "who"] and table[1][6] == demo.C2_IP
        assert table[1][3] == "Smart-Plug" and table[1][4] == "outbound"
        st = get("/api/connlog/stats")
        assert st["connections"] > 5 and "host:10.42.0.61" in st["who"] and st["retention_days"] == 90

        live = get(f"/api/graph/live?since={time.time() - 600}")
        edges = {(e["src"], e["rel"], e["dst"]) for e in live["edges"]}
        assert ("host:10.42.0.61", "connected_to", f"ip:{demo.C2_IP}") in edges
        assert ("host:10.42.0.23", "queried", f"domain:{demo.PHISH}") in edges
        assert {e["rel"] for e in live["edges"]} <= {
            "routes_for",
            "runs",
            "connected_to",
            "queried",
            "resolves_to",
        }
        assert not any(e["dst"].startswith("technique:") for e in live["edges"])
        lean = get(f"/api/graph/live?since={time.time() - 600}&hide_common=1")
        keys = {n["key"] for n in lean["nodes"]}
        assert "domain:video-stream.example" not in keys and f"ip:{demo.C2_IP}" in keys
        assert lean["hidden"]["common"] > 0
        later = get(f"/api/graph/live?since={live['now']}")
        assert later["edges"] == []  # nothing new since
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_connections(net, capsys, monkeypatch, tmp_path):
    engine, watch, network = net
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    assert main(["connections", "--who", "10.42.0.61", "--since", "1h"]) == 0
    out = capsys.readouterr().out
    assert f"-> {demo.C2_IP}:4444/tcp" in out and "Smart-Plug" in out
    assert main(["connections", "--dns", "--verdict", "malicious"]) == 0
    assert demo.PHISH in capsys.readouterr().out
    target = tmp_path / "all.csv"
    assert main(["connections", "--csv", str(target)]) == 0
    assert demo.C2_IP in target.read_text()
    assert main(["connections", "--stats"]) == 0
    assert "connection rows" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="--since"):
        main(["connections", "--since", "yesterday"])
