import json
import sqlite3
import threading
import time
import urllib.request

import pytest

from iglite import demo
from iglite.api import make_server
from iglite.cli import main
from iglite.common import active_only
from iglite.extract import treat_as_public
from iglite.model import Indicator, Kind, Relation
from iglite.store import Store


@pytest.fixture
def home(tmp_path):
    """The demo network: every device busy now, the guest laptop seen two days ago, one device idle."""
    engine, watch, network = demo.build(str(tmp_path / "demo.db"))
    for ip, name in demo.DEVICES.items():
        network.gw.add(demo.Lease(ip, name))
        network.visit(ip, demo.HABITS[ip][0])
    watch.scan()
    store = engine.store
    # the guest laptop's old corner of the graph, and a printer that went quiet two hours ago
    guest = Indicator(Kind.HOST, demo.GUEST[0])
    store.add_relation(Relation(Indicator(Kind.HOST, "gateway"), "routes_for", guest), "netwatch")
    store.upsert_node(Indicator(Kind.IP, "198.51.100.99"))
    store.add_relation(Relation(guest, "connected_to", Indicator(Kind.IP, "198.51.100.99")), "netwatch")
    with store.transaction() as db:
        db.execute("UPDATE inventory SET last_seen = ? WHERE who = 'host:10.42.0.40'", (time.time() - 7200,))
    try:
        yield engine, watch, network
    finally:
        store.close()
        treat_as_public([])


def test_inventory_tracks_every_device(home):
    engine, *_ = home
    inv = {r["who"]: r for r in engine.store.inventory()}
    assert len(inv) == 9 and inv["host:10.42.0.61"]["name"] == "Smart-Plug"
    assert time.time() - inv["host:10.42.0.11"]["last_seen"] < 60
    assert time.time() - inv[f"host:{demo.GUEST[0]}"]["last_seen"] > 86400  # the guest, two days ago
    assert inv["host:10.42.0.11"]["first_seen"] < time.time() - 7 * 86400  # history from the seeded week
    recent = {r["who"] for r in engine.store.inventory(since=time.time() - 300)}
    assert "host:10.42.0.40" not in recent and "host:10.42.0.11" in recent


def test_existing_connection_log_fills_the_inventory_on_upgrade(tmp_path):
    path = tmp_path / "old.db"
    Store(path).close()
    db = sqlite3.connect(path)
    db.execute(
        "INSERT INTO conn_log VALUES ('2026-10-01','host:192.168.1.7','203.0.113.5',443,'tcp',0,'',1000,2000,12)"
    )
    db.execute("INSERT INTO dns_log VALUES ('2026-10-02','host:192.168.1.7','shop.example',3000,4000,3)")
    db.execute("DELETE FROM inventory")
    db.execute("UPDATE meta SET v='8' WHERE k='schema_version'")
    db.commit()
    db.close()
    store = Store(path)
    [row] = store.inventory()
    assert (row["who"], row["first_seen"], row["last_seen"], row["flows"], row["lookups"]) == (
        "host:192.168.1.7",
        1000,
        4000,
        12,
        3,
    )
    store.close()


def _serve(engine):
    engine.config.api_token = None
    srv = make_server(engine, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def get(path):
        try:
            with opener.open(base + path, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    return srv, get


def test_devices_api_shows_active_devices_by_default(home):
    engine, *_ = home
    srv, get = _serve(engine)
    try:
        status, r = get("/api/devices")
        ips = {d["ip"] for d in r["devices"]}
        assert status == 200 and "10.42.0.11" in ips
        assert "10.42.0.40" not in ips and demo.GUEST[0] not in ips  # quiet for 2 h; gone for 2 days
        assert r["counts"] == {"active": 7, "today": 1, "offline": 1, "all": 9}
        assert all(d["state"] == "active" for d in r["devices"])
        plug = next(d for d in r["devices"] if d["ip"] == "10.42.0.61")
        assert len(plug["traffic"]) == 24 and plug["traffic"][-1] > 0  # connections this hour

        today = {d["ip"]: d for d in get("/api/devices?state=today")[1]["devices"]}
        assert today["10.42.0.40"]["state"] == "today" and demo.GUEST[0] not in today
        everyone = {d["ip"]: d for d in get("/api/devices?state=all")[1]["devices"]}
        guest = everyone[demo.GUEST[0]]
        assert guest["state"] == "offline" and guest["name"] == "Guest-Laptop" and guest["flows_total"] == 80
        assert get("/api/devices?state=sleeping")[0] == 400
    finally:
        srv.shutdown()
        srv.server_close()


def test_graph_can_show_only_active_devices(home):
    engine, *_ = home
    store = engine.store
    full = store.neighbourhood("host:gateway", 2, 2000)
    keys = {n["key"] for n in full["nodes"]}
    assert {f"host:{demo.GUEST[0]}", "ip:198.51.100.99", "host:10.42.0.40"} <= keys
    lean = active_only(store, full, 300, keep=["host:gateway"])
    keys = {n["key"] for n in lean["nodes"]}
    assert f"host:{demo.GUEST[0]}" not in keys and "ip:198.51.100.99" not in keys  # only the guest led there
    assert "host:10.42.0.40" not in keys and "host:10.42.0.61" in keys
    assert lean["inactive"] == 2
    assert all(e["src"] in keys and e["dst"] in keys for e in lean["edges"])
    plug = next(n for n in lean["nodes"] if n["key"] == "host:10.42.0.61")
    assert time.time() - plug["last_active"] < 60
    assert {n["key"] for n in active_only(store, full, 86400 * 30, keep=["host:gateway"])["nodes"]} >= {
        f"host:{demo.GUEST[0]}"
    }

    srv, get = _serve(engine)
    try:
        g = get("/api/graph?key=host:gateway&depth=2&limit=500&active=300&hide_common=1")[1]
        keys = {n["key"] for n in g["nodes"]}
        assert f"host:{demo.GUEST[0]}" not in keys and g["inactive"] == 2 and g["hidden"]["common"] > 0
        assert f"host:{demo.GUEST[0]}" in {
            n["key"] for n in get("/api/graph?key=host:gateway&depth=2&limit=500")[1]["nodes"]
        }
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_devices(home, capsys, monkeypatch):
    engine, *_ = home
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    assert main(["devices"]) == 0
    out = capsys.readouterr().out
    assert "Smart-Plug" in out and "Office-Printer" not in out and "Guest-Laptop" not in out
    assert main(["devices", "--today"]) == 0
    assert "Office-Printer" in capsys.readouterr().out
    assert main(["devices", "--all"]) == 0
    out = capsys.readouterr().out
    assert "Guest-Laptop" in out and "offline" in out


def test_addresses_recorded_by_mistake_drop_out_of_the_lists(home, capsys, monkeypatch):
    engine, *_ = home  # the demo's LAN is 10.42.0.0/24
    now = time.time()
    # an upstream neighbour and a link-local address, as older versions recorded them
    engine.store.touch_devices(
        [
            ("host:192.168.0.234", now, 400, 0),
            ("host:fe80::18ab:1", now, 50, 0),
        ]
    )
    assert not engine.is_device("host:192.168.0.234") and not engine.is_device("host:fe80::18ab:1")
    assert engine.is_device("host:10.42.0.61") and engine.is_device("process:firefox")
    srv, get = _serve(engine)
    try:
        r = get("/api/devices?state=all")[1]
        ips = {d["ip"] for d in r["devices"]}
        assert not ips & {"192.168.0.234", "fe80::18ab:1"} and r["counts"]["all"] == 9
        assert {d["who"] for d in get("/api/behaviour")[1]["devices"]} == {
            f"host:{ip}" for ip in (*demo.DEVICES, demo.GUEST[0])
        }
    finally:
        srv.shutdown()
        srv.server_close()
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    assert main(["devices", "--all"]) == 0
    assert "192.168.0.234" not in capsys.readouterr().out
