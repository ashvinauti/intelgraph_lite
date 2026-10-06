from iglite.netwatch import (
    Connection,
    NetWatch,
    Snapshot,
    parse_displaydns,
    parse_lsof,
    parse_netstat_windows,
    parse_proc_net,
    parse_tasklist,
)

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1120
  TCP    192.168.1.5:52144      45.155.205.20:443      ESTABLISHED     8812
  TCP    192.168.1.5:52150      192.168.1.1:53         TIME_WAIT       0
  TCP    [::1]:49670            [::1]:49671            ESTABLISHED     4567
  TCP    [2001:db8::5]:50000    [2606:4700::1111]:443  ESTABLISHED     8812
  UDP    0.0.0.0:5353           *:*                                    3344
  UDP    [fe80::1%12]:546       [fe80::2%12]:547                       900
"""

TASKLIST = """"System Idle Process","0","Services","0","8 K"
"chrome.exe","8812","Console","1","312,456 K"
"""

DISPLAYDNS = """
Windows IP Configuration

    cdn.example
    ----------------------------------------
    Record Name . . . . . : cdn.example
    Record Type . . . . . : 5
    Time To Live  . . . . : 30
    Data Length . . . . . : 8
    Section . . . . . . . : Answer
    CNAME Record  . . . . : edge.cdn-host.example

    Record Name . . . . . : edge.cdn-host.example
    Record Type . . . . . : 1
    Time To Live  . . . . : 30
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 45.155.205.20
"""

PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 1111 1
   1: 0501A8C0:CC10 14CD9B2D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1
"""

PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000501A8C0:D000 0000000000000000FFFF000014CD9B2D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3333 1
"""

LSOF = """p8812
cGoogle Chrome
f23
PTCP
n192.168.1.5:52144->45.155.205.20:443
TST=ESTABLISHED
f24
PTCP
n*:8080
TST=LISTEN
p99
cmDNSResponder
f5
PUDP
n*:5353
"""


def test_windows_netstat_and_tasklist():
    names = parse_tasklist(TASKLIST)
    assert names[8812] == "chrome.exe"
    conns = parse_netstat_windows(NETSTAT, names)
    remotes = {(c.remote_ip, c.remote_port, c.state, c.process) for c in conns}
    assert ("45.155.205.20", 443, "ESTABLISHED", "chrome.exe") in remotes
    assert ("2606:4700::1111", 443, "ESTABLISHED", "chrome.exe") in remotes
    assert ("fe80::2", 547, "", None) in remotes
    assert not any(c.remote_port == 0 for c in conns)  # listeners and *:* dropped


def test_windows_dns_cache_follows_cname():
    assert parse_displaydns(DISPLAYDNS) == {"45.155.205.20": ["edge.cdn-host.example"]}


def test_linux_proc_net_decodes_little_endian():
    conns = parse_proc_net(PROC_TCP, "tcp", {"2222": (42, "curl")})
    (c,) = conns  # the listener (remote port 0) is skipped
    assert (c.remote_ip, c.remote_port, c.state, c.pid, c.process) == (
        "45.155.205.20",
        443,
        "ESTABLISHED",
        42,
        "curl",
    )
    assert c.local == "192.168.1.5:52240"
    (c6,) = parse_proc_net(PROC_TCP6, "tcp")
    assert c6.remote_ip == "45.155.205.20"  # IPv4-mapped IPv6 unwrapped


def test_macos_lsof():
    (c,) = parse_lsof(LSOF)
    assert (c.process, c.pid, c.remote_ip, c.remote_port, c.state) == (
        "Google Chrome",
        8812,
        "45.155.205.20",
        443,
        "ESTABLISHED",
    )


def _snapshot():
    return Snapshot(
        connections=[
            Connection("tcp", "192.168.1.5:1", "203.0.113.66", 443, "ESTABLISHED", 10, "evil.exe"),
            Connection("tcp", "192.168.1.5:2", "203.0.113.66", 443, "ESTABLISHED", 10, "evil.exe"),
            Connection("tcp", "192.168.1.5:3", "192.168.1.1", 53, "ESTABLISHED", 4, "svchost.exe"),
            Connection("tcp", "192.168.1.5:4", "45.155.205.99", 443, "TIME_WAIT", 11, "x.exe"),
        ],
        dns={"203.0.113.66": ["cnc.example"]},
    )


def test_watcher_alerts_once_and_links_process(make_engine, lists, monkeypatch):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    # Documentation ranges count as non-public; treat them as public for this test.
    monkeypatch.setattr("iglite.netwatch.is_public", lambda ind: not ind.value.startswith("192.168."))
    watch = NetWatch(engine, collector=_snapshot)

    result = watch.scan()
    assert result == {
        "connections": 3,
        "public_ips": 1,
        "investigated": 1,
        "deferred": 0,
        "alerts": 1,
        "errors": [],
    }
    row = watch.rows[0]
    assert (row["verdict"], row["count"], row["process"], row["names"]) == (
        "malicious",
        2,
        "evil.exe",
        ["cnc.example"],
    )
    assert watch.rows[-1]["verdict"] == "private"

    (alert,) = engine.store.alerts()
    assert alert["key"] == "ip:203.0.113.66" and alert["context"]["process"] == "evil.exe"
    edges = {(e["src"], e["rel"]) for e in engine.store.edges_of("ip:203.0.113.66")}
    assert ("process:evil.exe", "connected_to") in edges
    assert ("domain:cnc.example", "resolves_to") in edges

    # Second scan: already checked and alerted, so no lookups and no new alert.
    again = watch.scan()
    assert again["investigated"] == 0 and again["alerts"] == 0
    assert len(engine.store.alerts()) == 1


def test_watcher_caps_lookups_per_scan(make_engine):
    conns = [Connection("tcp", "10.0.0.2:1", f"45.155.{i}.1", 443, "ESTABLISHED") for i in range(30)]
    watch = NetWatch(make_engine(), collector=lambda: Snapshot(conns), max_new=10)
    first = watch.scan()
    assert (first["investigated"], first["deferred"]) == (10, 20)
    assert sum(r["verdict"] == "pending" for r in watch.rows) == 20
    assert watch.scan()["investigated"] == 10


def test_watch_api(make_engine, lists):
    import json
    import threading
    import urllib.request

    from iglite.api import make_server

    engine = make_engine()
    engine.watcher().collector = _snapshot
    srv = make_server(engine, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert call("/api/watch")[1]["running"] is False
        status, body = call("/api/watch", {"action": "scan"})
        assert status == 200 and body["result"]["connections"] == 3
        assert len(call("/api/connections")[1]["connections"]) == 2
        assert call("/api/watch", {"action": "start", "interval": 60})[1]["running"] is True
        assert call("/api/watch", {"action": "stop"})[0] == 200
        assert call("/api/watch", {"action": "explode"})[0] == 400
        assert call("/api/alerts?since=0")[0] == 200
    finally:
        engine.watcher().stop()
        srv.shutdown()
        srv.server_close()


def test_alerts_are_not_repeated_after_restart_but_escalations_are(make_engine, lists, monkeypatch):
    engine = make_engine(blocklists={"bad": lists["bad"]})  # one list -> suspicious only
    engine.config.alert_min_score = 0  # this test is about de-duplication, not the threshold
    monkeypatch.setattr("iglite.netwatch.is_public", lambda ind: not ind.value.startswith("192.168."))
    NetWatch(engine, collector=_snapshot).scan()
    assert [a["verdict"] for a in engine.store.alerts()] == ["suspicious"]

    restarted = NetWatch(engine, collector=_snapshot)  # fresh process, same database
    assert restarted.scan()["alerts"] == 0

    engine2 = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    engine2.config.alert_min_score = 0
    engine2.store = engine.store  # same data, now corroborated -> malicious
    engine2.fetcher.store = engine.store
    escalated = NetWatch(engine2, collector=_snapshot, recheck=0)
    assert escalated.scan()["alerts"] == 1
    assert [a["verdict"] for a in engine.store.alerts()] == ["malicious", "suspicious"]
