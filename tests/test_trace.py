import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from iglite.api import make_server
from iglite.trace import Tracer, parse_hop_line

TRACERT = """
Tracing route to 45.155.205.20 over a maximum of 20 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    11 ms    12 ms  203.0.113.66
  4    15 ms    14 ms    14 ms  45.155.205.20

Trace complete.
"""

TRACEROUTE = """traceroute to 45.155.205.20 (45.155.205.20), 20 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms
 2  *
 3  203.0.113.66  12.301 ms
 4  45.155.205.20  14.9 ms
"""

TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1                                           0.512ms
 1:  192.168.1.1                                           0.401ms
 2:  no reply
 3:  203.0.113.66                                         12.3ms
 4:  45.155.205.20                                        14.9ms reached
     Resume: pmtu 1500 hops 4 back 4
"""


@pytest.mark.parametrize("output", [TRACERT, TRACEROUTE, TRACEPATH])
def test_parsers_agree(output):
    hops = [h for h in map(parse_hop_line, output.splitlines()) if h]
    dedup = {}
    for h in hops:
        dedup.setdefault(h.n, h)
    assert [(h.n, h.ip) for h in dedup.values()] == [
        (1, "192.168.1.1"),
        (2, None),
        (3, "203.0.113.66"),
        (4, "45.155.205.20"),
    ]
    assert dedup[3].rtt == pytest.approx(12.3, abs=0.4)
    assert dedup[2].rtt is None


def fake_runner(output):
    def run(ip, max_hops):
        yield from output.splitlines(keepends=True)

    return run


def test_trace_persists_path_and_checks_hops(make_engine, lists):
    engine = make_engine(blocklists={"bad": lists["bad"]})
    tracer = Tracer(engine, runner=fake_runner(TRACERT))
    job = tracer.run("45.155.205.20")
    assert job.status == "done" and len(job.hops) == 4

    edges = {(e["src"], e["dst"]) for e in engine.store.neighbourhood("host:this-computer", 5)["edges"]}
    assert ("host:this-computer", "ip:192.168.1.1") in edges
    assert ("ip:192.168.1.1", "ip:203.0.113.66") in edges  # unanswered hop 2 is skipped
    assert ("ip:203.0.113.66", "ip:45.155.205.20") in edges

    d = tracer.describe(job)
    assert d["reached"] is True
    hop3 = d["hops"][2]
    assert hop3["verdict"] == "suspicious"  # it is on the blocklist
    assert d["hops"][0]["private"] is True
    assert engine.store.routes()[0]["target"] == "45.155.205.20"


def test_unreached_target_still_ends_the_path(make_engine):
    engine = make_engine()
    partial = "\n".join(TRACEROUTE.splitlines()[:3])
    job = Tracer(engine, runner=fake_runner(partial)).run("45.155.205.20")
    d = Tracer(engine).describe(job)
    assert d["reached"] is False
    edges = {(e["src"], e["dst"]) for e in engine.store.edges_of("ip:45.155.205.20")}
    assert ("ip:192.168.1.1", "ip:45.155.205.20") in edges


def test_resolve_rejects_bad_targets():
    with pytest.raises(ValueError):
        Tracer.resolve("--help")
    with pytest.raises(ValueError):
        Tracer.resolve("d41d8cd98f00b204e9800998ecf8427e")
    assert Tracer.resolve("hxxp://45.155.205[.]20/x") == ("45.155.205.20", "45.155.205.20")


def test_trace_api(make_engine):
    engine = make_engine()
    engine.tracer().runner = fake_runner(TRACEROUTE)
    srv = make_server(engine, "127.0.0.1", 0)
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
        status, job = call("/api/trace", {"target": "45.155.205.20"})
        assert status == 200 and job["status"] in ("running", "done")
        for _ in range(50):
            status, job = call(f"/api/trace?id={job['id']}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done" and len(job["hops"]) == 4
        assert call("/api/traces")[1]["saved"][0]["ip"] == "45.155.205.20"
        assert call("/api/trace", {"target": "not a target"})[0] == 400
        assert call("/api/trace?id=999")[0] == 404
        assert call("/api/watch/history")[0] == 200
    finally:
        srv.shutdown()
        srv.server_close()
