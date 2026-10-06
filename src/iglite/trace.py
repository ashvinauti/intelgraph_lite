"""Traceroute: the network path from this computer to a target, hop by hop.

Uses the operating system's own tool, so no raw sockets or admin rights:

* Windows      - ``tracert -d``
* Linux/macOS  - ``traceroute -n`` (or ``tracepath -n`` when that is all there is)

Output is parsed line by line while the tool runs, so callers can show hops
as they arrive. When the trace finishes, the path is stored as graph edges
(``host:this-computer -next_hop-> hop1 -next_hop-> ... -> target``) and the
public hops are looked up like any other indicator, which tells you which
networks your traffic crosses and whether any of them is flagged.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from .extract import classify, is_public
from .model import Indicator, Kind, Relation
from .netwatch import THIS_COMPUTER

if TYPE_CHECKING:
    from .engine import Engine


# Runner: (target ip, max hops) -> iterator of raw output lines.
Runner = Callable[[str, int], Iterator[str]]


class TraceUnavailable(RuntimeError):
    pass


@dataclass
class Hop:
    n: int
    ip: str | None
    rtt: float | None  # milliseconds, first reply


_HOP_LINE = re.compile(r"^\s*(\d+)\??:?\s+(.*)$")
_RTT = re.compile(r"<?(\d+(?:\.\d+)?)\s*ms", re.I)


def parse_hop_line(line: str) -> Hop | None:
    """Parse one line of tracert / traceroute -n / tracepath -n output."""
    m = _HOP_LINE.match(line)
    if not m or "LOCALHOST" in line.upper():
        return None
    rest = m.group(2)
    ip = None
    for token in rest.split():
        token = token.strip("()[],")
        try:
            ip = str(ipaddress.ip_address(token))
            break
        except ValueError:
            continue
    rtt = _RTT.search(rest)
    if ip is None and rtt is None and "*" not in rest and "no reply" not in rest.lower():
        return None
    return Hop(int(m.group(1)), ip, float(rtt.group(1)) if rtt and ip else None)


def command(target: str, max_hops: int) -> list[str]:
    if sys.platform == "win32":
        return ["tracert", "-d", "-h", str(max_hops), "-w", "800", target]
    if shutil.which("traceroute"):
        return ["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), target]
    if shutil.which("tracepath"):
        return ["tracepath", "-n", "-m", str(max_hops), target]
    raise TraceUnavailable("no traceroute tool found: install 'traceroute' (e.g. apt install traceroute)")


def system_runner(target: str, max_hops: int) -> Iterator[str]:
    cmd = command(target, max_hops)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(  # noqa: S603 - fixed argv; target validated as an IP
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        creationflags=flags,
    )
    killer = threading.Timer(120, proc.kill)  # hard cap on a stuck trace
    killer.start()
    try:
        assert proc.stdout is not None
        yield from proc.stdout
    finally:
        killer.cancel()
        proc.kill()
        proc.wait()


@dataclass
class TraceJob:
    id: int
    target: str  # what the user asked for
    ip: str  # what we actually traced
    max_hops: int
    status: str = "running"  # running | done | error
    hops: list[Hop] = field(default_factory=list)
    error: str | None = None
    started: float = field(default_factory=time.time)
    finished: float | None = None


class Tracer:
    MAX_RUNNING = 3

    def __init__(self, engine: Engine, runner: Runner = system_runner) -> None:
        self.engine = engine
        self.runner = runner
        self.jobs: dict[int, TraceJob] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    @staticmethod
    def resolve(raw: str) -> tuple[str, str]:
        """User input -> (display target, IP to trace). Raises ValueError."""
        ind = classify(raw)
        if ind is not None and ind.kind is Kind.URL:
            from urllib.parse import urlsplit

            ind = classify(urlsplit(ind.value).hostname or "")
        if ind is None or ind.kind not in (Kind.IP, Kind.DOMAIN):
            raise ValueError("target must be an IP address, domain or URL")
        if ind.kind is Kind.IP:
            return ind.value, ind.value
        try:
            ip = socket.getaddrinfo(ind.value, None, proto=socket.IPPROTO_TCP)[0][4][0]
        except (socket.gaierror, UnicodeError, IndexError):
            raise ValueError(f"cannot resolve {ind.value}")
        return ind.value, str(ipaddress.ip_address(ip.split("%")[0]))

    def start(self, raw: str, max_hops: int = 20) -> TraceJob:
        target, ip = self.resolve(raw)
        with self._lock:
            if sum(j.status == "running" for j in self.jobs.values()) >= self.MAX_RUNNING:
                raise RuntimeError("too many traces running; wait for one to finish")
            job = TraceJob(next(self._ids), target, ip, max(1, min(int(max_hops), 30)))
            self.jobs[job.id] = job
            for old in sorted(self.jobs)[:-20]:  # keep the last 20 in memory
                del self.jobs[old]
        threading.Thread(target=self._run, args=(job,), name=f"trace-{job.id}", daemon=True).start()
        return job

    def run(self, raw: str, max_hops: int = 20, on_hop: Callable[[Hop], None] | None = None) -> TraceJob:
        """Synchronous trace (CLI)."""
        target, ip = self.resolve(raw)
        job = TraceJob(0, target, ip, max_hops)
        self._run(job, on_hop)
        return job

    def _run(self, job: TraceJob, on_hop: Callable[[Hop], None] | None = None) -> None:
        try:
            for line in self.runner(job.ip, job.max_hops):
                hop = parse_hop_line(line)
                if hop is None or hop.n > job.max_hops:
                    continue
                if job.hops and job.hops[-1].n == hop.n:  # tracepath repeats a hop
                    if job.hops[-1].ip is None and hop.ip:
                        job.hops[-1] = hop
                    continue
                job.hops.append(hop)
                if on_hop:
                    on_hop(hop)
                if hop.ip == job.ip:
                    break
            self._persist(job)
            job.status = "done"
        except Exception as exc:  # report on the job instead of killing the thread
            job.status, job.error = "error", f"{type(exc).__name__}: {exc}"
        job.finished = time.time()

    def _persist(self, job: TraceJob) -> None:
        store = self.engine.store
        target = Indicator(Kind.IP, job.ip)
        path = [THIS_COMPUTER] + [Indicator(Kind.IP, h.ip) for h in job.hops if h.ip]
        if path[-1] != target:
            path.append(target)  # unreached target still ends the path
        for ind in path:
            store.upsert_node(ind)
        for a, b in itertools.pairwise(path):
            if a != b:
                store.add_relation(Relation(a, "next_hop", b, pivot=False), "traceroute")
        if job.target != job.ip and (dom := classify(job.target)) is not None:
            store.upsert_node(dom)
            store.add_relation(Relation(dom, "resolves_to", target), "traceroute")
        store.add_route(job.target, job.ip, json.dumps([asdict(h) for h in job.hops]))
        # Who owns each hop, and is any of them flagged? Private hops are only
        # checked against local lists; the engine never sends them out.
        hops = list(dict.fromkeys(path[1:]))
        if hops:
            self.engine.investigate(hops, depth=0, budget=len(hops))

    def describe(self, job: TraceJob) -> dict[str, Any]:
        keys = [f"ip:{h.ip}" for h in job.hops if h.ip] + [f"ip:{job.ip}"]
        nodes = {n["key"]: n for n in self.engine.store.nodes(dict.fromkeys(keys))}

        def info(ip: str | None) -> dict[str, Any]:
            node = nodes.get(f"ip:{ip}") or {}
            attrs = node.get("attrs") or {}
            org = attrs.get("rdap.net_name") or attrs.get("rdap.net_handle")
            return {
                "key": f"ip:{ip}" if ip else None,
                "verdict": node.get("verdict") or (None if ip is None else "unscored"),
                "score": node.get("score"),
                "org": org,
                "country": attrs.get("rdap.net_country"),
                "private": bool(ip) and not is_public(Indicator(Kind.IP, ip)),
            }

        return {
            "id": job.id,
            "target": job.target,
            "ip": job.ip,
            "status": job.status,
            "error": job.error,
            "started": job.started,
            "finished": job.finished,
            "reached": any(h.ip == job.ip for h in job.hops),
            "hops": [{**asdict(h), **info(h.ip)} for h in job.hops],
            "destination": info(job.ip),
        }
