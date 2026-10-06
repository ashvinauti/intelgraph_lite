"""Live network monitoring: who is this machine talking to, and is it bad?

Every ``interval`` seconds the watcher takes a snapshot of the operating
system's connection table (and, on Windows, the DNS cache), records which
process talks to which remote address, investigates *new* public addresses
through the normal engine, and raises an alert when one is suspicious or
malicious.

This reads the OS connection table instead of capturing packets: it needs no
driver, no admin rights and almost no CPU, and it knows the owning process,
which packet capture does not. Collectors:

* Windows - ``netstat -ano``, ``tasklist`` (process names), ``ipconfig /displaydns``
* Linux   - ``/proc/net/{tcp,tcp6,udp,udp6}`` and ``/proc/<pid>/fd`` (no subprocess)
* macOS   - ``lsof -nP -i``
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .extract import classify, is_public
from .model import Indicator, Kind, Relation, Verdict

if TYPE_CHECKING:
    from .engine import Engine


@dataclass(frozen=True)
class Connection:
    proto: str
    local: str
    remote_ip: str
    remote_port: int
    state: str
    pid: int | None = None
    process: str | None = None


@dataclass
class Snapshot:
    connections: list[Connection] = field(default_factory=list)
    dns: dict[str, list[str]] = field(default_factory=dict)  # ip -> names


# -- parsing helpers -----------------------------------------------------------


def _split_endpoint(text: str) -> tuple[str, int] | None:
    """'1.2.3.4:443', '[::1]:80', '[fe80::1%12]:5353', '*:*' -> (ip, port)."""
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        return None
    host = host.strip("[]").split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(host)), int(port)
    except ValueError:
        return None


def parse_netstat_windows(text: str, names: dict[int, str] | None = None) -> list[Connection]:
    names = names or {}
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        proto = parts[0].lower()
        if proto == "tcp" and len(parts) >= 5:
            local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
        else:
            local, remote, state, pid = parts[1], parts[2], "", parts[-1]
        ep = _split_endpoint(remote)
        if ep is None or ep[1] == 0:
            continue
        pid_i = int(pid) if pid.isdigit() else None
        out.append(Connection(proto, local, ep[0], ep[1], state.upper(), pid_i, names.get(pid_i or -1)))
    return out


def parse_tasklist(text: str) -> dict[int, str]:
    names = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = row[0]
    return names


_DNS_LINE = re.compile(r"^\s*([^:]+?)[ .]*:\s*(\S+)\s*$")


def parse_displaydns(text: str) -> dict[str, list[str]]:
    """Language-independent: 'label . . : value' lines; a domain value names the
    record, an IP value is an answer for the most recent name."""
    result: dict[str, list[str]] = {}
    name: str | None = None
    for line in text.splitlines():
        m = _DNS_LINE.match(line)
        if not m:
            continue
        ind = classify(m.group(2))
        if ind is None:
            continue
        if ind.kind is Kind.DOMAIN:
            name = ind.value
        elif ind.kind is Kind.IP and name:
            names = result.setdefault(ind.value, [])
            if name not in names:
                names.append(name)
    return result


_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _proc_addr(hexaddr: str) -> tuple[str, int]:
    host, port = hexaddr.split(":")
    raw = bytes.fromhex(host)
    # The kernel prints each 32-bit word in host (little-endian) byte order.
    raw = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
    return str(ipaddress.ip_address(raw)), int(port, 16)


def parse_proc_net(
    text: str, proto: str, owners: dict[str, tuple[int, str]] | None = None
) -> list[Connection]:
    owners = owners or {}
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local_ip, local_port = _proc_addr(parts[1])
            remote_ip, remote_port = _proc_addr(parts[2])
        except ValueError:
            continue
        if remote_port == 0:
            continue
        mapped = ipaddress.ip_address(remote_ip)
        if isinstance(mapped, ipaddress.IPv6Address) and mapped.ipv4_mapped:
            remote_ip = str(mapped.ipv4_mapped)
        state = _TCP_STATES.get(parts[3], parts[3]) if proto == "tcp" else ""
        pid, name = owners.get(parts[9], (None, None))
        out.append(Connection(proto, f"{local_ip}:{local_port}", remote_ip, remote_port, state, pid, name))
    return out


def _socket_owners(proc: Path = Path("/proc")) -> dict[str, tuple[int, str]]:
    """socket inode -> (pid, process name); best effort, only readable processes."""
    owners: dict[str, tuple[int, str]] = {}
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            name = (pid_dir / "comm").read_text().strip()
            for fd in (pid_dir / "fd").iterdir():
                target = os.readlink(fd)
                if target.startswith("socket:["):
                    owners[target[8:-1]] = (int(pid_dir.name), name)
        except OSError:
            continue
    return owners


def parse_lsof(text: str) -> list[Connection]:
    """Parse ``lsof -nP -i -F pcPnT`` field output."""
    out = []
    pid: int | None = None
    cmd: str | None = None
    entry: dict[str, str] = {}

    def flush() -> None:
        name = entry.get("n", "")
        if "->" in name:
            local, remote = name.split("->", 1)
            ep = _split_endpoint(remote)
            if ep:
                out.append(
                    Connection(entry.get("P", "").lower(), local, ep[0], ep[1], entry.get("T", ""), pid, cmd)
                )
        entry.clear()

    for line in text.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            flush()
            pid = int(value) if value.isdigit() else None
        elif tag == "c":
            cmd = value
        elif tag == "f":
            flush()
        elif tag == "T":
            if value.startswith("ST="):
                entry["T"] = value[3:]
        elif tag in ("P", "n"):
            entry[tag] = value
    flush()
    return out


# -- platform collectors -------------------------------------------------------


def _run(cmd: list[str]) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(  # noqa: S603 - fixed argument lists, no shell
        cmd, capture_output=True, text=True, errors="replace", timeout=20, check=False, creationflags=flags
    ).stdout


def collect() -> Snapshot:
    """Snapshot of the current machine's connections for this platform."""
    if sys.platform == "win32":
        names = parse_tasklist(_run(["tasklist", "/fo", "csv", "/nh"]))
        conns = parse_netstat_windows(_run(["netstat", "-ano"]), names)
        dns = parse_displaydns(_run(["ipconfig", "/displaydns"]))
        return Snapshot(conns, dns)
    if Path("/proc/net/tcp").exists():
        owners = _socket_owners()
        conns: list[Connection] = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            path = Path("/proc/net") / proto
            if path.exists():
                conns += parse_proc_net(path.read_text(), proto.rstrip("6"), owners)
        return Snapshot(conns)
    return Snapshot(parse_lsof(_run(["lsof", "-nP", "-i", "-F", "pcPnT"])))


# -- the watcher -----------------------------------------------------------------

_FLAGGED = {Verdict.MALICIOUS.value, Verdict.SUSPICIOUS.value}
_IGNORED_STATES = {"LISTEN", "LISTENING", "TIME_WAIT", "CLOSE", "CLOSED"}


class NetWatch:
    REALERT_AFTER = 86400.0  # repeat an unchanged alert at most once a day

    def __init__(
        self,
        engine: Engine,
        *,
        interval: float = 30.0,
        max_new: int = 25,
        recheck: float = 3600.0,
        collector: Callable[[], Snapshot] = collect,
    ) -> None:
        self.engine = engine
        self.interval = max(5.0, interval)
        self.max_new = max_new
        self.recheck = recheck
        self.collector = collector
        self._checked: dict[str, float] = {}  # ip key -> last investigated
        # ip key -> (verdict, when) already alerted; survives restarts via the store.
        self._alerted = engine.store.recent_alert_verdicts(time.time() - self.REALERT_AFTER)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()  # one scan at a time
        self.last_scan: float | None = None
        self.last_error: str | None = None
        self.scans = 0
        self.rows: list[dict[str, Any]] = []

    # -- lifecycle -------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="iglite-netwatch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan()
            except Exception as exc:  # keep watching; report on the status endpoint
                self.last_error = f"{type(exc).__name__}: {exc}"
            self._stop.wait(self.interval)

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "interval": self.interval,
            "scans": self.scans,
            "last_scan": self.last_scan,
            "last_error": self.last_error,
            "connections": len(self.rows),
            "flagged": sum(1 for r in self.rows if r["verdict"] in _FLAGGED),
        }

    def _should_alert(self, key: str, verdict: str, now: float) -> bool:
        previous = self._alerted.get(key)
        if previous is None or now - previous[1] > self.REALERT_AFTER:
            return True
        # Escalation (suspicious -> malicious) alerts again; anything else is a repeat.
        return previous[0] == "suspicious" and verdict == "malicious"

    # -- one scan ----------------------------------------------------------------

    def scan(self) -> dict[str, Any]:
        with self._lock:
            return self._scan()

    def _scan(self) -> dict[str, Any]:
        snap = self.collector()
        store = self.engine.store
        now = time.time()

        live = [c for c in snap.connections if c.state not in _IGNORED_STATES]
        public = {}
        for c in live:
            ind = Indicator(Kind.IP, c.remote_ip)
            if is_public(ind):
                public.setdefault(ind.key, ind)

        # Record who talks to whom (cheap, local) before any lookups.
        for c in live:
            if c.process and f"ip:{c.remote_ip}" in public:
                proc = Indicator(Kind.PROCESS, c.process.lower())
                store.upsert_node(proc)
                store.upsert_node(public[f"ip:{c.remote_ip}"], {"netwatch.last_seen": now})
                store.add_relation(Relation(proc, "connected_to", public[f"ip:{c.remote_ip}"]), "netwatch")
        for ip, names in snap.dns.items():
            if f"ip:{ip}" in public:
                for name in names[:5]:
                    if (dom := classify(name)) is not None:
                        store.upsert_node(dom)
                        store.add_relation(Relation(dom, "resolves_to", public[f"ip:{ip}"]), "dnscache")

        due = [ind for key, ind in public.items() if now - self._checked.get(key, 0) > self.recheck]
        seeds = due[: self.max_new]
        report = None
        if seeds:
            for ind in seeds:
                self._checked[ind.key] = now
            # depth 0: look up exactly what we saw, nothing more.
            report = self.engine.investigate(seeds, depth=0, budget=len(seeds))

        nodes = {n["key"]: n for n in store.nodes(public)}
        grouped: dict[tuple, dict[str, Any]] = {}
        new_alerts = 0
        for c in live:
            key = f"ip:{c.remote_ip}"
            group = (c.pid, c.process, c.proto, c.remote_ip, c.remote_port)
            if group in grouped:  # many sockets to one endpoint = one row
                grouped[group]["count"] += 1
                continue
            node = nodes.get(key) or {}
            verdict = node.get("verdict") or ("private" if key not in public else "pending")
            grouped[group] = {
                **asdict(c),
                "key": key,
                "count": 1,
                "names": snap.dns.get(c.remote_ip, [])[:3],
                "verdict": verdict,
                "score": node.get("score"),
            }
            if verdict in _FLAGGED and self._should_alert(key, verdict, now):
                self._alerted[key] = (verdict, now)
                store.add_alert(
                    key,
                    verdict,
                    node.get("score") or 0,
                    json.dumps(
                        {
                            "process": c.process,
                            "pid": c.pid,
                            "remote_port": c.remote_port,
                            "local": c.local,
                            "names": snap.dns.get(c.remote_ip, [])[:3],
                        }
                    ),
                )
                new_alerts += 1

        rows = list(grouped.values())
        rank = {"malicious": 0, "suspicious": 1, "pending": 2, "unknown": 3, "benign": 4, "private": 5}
        rows.sort(key=lambda r: (rank.get(r["verdict"], 3), -(r["score"] or 0), r["remote_ip"]))
        self.rows = rows
        self.scans += 1
        self.last_scan = now
        self.last_error = None
        return {
            "connections": len(live),
            "public_ips": len(public),
            "investigated": len(seeds),
            "deferred": max(0, len(due) - len(seeds)),
            "alerts": new_alerts,
            "errors": report.errors if report else [],
        }
