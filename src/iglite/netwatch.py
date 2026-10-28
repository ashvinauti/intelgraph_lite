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
* Gateway - flows from a router/firewall for every device on the network (``gateway.py``);
            connections then carry the LAN device instead of a process.
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
from collections import deque
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
    # Gateway mode: the LAN device behind the router/firewall, and its DHCP/configured name.
    device: str | None = None
    device_name: str | None = None
    inbound: bool = False  # a remote host connected in (e.g. to a forwarded port)
    count: int = 1  # sockets / flow records folded into this one
    fresh: int = 0  # gateway mode: flow records since the previous snapshot


@dataclass
class Snapshot:
    connections: list[Connection] = field(default_factory=list)
    dns: dict[str, list[str]] = field(default_factory=dict)  # ip -> names
    # Gateway mode extras: domain -> devices that looked it up, device ip -> name,
    # and IDS alerts as (device, remote ip, signature, ATT&CK technique ids).
    queries: dict[str, list[str]] = field(default_factory=dict)
    devices: dict[str, str] = field(default_factory=dict)
    ids_alerts: list[tuple[str, str, str, tuple[str, ...]]] = field(default_factory=list)


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


THIS_COMPUTER = Indicator(Kind.HOST, "this-computer")
GATEWAY = Indicator(Kind.HOST, "gateway")


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
        origin: Indicator = THIS_COMPUTER,
        gateway: Any = None,
    ) -> None:
        self.engine = engine
        self.interval = max(5.0, interval)
        self.max_new = max_new
        self.recheck = recheck
        self.collector = collector
        self.origin = origin
        self.gateway = gateway  # the GatewayCollector in gateway mode, for its status
        if gateway is not None:  # device names survive restarts: yours win, DHCP names fill gaps
            for n in engine.store.search(kind=Kind.HOST.value, limit=5000):
                if not (name := n["attrs"].get("name")):
                    continue
                if n["attrs"].get("name_source") == "user":
                    gateway.set_name(n["value"], name)
                else:
                    gateway.learn_name(n["value"], name)
        self._checked: dict[str, float] = {}  # indicator key -> last investigated
        # key -> (verdict, when) already alerted; survives restarts via the store.
        self._alerted = engine.store.recent_alert_verdicts(time.time() - self.REALERT_AFTER)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()  # one scan at a time
        self.last_scan: float | None = None
        self.last_error: str | None = None
        self.scans = 0
        self.rows: list[dict[str, Any]] = []
        # (time, connections, public IPs, flagged) per scan, for the activity chart.
        self.history: deque[tuple[float, int, int, int]] = deque(maxlen=720)
        self._logged_lookups = 0.0  # newest DNS lookup already written to the log
        self._log_pruned = 0.0

    @property
    def mode(self) -> str:
        return "gateway" if self.gateway is not None else "host"

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
        out = {
            "running": self.running,
            "mode": self.mode,
            "interval": self.interval,
            "scans": self.scans,
            "last_scan": self.last_scan,
            "last_error": self.last_error,
            "connections": len(self.rows),
            "flagged": sum(1 for r in self.rows if r["verdict"] in _FLAGGED),
        }
        if self.gateway is not None:
            out["gateway"] = self.gateway.status()
            out["devices"] = len({r["device"] for r in self.rows if r.get("device")})
        return out

    @staticmethod
    def _suppressed(
        key: str, process: str | None, rules: dict[str, set[str]], device: str | None = None
    ) -> bool:
        return (
            key in rules.get("indicator", ())
            or (process or "").lower() in rules.get("process", ())
            or (device or "") in rules.get("device", ())
        )

    def _should_alert(self, key: str, verdict: str, now: float) -> bool:
        previous = self._alerted.get(key)
        if previous is None or now - previous[1] > self.REALERT_AFTER:
            return True
        # Escalation (suspicious -> malicious) alerts again; anything else is a repeat.
        return previous[0] == "suspicious" and verdict == "malicious"

    def _who(self, c: Connection) -> tuple[Indicator, str, dict[str, Any] | None] | None:
        """The local end of a connection: (node, relation from the origin, attrs)."""
        if c.device:
            return (
                Indicator(Kind.HOST, c.device),
                "routes_for",
                {"name": c.device_name} if c.device_name else None,
            )
        if c.process:
            return Indicator(Kind.PROCESS, c.process.lower()), "runs", None
        return None

    # -- one scan ----------------------------------------------------------------

    def scan(self) -> dict[str, Any]:
        with self._lock:
            return self._scan()

    def _scan(self) -> dict[str, Any]:
        snap = self.collector()
        store = self.engine.store
        now = time.time()

        live = [c for c in snap.connections if c.state not in _IGNORED_STATES]
        public: dict[str, Indicator] = {}
        for c in live:
            ind = Indicator(Kind.IP, c.remote_ip)
            if is_public(ind):
                public.setdefault(ind.key, ind)
        queried: dict[str, tuple[Indicator, list[str]]] = {}  # gateway DNS logs
        for name, devices in snap.queries.items():
            dom = classify(name)
            if dom is not None and dom.kind is Kind.DOMAIN and is_public(dom):
                queried[dom.key] = (dom, devices)

        if self.engine.config.connection_log:
            try:
                self._log(snap, live, now)
            except Exception as exc:  # the log must never stop monitoring
                self.last_error = f"connection log: {type(exc).__name__}: {exc}"

        # Record who talks to whom (cheap, local) before any lookups.
        if live or queried:
            store.upsert_node(self.origin)
        recorded: set[tuple[str, str]] = set()
        for c in live:
            if c.state == "RECENT":  # gateway flow already recorded in an earlier window
                continue
            ip = public.get(f"ip:{c.remote_ip}")
            who = self._who(c)
            if ip is None or who is None or (who[0].key, ip.key) in recorded:
                continue
            recorded.add((who[0].key, ip.key))
            store.upsert_node(who[0], who[2])
            store.add_relation(Relation(self.origin, who[1], who[0], pivot=False), "netwatch")
            store.upsert_node(ip, {"netwatch.last_seen": now})
            store.add_relation(Relation(who[0], "connected_to", ip), "netwatch")
        for dom, devices in queried.values():
            store.upsert_node(dom, {"netwatch.last_seen": now})
            for device in devices[:20]:
                host = Indicator(Kind.HOST, device)
                store.upsert_node(host, {"name": snap.devices[device]} if device in snap.devices else None)
                store.add_relation(Relation(self.origin, "routes_for", host, pivot=False), "netwatch")
                store.add_relation(Relation(host, "queried", dom, pivot=False), "dnslog")
        for ip, names in snap.dns.items():
            if f"ip:{ip}" in public:
                for name in names[:5]:
                    if (dom := classify(name)) is not None:
                        store.upsert_node(dom)
                        store.add_relation(Relation(dom, "resolves_to", public[f"ip:{ip}"]), "dnscache")
        for device, remote, signature, techniques in snap.ids_alerts:
            # A local IDS (Suricata) saw it happen: its ATT&CK metadata is an observation.
            target = Indicator(Kind.IP, remote)
            store.upsert_node(target, {"ids.last_signature": signature[:200], "ids.last_seen": now})
            for tid in techniques[:10]:
                self.engine.link_technique(target, tid, "exhibits", "ids")
                self.engine.link_technique(Indicator(Kind.HOST, device), tid, "exhibits", "ids")

        candidates = [*public.items(), *((k, v[0]) for k, v in queried.items())]
        due = [ind for key, ind in candidates if now - self._checked.get(key, 0) > self.recheck]
        seeds = due[: self.max_new]
        report = None
        if seeds:
            for ind in seeds:
                self._checked[ind.key] = now
            # depth 0: look up exactly what we saw, nothing more.
            report = self.engine.investigate(seeds, depth=0, budget=len(seeds))

        nodes = {n["key"]: n for n in store.nodes([*public, *queried])}
        suppressed: dict[str, set[str]] = {}
        for rule in store.suppressions():
            suppressed.setdefault(rule["kind"], set()).add(
                rule["value"].lower() if rule["kind"] == "process" else rule["value"]
            )
        grouped: dict[tuple, dict[str, Any]] = {}
        rows_in: list[tuple[Connection, str]] = [(c, f"ip:{c.remote_ip}") for c in live]
        for key, (dom, devices) in queried.items():
            rows_in += [
                (Connection("dns", d, dom.value, 53, "QUERY", device=d, device_name=snap.devices.get(d)), key)
                for d in devices[:20]
            ]
        new_alerts = 0
        for c, key in rows_in:
            group = (c.pid, c.process, c.device, c.proto, c.remote_ip, c.remote_port, c.inbound)
            if group in grouped:  # many sockets to one endpoint = one row
                grouped[group]["count"] += c.count
                continue
            node = nodes.get(key) or {}
            verdict = node.get("verdict") or (
                "private" if key not in public and key not in queried else "pending"
            )
            grouped[group] = {
                **asdict(c),
                "key": key,
                "names": snap.dns.get(c.remote_ip, [])[:3],
                "verdict": verdict,
                "score": node.get("score"),
            }
            if (
                verdict in _FLAGGED
                and (node.get("score") or 0) >= self.engine.config.alert_min_score
                and not self._suppressed(key, c.process, suppressed, c.device)
                and self._should_alert(key, verdict, now)
            ):
                self._alerted[key] = (verdict, now)
                techniques = self._attack_on_alert(c, key)
                alert_id = store.add_alert(
                    key,
                    verdict,
                    node.get("score") or 0,
                    json.dumps(
                        {
                            k: v
                            for k, v in {
                                "process": c.process,
                                "pid": c.pid,
                                "device": c.device,
                                "device_name": c.device_name,
                                "inbound": c.inbound or None,
                                "query": c.proto == "dns" or None,
                                "remote_port": c.remote_port,
                                "local": c.local,
                                "names": snap.dns.get(c.remote_ip, [])[:3],
                                "attack": techniques or None,
                                "mode": self.mode,
                            }.items()
                            if v is not None or k in ("process", "pid", "remote_port", "local", "names")
                        }
                    ),
                )
                self.engine.on_alert(alert_id)
                new_alerts += 1

        for row in grouped.values():  # analyst marks are shown in the table
            row["suppressed"] = self._suppressed(row["key"], row["process"], suppressed, row.get("device"))
        rows = list(grouped.values())
        rank = {"malicious": 0, "suspicious": 1, "pending": 2, "unknown": 3, "benign": 4, "private": 5}
        rows.sort(key=lambda r: (rank.get(r["verdict"], 3), -(r["score"] or 0), r["remote_ip"]))
        self.rows = rows
        self.history.append((now, len(rows), len(public), sum(r["verdict"] in _FLAGGED for r in rows)))
        self.scans += 1
        self.last_scan = now
        self.last_error = None
        return {
            "connections": len(live),
            "public_ips": len(public),
            "domains": len(queried),
            "investigated": len(seeds),
            "deferred": max(0, len(due) - len(seeds)),
            "alerts": new_alerts,
            "errors": report.errors if report else [],
        }

    # -- devices (gateway mode) ---------------------------------------------------

    def _log(self, snap: Snapshot, live: list[Connection], now: float) -> None:
        """Append this snapshot to the connection and DNS log (one row per endpoint per day)."""
        rows = []
        for c in live:
            try:
                if ipaddress.ip_address(c.remote_ip).is_loopback:
                    continue
            except ValueError:
                continue
            if self.gateway is not None:
                if not c.fresh:  # already logged when it was new
                    continue
                hits = c.fresh
            else:
                hits = c.count
            who = f"host:{c.device}" if c.device else f"process:{(c.process or 'unknown').lower()}"
            names = ",".join(snap.dns.get(c.remote_ip, [])[:5])
            rows.append((now, who, c.remote_ip, int(c.remote_port or 0), c.proto, c.inbound, names, hits))
        store = self.engine.store
        store.log_connections(rows)
        if self.gateway is not None:
            items = self.gateway.recent_lookups(self._logged_lookups, 5000)
            if items:
                self._logged_lookups = max(t for t, _, _ in items)
                store.log_lookups((t, f"host:{dev}", dom) for t, dev, dom in items)
        days = float(self.engine.config.connection_log_days or 0)
        if days > 0 and now - self._log_pruned > 3600:
            self._log_pruned = now
            store.prune_connection_log(days)

    def devices(self) -> list[dict[str, Any]]:
        """One summary per LAN device: activity in the current window, worst verdict, alerts."""
        rank = {"malicious": 0, "suspicious": 1, "pending": 2, "unknown": 3, "benign": 4, "private": 5}
        out: dict[str, dict[str, Any]] = {}
        for r in self.rows:
            ip = r.get("device")
            if not ip:
                continue
            d = out.setdefault(
                ip,
                {
                    "ip": ip,
                    "name": r.get("device_name"),
                    "connections": 0,
                    "remotes": set(),
                    "lookups": set(),
                    "flagged": 0,
                    "worst": "private",
                    "score": None,
                    "active": False,
                },
            )
            d["name"] = d["name"] or r.get("device_name")
            if r["proto"] == "dns":
                d["lookups"].add(r["remote_ip"])
            else:
                d["connections"] += r["count"]
                d["remotes"].add(r["remote_ip"])
                d["lookups"].update(r.get("names") or [])
            d["active"] = d["active"] or r.get("state") in ("NEW", "QUERY")
            if r["verdict"] in _FLAGGED:
                d["flagged"] += 1
            if rank.get(r["verdict"], 3) < rank.get(d["worst"], 3):
                d["worst"] = r["verdict"]
            if r.get("score") is not None and r["verdict"] in _FLAGGED:
                d["score"] = max(d["score"] or 0, r["score"])
        store = self.engine.store
        nodes = {n["value"]: n for n in store.nodes(f"host:{ip}" for ip in out)}
        alerts: dict[str, int] = {}
        for a in store.alerts(limit=1000):
            if (dev := (a["context"] or {}).get("device")) and a["status"] == "open":
                alerts[dev] = alerts.get(dev, 0) + 1
        quarantined = {b["value"] for b in store.blocks() if b["kind"] == "device"}
        result = []
        for ip, d in out.items():
            node = nodes.get(ip) or {}
            result.append(
                {
                    **d,
                    "name": (node.get("attrs") or {}).get("name") or d["name"],
                    "remotes": len(d["remotes"]),
                    "lookups": len(d["lookups"]),
                    "open_alerts": alerts.get(ip, 0),
                    "first_seen": node.get("first_seen"),
                    "last_seen": node.get("last_seen"),
                    "key": f"host:{ip}",
                    "quarantined": ip in quarantined,
                }
            )
        result.sort(key=lambda d: (rank.get(d["worst"], 3), -d["open_alerts"], -d["connections"], d["ip"]))
        return result

    def device(self, ip: str) -> dict[str, Any]:
        """Everything about one device: its connections, recent lookups, alerts and techniques."""
        from .attack import techniques_of

        store = self.engine.store
        key = f"host:{ip}"
        node = store.node(key) or {"attrs": {}}
        rows = [r for r in self.rows if r.get("device") == ip]
        lookups = self.gateway.recent_lookups(limit=2000) if self.gateway is not None else []
        mine = [(t, name) for t, dev, name in lookups if dev == ip][-100:]
        verdicts = {n["value"]: n for n in store.nodes(f"domain:{name}" for _, name in mine)}
        return {
            "ip": ip,
            "key": key,
            "name": node["attrs"].get("name"),
            "named_by_you": node["attrs"].get("name_source") == "user",
            "quarantined": any(b["kind"] == "device" and b["value"] == ip for b in store.blocks()),
            "first_seen": node.get("first_seen"),
            "last_seen": node.get("last_seen"),
            "connections": rows,
            "lookups": [
                {
                    "at": t,
                    "domain": name,
                    "verdict": (verdicts.get(name) or {}).get("verdict"),
                    "score": (verdicts.get(name) or {}).get("score"),
                }
                for t, name in reversed(mine)
            ],
            "alerts": [a for a in store.alerts(limit=1000) if (a["context"] or {}).get("device") == ip][:50],
            "attack": techniques_of(store, key, associated=False),
        }

    def rename(self, ip: str, name: str | None) -> None:
        """Give a device a name of your own (kept across restarts and over DHCP names)."""
        host = Indicator(Kind.HOST, ip)
        self.engine.store.upsert_node(host, {"name": name, "name_source": "user" if name else None})
        if self.gateway is not None:
            self.gateway.set_name(ip, name)
        for r in self.rows:
            if r.get("device") == ip:
                r["device_name"] = name

    def lookup_feed(self, since: float = 0.0, limit: int = 200) -> list[dict[str, Any]]:
        """Recent DNS lookups across the network, newest first, with each domain's verdict."""
        if self.gateway is None:
            return []
        items = self.gateway.recent_lookups(since, limit)
        nodes = {n["value"]: n for n in self.engine.store.nodes({f"domain:{d}" for _, _, d in items})}
        names = dict(self.gateway.devices)
        return [
            {
                "at": t,
                "device": dev,
                "device_name": names.get(dev),
                "domain": d,
                "verdict": (nodes.get(d) or {}).get("verdict") or "pending",
                "score": (nodes.get(d) or {}).get("score"),
            }
            for t, dev, d in reversed(items)
        ]

    def _attack_on_alert(self, c: Connection, key: str) -> list[str]:
        """Outbound traffic to a flagged host suggests C2 over that port's protocol (ATT&CK)."""
        if c.inbound or c.proto == "dns" or not key.startswith("ip:"):
            return []
        from .attack import from_connection

        tid = from_connection(c.remote_port)
        self.engine.link_technique(Indicator.from_key(key), tid, "suggests_technique", "netwatch")
        if (who := self._who(c)) is not None:
            self.engine.link_technique(who[0], tid, "suggests_technique", "netwatch")
        return [tid]
