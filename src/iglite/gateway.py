"""Gateway mode: watch a whole network from the router or firewall, not one computer.

Live monitoring normally reads *this* computer's connection table. In gateway
mode the same watcher is fed by what the network's choke point already
records, so every device behind it is covered (phones, TVs, servers):

* **syslog** (UDP) from the router/firewall: netfilter/iptables/nftables LOG
  lines (OpenWrt, UFW, Ubiquiti), pfSense/OPNsense ``filterlog``, key=value
  logs (FortiGate, Sophos, SonicWall, Check Point, WatchGuard...), Cisco ASA
  "Built ... connection", Juniper SRX ``RT_FLOW``, MikroTik, Palo Alto
  TRAFFIC CSV, and DNS logs from dnsmasq / Pi-hole / Unbound.
* **NetFlow v5/v9 and IPFIX** (UDP) from routers and firewalls.
* **conntrack**: when IntelGraph Lite runs *on* a Linux/OpenWrt gateway, the
  kernel's NAT table (``/proc/net/nf_conntrack`` or ``conntrack -L``).
* **log files** it tails: Zeek ``conn.log`` / ``dns.log`` (TSV or JSON),
  Suricata ``eve.json`` (flow, dns and alert events - alerts carry ATT&CK
  technique IDs), or any file the syslog formats above are written to.

Each flow is reduced to (LAN device, remote address, port). The device is the
side inside the network, the remote is the public side; LAN-to-LAN traffic is
skipped. Flows that the firewall blocked are ignored by default: a blocked
internet scan is the firewall working, not an incident.

Nothing here sends traffic anywhere. Only the public remote addresses go on to
the normal lookup pipeline, exactly as in host mode. Listeners accept packets
from private addresses only unless ``gateway_senders`` lists the exporters.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .attack import ids_in
from .extract import classify
from .model import Kind
from .netwatch import Connection, Snapshot

if TYPE_CHECKING:
    from .config import Config

MAX_LINE = 8192
MAX_FLOWS = 20_000  # distinct flows buffered between scans
MAX_DNS = 50_000  # remembered DNS answers (ip -> names)
_BLOCKED = {"block", "blocked", "drop", "dropped", "deny", "denied", "reject", "rejected", "close-blocked"}


@dataclass(frozen=True)
class Flow:
    src: str
    dst: str
    sport: int | None
    dport: int | None
    proto: str = "tcp"
    action: str = ""  # "", "pass", "block", ...
    signature: str | None = None  # an IDS alert's signature (Suricata)
    techniques: tuple[str, ...] = ()  # ATT&CK IDs from that signature's metadata


@dataclass(frozen=True)
class DnsEvent:
    client: str | None  # who asked (None for an answer line)
    name: str
    answers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Lease:
    ip: str
    name: str


Event = Flow | DnsEvent | Lease


# -- address helpers ------------------------------------------------------------


def _ip(value: Any) -> str | None:
    try:
        addr = ipaddress.ip_address(str(value).strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def _port(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmp6", "47": "gre", "50": "esp", "132": "sctp"}


def _proto(value: Any) -> str:
    text = str(value or "").strip().lower().split("/")[0].split("(")[0].strip()
    return _PROTO_NUM.get(text, text or "tcp")


class Lan:
    """Which addresses are inside the network. Default: every non-public address."""

    def __init__(self, networks: Iterable[str] = ()) -> None:
        self.networks = [ipaddress.ip_network(n, strict=False) for n in networks]

    def inside(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        if self.networks:
            return any(addr in n for n in self.networks if n.version == addr.version)
        return not addr.is_global

    def orient(self, flow: Flow) -> tuple[str, str, int | None, bool] | None:
        """(device, remote, remote port, inbound) or None for internal / transit / non-public."""
        try:
            src_in, dst_in = self.inside(flow.src), self.inside(flow.dst)
        except ValueError:
            return None
        if src_in and not dst_in and ipaddress.ip_address(flow.dst).is_global:
            return flow.src, flow.dst, flow.dport, False
        if dst_in and not src_in and ipaddress.ip_address(flow.src).is_global:
            return flow.dst, flow.src, flow.dport, True
        return None


# -- line parsers ---------------------------------------------------------------------

_KV = re.compile(r'([A-Za-z_][\w.-]*)=("([^"]*)"|\S+)')
_SRC_KEYS = ("srcip", "src_ip", "src", "source_ip", "source-address", "sip", "s_ip")
_DST_KEYS = ("dstip", "dst_ip", "dst", "destination_ip", "destination-address", "dip", "dest_ip", "d_ip")
_SPORT_KEYS = ("srcport", "src_port", "spt", "sport", "source-port", "s_port")
_DPORT_KEYS = ("dstport", "dst_port", "dpt", "dport", "destination-port", "d_port", "dest_port", "service")
_ACTION_KEYS = ("action", "act", "fw_action", "disposition", "status")
_ASA = re.compile(
    r"Built (?P<dir>inbound|outbound) (?P<proto>TCP|UDP|ICMP) connection \d+ for "
    r"[^:]+:(?P<a>[\da-fA-F.:]+)/(?P<ap>\d+) .*?to [^:]+:(?P<b>[\da-fA-F.:]+)/(?P<bp>\d+)"
)
_ARROW = re.compile(
    r"(?P<proto>tcp|udp|icmp)\b[^,]*?,?\s*(?:\S+\s+)?\[?(?P<s>[\da-fA-F.:]+?)\]?:(?P<sp>\d+)->\[?(?P<d>[\da-fA-F.:]+?)\]?:(?P<dp>\d+)",
    re.I,
)
_SRX = re.compile(r"(?P<s>[\da-fA-F.:]+)/(?P<sp>\d+)->(?P<d>[\da-fA-F.:]+)/(?P<dp>\d+)")
_DNSMASQ_QUERY = re.compile(r"query\[\w+\]\s+(\S+)\s+from\s+([\da-fA-F.:]+)")
_DNSMASQ_REPLY = re.compile(r"(?:reply|cached|forwarded-answer)\s+(\S+)\s+is\s+([\da-fA-F.:]+)")
_UNBOUND_QUERY = re.compile(r"info: ([\da-fA-F.:]+) (\S+?)\.? (?:A|AAAA|CNAME|MX|TXT|HTTPS|ANY|SRV) IN")
_DHCP_ACK = re.compile(r"DHCPACK\([^)]*\)\s+([\d.]+)\s+(?:[0-9a-fA-F:]{17})\s+(\S+)")
_VERDICT_WORDS = re.compile(r"\b(BLOCK|DROP|DENY|REJECT|ACCEPT|ALLOW|PASS)\b", re.I)


def _first(d: dict[str, str], keys: Iterable[str]) -> str | None:
    for k in keys:
        if d.get(k):
            return d[k]
    return None


def _split_hostport(value: str) -> tuple[str, int | None]:
    """'1.2.3.4:443:X1' (SonicWall) or plain '1.2.3.4' -> (ip, port)."""
    parts = value.split(":")
    if len(parts) >= 2 and _ip(parts[0]) and parts[1].isdigit():
        return parts[0], _port(parts[1])
    return value, None


def parse_kv(line: str) -> Flow | None:
    fields = {k.lower(): (q if q is not None and v.startswith('"') else v) for k, v, q in _KV.findall(line)}
    src, dst = _first(fields, _SRC_KEYS), _first(fields, _DST_KEYS)
    if not src or not dst:
        return None
    src, sport = _split_hostport(src)
    dst, dport = _split_hostport(dst)
    src_ip, dst_ip = _ip(src), _ip(dst)
    if not src_ip or not dst_ip:
        return None
    action = (_first(fields, _ACTION_KEYS) or "").lower()
    if not action and (m := _VERDICT_WORDS.search(line)):  # netfilter prefixes: "[UFW BLOCK]"
        action = m.group(1).lower()
    return Flow(
        src_ip,
        dst_ip,
        sport or _port(_first(fields, _SPORT_KEYS)),
        dport or _port(_first(fields, _DPORT_KEYS)),
        _proto(fields.get("proto") or fields.get("protocol") or fields.get("ip_proto")),
        action,
    )


def parse_filterlog(line: str) -> Flow | None:
    """pfSense / OPNsense ``filterlog``: rule,sub,anchor,tracker,if,reason,action,dir,ipver,..."""
    _, _, csv_part = line.partition("filterlog")
    csv_part = csv_part.split(":", 1)[-1].strip()
    f = csv_part.split(",")
    if len(f) < 20:
        return None
    action = f[6]
    if f[8] == "4":
        proto, src, dst, rest = f[16], f[18], f[19], f[20:]
    elif f[8] == "6" and len(f) >= 17:
        proto, src, dst, rest = f[12], f[15], f[16], f[17:]
    else:
        return None
    src_ip, dst_ip = _ip(src), _ip(dst)
    if not src_ip or not dst_ip:
        return None
    ports = (_port(rest[0]), _port(rest[1])) if len(rest) >= 2 and proto in ("tcp", "udp") else (None, None)
    return Flow(src_ip, dst_ip, ports[0], ports[1], _proto(proto), action)


def parse_paloalto(line: str) -> Flow | None:
    """PAN-OS TRAFFIC log (CSV): fields are counted from the ``TRAFFIC`` type column."""
    f = line.split(",")
    try:
        t = f.index("TRAFFIC")
    except ValueError:
        return None
    if len(f) < t + 28:
        return None
    src_ip, dst_ip = _ip(f[t + 4]), _ip(f[t + 5])
    if not src_ip or not dst_ip:
        return None
    return Flow(src_ip, dst_ip, _port(f[t + 21]), _port(f[t + 22]), _proto(f[t + 26]), f[t + 27].lower())


def parse_text(line: str) -> list[Event]:
    """One syslog / log-file line in any of the supported text formats."""
    line = line[:MAX_LINE]
    if "filterlog" in line:
        return [f] if (f := parse_filterlog(line)) else []
    if ",TRAFFIC," in line:
        return [f] if (f := parse_paloalto(line)) else []
    if "dnsmasq" in line or "pihole" in line.lower():
        if m := _DNSMASQ_QUERY.search(line):
            return [DnsEvent(_ip(m.group(2)), m.group(1).rstrip("."))]
        if m := _DNSMASQ_REPLY.search(line):
            ip = _ip(m.group(2))
            return [DnsEvent(None, m.group(1).rstrip("."), (ip,))] if ip else []
        if m := _DHCP_ACK.search(line):
            return [Lease(m.group(1), m.group(2))] if m.group(2) != "*" else []
        return []
    if m := _UNBOUND_QUERY.search(line):
        return [DnsEvent(_ip(m.group(1)), m.group(2))]
    if m := _ASA.search(line):
        # outbound: "for outside:RESPONDER/port ... to inside:INITIATOR/port"; inbound: the reverse
        a, b = _ip(m.group("a")), _ip(m.group("b"))
        if not a or not b:
            return []
        proto = m.group("proto").lower()
        if m.group("dir") == "inbound":
            return [Flow(a, b, _port(m.group("ap")), _port(m.group("bp")), proto, "pass")]
        return [Flow(b, a, _port(m.group("bp")), _port(m.group("ap")), proto, "pass")]
    if flow := parse_kv(line):
        return [flow]
    if "RT_FLOW" in line and (m := _SRX.search(line)):
        s, d = _ip(m.group("s")), _ip(m.group("d"))
        action = "pass" if "SESSION_CREATE" in line or "SESSION_CLOSE" in line else "block"
        proto = "udp" if "protocol 17" in line or " udp" in line.lower() else "tcp"
        return [Flow(s, d, _port(m.group("sp")), _port(m.group("dp")), proto, action)] if s and d else []
    if m := _ARROW.search(line):  # MikroTik: "proto TCP (SYN), 192.168.88.10:5000->1.2.3.4:443"
        s, d = _ip(m.group("s")), _ip(m.group("d"))
        verdict = _VERDICT_WORDS.search(line)
        action = verdict.group(1).lower() if verdict else ""
        if not s or not d:
            return []
        return [Flow(s, d, _port(m.group("sp")), _port(m.group("dp")), m.group("proto").lower(), action)]
    return []


def parse_json(obj: dict[str, Any]) -> list[Event]:
    """Zeek (JSON logs) and Suricata ``eve.json`` events."""
    if "id.orig_h" in obj:  # Zeek
        src, dst = _ip(obj.get("id.orig_h")), _ip(obj.get("id.resp_h"))
        if not src or not dst:
            return []
        if "query" in obj:  # dns.log
            answers = tuple(a for a in (_ip(x) for x in obj.get("answers") or []) if a)
            return [DnsEvent(src, str(obj["query"]).rstrip("."), answers)] if obj.get("query") else []
        return [
            Flow(src, dst, _port(obj.get("id.orig_p")), _port(obj.get("id.resp_p")), _proto(obj.get("proto")))
        ]
    event = obj.get("event_type")
    if event in ("flow", "alert", "dns", "netflow"):
        src, dst = _ip(obj.get("src_ip")), _ip(obj.get("dest_ip"))
        if not src or not dst:
            return []
        if event == "dns":
            dns = obj.get("dns") or {}
            names = [q.get("rrname") for q in dns.get("queries") or []] or [dns.get("rrname")]
            answers = tuple(
                a for a in (_ip(x.get("rdata")) for x in dns.get("answers") or [] if isinstance(x, dict)) if a
            )
            if dns.get("type") == "answer" and dns.get("rdata") and (one := _ip(dns["rdata"])):
                answers += (one,)
            return [DnsEvent(src if not answers else None, str(n).rstrip("."), answers) for n in names if n]
        alert = obj.get("alert") or {}
        meta = alert.get("metadata") or {}
        return [
            Flow(
                src,
                dst,
                _port(obj.get("src_port")),
                _port(obj.get("dest_port")),
                _proto(obj.get("proto")),
                "block" if alert.get("action") == "blocked" else "",
                alert.get("signature") if event == "alert" else None,
                tuple(ids_in(meta.get("mitre_technique_id") or [])) if event == "alert" else (),
            )
        ]
    return []


class LineParser:
    """Stateful per stream: remembers a Zeek TSV ``#fields`` header."""

    def __init__(self) -> None:
        self.zeek_fields: list[str] | None = None

    def parse(self, line: str) -> list[Event]:
        line = line.strip()
        if not line:
            return []
        if line.startswith("{"):
            try:
                obj = json.loads(line[:65536])
            except ValueError:
                return []
            return parse_json(obj) if isinstance(obj, dict) else []
        if line.startswith("#fields"):
            self.zeek_fields = line.split("\t")[1:]
            return []
        if line.startswith("#"):
            return []
        if self.zeek_fields and "\t" in line:
            values = line.split("\t")
            row = {k: v for k, v in zip(self.zeek_fields, values, strict=False) if v not in ("-", "(empty)")}
            if "answers" in row:
                row["answers"] = row["answers"].split(",")  # type: ignore[assignment]
            return parse_json(row)
        return parse_text(line)


# -- conntrack (running on the gateway itself) ---------------------------------------------

_CT_STATES = {
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT",
    "CLOSE_WAIT",
    "LAST_ACK",
    "TIME_WAIT",
    "CLOSE",
}


def parse_conntrack(text: str) -> list[Flow]:
    """``/proc/net/nf_conntrack`` or ``conntrack -L``: the *original* tuple of each entry."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        proto = next((p for p in parts[:4] if p in ("tcp", "udp", "icmp", "icmpv6", "sctp")), None)
        if proto is None:
            continue
        state = next((p for p in parts[:6] if p in _CT_STATES), "")
        if state in ("TIME_WAIT", "CLOSE"):
            continue
        kv: dict[str, str] = {}
        for p in parts:
            k, sep, v = p.partition("=")
            if sep and k in ("src", "dst", "sport", "dport") and k not in kv:
                kv[k] = v  # first occurrence = original direction
        src, dst = _ip(kv.get("src")), _ip(kv.get("dst"))
        if src and dst:
            out.append(Flow(src, dst, _port(kv.get("sport")), _port(kv.get("dport")), proto, "pass"))
    return out


def read_conntrack() -> str:
    path = Path("/proc/net/nf_conntrack")
    try:
        return path.read_text()
    except OSError:
        pass
    try:
        return subprocess.run(  # noqa: S603 - fixed argument list, no shell
            ["conntrack", "-L"],  # noqa: S607 - conntrack-tools from PATH
            capture_output=True,
            text=True,
            timeout=20,
            check=False,  # noqa: S607
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# -- DHCP leases ------------------------------------------------------------------------


def parse_leases(text: str) -> list[Lease]:
    """dnsmasq / OpenWrt (``expiry mac ip name id``) and ISC dhcpd (``lease ip { client-hostname "x"; }``)."""
    out = []
    current: str | None = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit() and _ip(parts[2]) and parts[3] != "*":
            out.append(Lease(_ip(parts[2]) or parts[2], parts[3]))
        elif parts[:1] == ["lease"] and len(parts) >= 2:
            current = _ip(parts[1])
        elif current and parts[:1] == ["client-hostname"] and len(parts) >= 2:
            out.append(Lease(current, parts[1].strip('";')))
    return out


# -- NetFlow v5 / v9 / IPFIX ---------------------------------------------------------------

# Information elements we read: protocol, ports, addresses.
_IE = {4: "proto", 7: "sport", 11: "dport", 8: "src", 12: "dst", 27: "src", 28: "dst"}


class NetFlowParser:
    """Decodes NetFlow v5/v9 and IPFIX datagrams; v9/IPFIX templates are kept per exporter."""

    MAX_TEMPLATES = 2048

    def __init__(self) -> None:
        self.templates: dict[tuple[str, int, int], list[tuple[int, int]]] = {}

    def parse(self, data: bytes, exporter: str = "") -> list[Flow]:
        if len(data) < 4:
            return []
        version = struct.unpack_from("!H", data)[0]
        try:
            if version == 5:
                return self._v5(data)
            if version == 9:
                return self._sets(data, exporter, header=20, domain_at=16, tmpl_ids=(0,), opt_ids=(1,))
            if version == 10:
                return self._sets(data, exporter, header=16, domain_at=12, tmpl_ids=(2,), opt_ids=(3,))
        except struct.error:
            return []
        return []

    @staticmethod
    def _v5(data: bytes) -> list[Flow]:
        count = struct.unpack_from("!H", data, 2)[0]
        out = []
        for i in range(min(count, 30)):
            off = 24 + 48 * i
            if off + 48 > len(data):
                break
            src, dst = data[off : off + 4], data[off + 4 : off + 8]
            sport, dport = struct.unpack_from("!HH", data, off + 32)
            proto = data[off + 38]
            out.append(
                Flow(
                    str(ipaddress.IPv4Address(src)),
                    str(ipaddress.IPv4Address(dst)),
                    sport or None,
                    dport or None,
                    _PROTO_NUM.get(str(proto), str(proto)),
                )
            )
        return out

    def _sets(
        self, data: bytes, exporter: str, *, header: int, domain_at: int, tmpl_ids: tuple, opt_ids: tuple
    ) -> list[Flow]:
        ipfix = header == 16
        domain = struct.unpack_from("!I", data, domain_at)[0]
        out: list[Flow] = []
        off = header
        while off + 4 <= len(data):
            set_id, length = struct.unpack_from("!HH", data, off)
            if length < 4 or off + length > len(data):
                break
            body = data[off + 4 : off + length]
            if set_id in tmpl_ids:
                self._templates(body, exporter, domain, ipfix)
            elif set_id > 255:
                fields = self.templates.get((exporter, domain, set_id))
                if fields:
                    out += self._records(body, fields, ipfix)
            # options templates (opt_ids) and their data are skipped
            off += length
        return out

    def _templates(self, body: bytes, exporter: str, domain: int, ipfix: bool) -> None:
        off = 0
        while off + 4 <= len(body):
            tid, count = struct.unpack_from("!HH", body, off)
            off += 4
            fields = []
            for _ in range(count):
                if off + 4 > len(body):
                    return
                ftype, flen = struct.unpack_from("!HH", body, off)
                off += 4
                if ipfix and ftype & 0x8000:  # enterprise-specific: 4-byte PEN follows
                    off += 4
                    ftype = -1
                fields.append((ftype, flen))
            if tid > 255 and len(self.templates) < self.MAX_TEMPLATES:
                self.templates[(exporter, domain, tid)] = fields

    @staticmethod
    def _records(body: bytes, fields: list[tuple[int, int]], ipfix: bool) -> list[Flow]:
        out = []
        off = 0
        fixed = sum(flen for _, flen in fields if flen != 65535)
        while off + max(1, fixed) <= len(body) and len(out) < 1000:
            rec: dict[str, Any] = {}
            for ftype, flen in fields:
                if flen == 65535 and ipfix:  # variable length
                    flen = body[off]
                    off += 1
                    if flen == 255:
                        flen = struct.unpack_from("!H", body, off)[0]
                        off += 2
                chunk = body[off : off + flen]
                off += flen
                name = _IE.get(ftype)
                if name is None or len(chunk) != flen:
                    continue
                if name in ("src", "dst") and flen in (4, 16):
                    rec[name] = str(ipaddress.ip_address(chunk))
                elif name in ("sport", "dport", "proto"):
                    rec[name] = int.from_bytes(chunk, "big")
            if "src" in rec and "dst" in rec:
                out.append(
                    Flow(
                        rec["src"],
                        rec["dst"],
                        rec.get("sport") or None,
                        rec.get("dport") or None,
                        _PROTO_NUM.get(str(rec.get("proto", 6)), str(rec.get("proto", 6))),
                    )
                )
        return out


# -- the collector -----------------------------------------------------------------------------


def _bind(spec: str, default_port: int) -> tuple[str, int]:
    host, sep, port = str(spec).rpartition(":")
    if not sep:
        host, port = "", str(spec)
    if not port.isdigit():
        host, port = str(spec), str(default_port)
    return (host.strip("[]") or "0.0.0.0", int(port))  # noqa: S104 - a gateway listener is meant to be reachable


@dataclass
class _Stats:
    datagrams: int = 0
    lines: int = 0
    events: int = 0
    unparsed: int = 0
    rejected_senders: int = 0
    blocked_skipped: int = 0
    internal_skipped: int = 0
    dropped: int = 0
    errors: list[str] = field(default_factory=list)


class GatewayCollector:
    """Gathers flows from every configured input between scans and hands them to NetWatch."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.lan = Lan(cfg.lan_networks)
        self.senders = [ipaddress.ip_network(s, strict=False) for s in cfg.gateway_senders]
        self.devices: dict[str, str] = {str(k): str(v) for k, v in (cfg.devices or {}).items()}
        self.stats = _Stats()
        self._lock = threading.Lock()
        self._flows: dict[tuple, int] = {}
        self._ids: list[tuple[str, str, str, tuple[str, ...]]] = []  # (device, remote, signature, techniques)
        self._queries: dict[str, set[str]] = {}
        self._answers: OrderedDict[str, list[str]] = OrderedDict()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self.addresses: dict[str, tuple[str, int]] = {}  # bound listener addresses
        # Rolling window of what was seen: flow key -> (count, last seen); (domain, client) -> last seen.
        self._recent: dict[tuple, tuple[int, float]] = {}
        self._recent_queries: dict[tuple[str, str], float] = {}
        self.netflow = NetFlowParser()
        self.started = False

    # -- inputs ----------------------------------------------------------------

    @property
    def inputs(self) -> list[str]:
        out = []
        if self.cfg.gateway_syslog:
            out.append(f"syslog udp {self.cfg.gateway_syslog}")
        if self.cfg.gateway_netflow:
            out.append(f"netflow udp {self.cfg.gateway_netflow}")
        if self.cfg.gateway_conntrack:
            out.append("conntrack")
        out += [f"file {p}" for p in self.cfg.gateway_files]
        return out

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        self._load_leases()
        if self.cfg.gateway_syslog:
            self._listen(_bind(self.cfg.gateway_syslog, 5514), self._on_syslog, "syslog")
        if self.cfg.gateway_netflow:
            self._listen(_bind(self.cfg.gateway_netflow, 2055), self._on_netflow, "netflow")
        for path in self.cfg.gateway_files:
            self._spawn(self._tail, Path(path).expanduser(), name=f"iglite-tail-{Path(path).name}")

    def stop(self) -> None:
        self._stop.set()
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass

    def _spawn(self, target: Any, *args: Any, name: str) -> None:
        t = threading.Thread(target=target, args=args, name=name, daemon=True)
        t.start()
        self._threads.append(t)

    def _listen(self, addr: tuple[str, int], handler: Any, label: str) -> None:
        family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.bind(addr)
        sock.settimeout(1.0)
        self.addresses[label] = sock.getsockname()[:2]
        self._sockets.append(sock)
        self._spawn(self._recv_loop, sock, handler, name=f"iglite-{label}")

    def _sender_ok(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.senders:
            return any(addr in n for n in self.senders if n.version == addr.version)
        return not addr.is_global

    def _recv_loop(self, sock: socket.socket, handler: Any) -> None:
        while not self._stop.is_set():
            try:
                data, peer = sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                return
            sender = _ip(peer[0]) or ""
            if not self._sender_ok(sender):
                self.stats.rejected_senders += 1
                continue
            self.stats.datagrams += 1
            try:
                handler(data, sender)
            except Exception as exc:  # one bad packet must not stop the listener
                self._error(f"{type(exc).__name__}: {exc}")

    def _on_syslog(self, data: bytes, sender: str) -> None:
        parser = LineParser()
        for line in data.decode("utf-8", "replace").splitlines():
            self.feed_line(line, parser)

    def _on_netflow(self, data: bytes, sender: str) -> None:
        for flow in self.netflow.parse(data, sender):
            self.add(flow)

    def _tail(self, path: Path) -> None:
        parser = LineParser()
        fh = None
        inode = None
        while not self._stop.is_set():
            try:
                st = path.stat()
                if fh is None or st.st_ino != inode or st.st_size < fh.tell():
                    if fh is not None:
                        fh.close()
                    first = fh is None
                    fh = path.open("r", encoding="utf-8", errors="replace")
                    if first:
                        fh.seek(0, os.SEEK_END)  # start from now, not the whole history
                    inode = st.st_ino
                    parser = LineParser()
                    if not first:  # a rotated Zeek log restarts with its header
                        for line in fh:
                            self.feed_line(line, parser)
                for line in fh:
                    self.feed_line(line, parser)
            except OSError as exc:
                self._error(f"{path}: {exc.strerror or exc}")
            self._stop.wait(1.0)
        if fh is not None:
            fh.close()

    def _load_leases(self) -> None:
        for path in self.cfg.gateway_leases:
            try:
                text = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self._error(f"{path}: {exc.strerror or exc}")
                continue
            for lease in parse_leases(text):
                self.devices.setdefault(lease.ip, lease.name)

    def _error(self, msg: str) -> None:
        self.stats.errors = [*self.stats.errors[-4:], msg[:200]]

    # -- events ------------------------------------------------------------------

    def feed_line(self, line: str, parser: LineParser | None = None) -> None:
        self.stats.lines += 1
        events = (parser or LineParser()).parse(line)
        if not events and line.strip() and not line.startswith("#"):
            self.stats.unparsed += 1
        for event in events:
            self.add(event)

    def add(self, event: Event) -> None:
        self.stats.events += 1
        with self._lock:
            if isinstance(event, Lease):
                if event.ip not in (self.cfg.devices or {}):  # names you set win over DHCP
                    self.devices[event.ip] = event.name
                return
            if isinstance(event, DnsEvent):
                self._dns(event)
                return
            if event.action in _BLOCKED and not self.cfg.gateway_include_blocked:
                self.stats.blocked_skipped += 1
                return
            oriented = self.lan.orient(event)
            if oriented is None:
                self.stats.internal_skipped += 1
                return
            device, remote, port, inbound = oriented
            if event.signature:
                if len(self._ids) < 1000:
                    self._ids.append((device, remote, event.signature, event.techniques))
            key = (device, event.proto, remote, port, inbound)
            if key in self._flows:
                self._flows[key] += 1
            elif len(self._flows) < MAX_FLOWS:
                self._flows[key] = 1
            else:
                self.stats.dropped += 1

    def _dns(self, event: DnsEvent) -> None:
        name = event.name.lower()
        dom = classify(name)
        if dom is None or dom.kind is not Kind.DOMAIN:
            return
        for ip in event.answers:
            names = self._answers.pop(ip, [])
            if dom.value not in names:
                names = [dom.value, *names][:5]
            self._answers[ip] = names
            if len(self._answers) > MAX_DNS:
                self._answers.popitem(last=False)
        if event.client:
            try:
                inside = self.lan.inside(event.client)
            except ValueError:
                inside = False
            if inside and (len(self._queries) < MAX_FLOWS or dom.value in self._queries):
                self._queries.setdefault(dom.value, set()).add(event.client)

    # -- snapshot ------------------------------------------------------------------

    def collect(self, now: float | None = None) -> Snapshot:
        """Flows seen in the last ``gateway_window`` seconds (plus the live conntrack table).

        Log and flow inputs report events, not state, so recent flows are kept for a
        rolling window: the live table shows who talked to what lately, not just in
        the last few seconds.
        """
        if not self.started:
            self.start()
        if self.cfg.gateway_conntrack:
            for flow in parse_conntrack(read_conntrack()):
                self.add(flow)
        now = time.time() if now is None else now
        cutoff = now - max(0.0, float(self.cfg.gateway_window))
        with self._lock:
            fresh, self._flows = self._flows, {}
            ids, self._ids = self._ids, []
            new_queries, self._queries = self._queries, {}
            answers = dict(self._answers)
            devices = dict(self.devices)
        for key, count in fresh.items():
            seen = self._recent.get(key)
            self._recent[key] = (seen[0] + count if seen else count, now)
        for name, clients in new_queries.items():
            for client in clients:
                self._recent_queries[(name, client)] = now
        self._recent = {k: v for k, v in self._recent.items() if v[1] >= cutoff}
        if len(self._recent) > 2 * MAX_FLOWS:  # keep the most recently seen
            keep = sorted(self._recent.items(), key=lambda kv: -kv[1][1])[: 2 * MAX_FLOWS]
            self._recent = dict(keep)
        self._recent_queries = {k: t for k, t in self._recent_queries.items() if t >= cutoff}
        flows = {k: v[0] for k, v in self._recent.items()}
        queries: dict[str, set[str]] = {}
        for name, client in self._recent_queries:
            queries.setdefault(name, set()).add(client)
        conns = [
            Connection(
                proto,
                device,
                remote,
                port or 0,
                "NEW" if (device, proto, remote, port, inbound) in fresh else "RECENT",
                device=device,
                device_name=devices.get(device),
                inbound=inbound,
                count=count,
            )
            for (device, proto, remote, port, inbound), count in flows.items()
        ]
        remotes = {c.remote_ip for c in conns}
        dns = {ip: names for ip, names in answers.items() if ip in remotes}
        return Snapshot(
            conns,
            dns,
            queries={d: sorted(c) for d, c in queries.items()},
            devices=devices,
            ids_alerts=ids,
        )

    def status(self) -> dict[str, Any]:
        s = self.stats
        return {
            "inputs": self.inputs,
            "datagrams": s.datagrams,
            "lines": s.lines,
            "events": s.events,
            "unparsed_lines": s.unparsed,
            "rejected_senders": s.rejected_senders,
            "blocked_skipped": s.blocked_skipped,
            "internal_skipped": s.internal_skipped,
            "dropped": s.dropped,
            "devices_named": len(self.devices),
            "errors": s.errors,
            "lan_networks": [str(n) for n in self.lan.networks] or ["all non-public addresses"],
        }
