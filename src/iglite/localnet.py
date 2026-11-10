"""Local network: this computer's adapters, the Wi-Fi it is on, who shares it, and what is exposed.

Three questions, answered from this computer alone with no admin rights:

1. **Is this Wi-Fi safe?** The security of the network you're on (open, WEP,
   WPA/TKIP), nearby networks with the same name but different security (an
   "evil twin"), the router's hardware address changing between scans (ARP
   spoofing), and DNS servers changing.
2. **Who else is on it?** Devices in this computer's neighbour table for that
   adapter, with new ones called out.
3. **What on this computer can they reach?** The exposure map: every
   listening service and program, and which network adapters (Wi-Fi, Ethernet,
   VPN, the Mobile hotspot you share, virtual switches) it is reachable on,
   against a list of risky ports (file sharing, remote desktop, databases,
   discovery protocols). Windows Firewall's state and the network's profile
   (Public/Private) are taken into account.

It also gives live monitoring a "Wi-Fi only" scope: :func:`wifi_addresses`
returns this computer's addresses on Wi-Fi adapters, and connections made from
any other address are left out.

Collectors:

* Windows - one PowerShell call (``Get-NetAdapter``, ``Get-NetIPAddress``,
  ``Get-NetRoute``, ``Get-DnsClientServerAddress``, ``Get-NetConnectionProfile``,
  ``Get-NetFirewallProfile``, ``Get-NetNeighbor``, ``Get-NetTCPConnection``,
  ``Get-NetUDPEndpoint``, ``Win32_Service``) that returns language-independent
  JSON, plus ``netsh wlan show interfaces`` / ``show networks mode=bssid`` for
  Wi-Fi details (English labels; Windows 11 needs Location turned on to list
  nearby networks).
* Linux - ``/sys/class/net``, ``/proc/net`` (routes, ARP, sockets),
  ``/etc/resolv.conf`` and ``nmcli`` when present.

Nothing here sends packets: it only reads what the operating system already
knows.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .store import Store

# -- model ----------------------------------------------------------------------------


@dataclass
class Adapter:
    name: str
    description: str = ""
    index: int | None = None
    status: str = "Up"  # Up | Disconnected | ...
    mac: str | None = None
    kind: str = "other"  # wifi | hotspot | ethernet | vpn | virtual | bluetooth | loopback | other
    addresses: list[str] = field(default_factory=list)  # "ip/prefix"
    gateways: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    profile: str | None = None  # Windows network category: Public | Private | DomainAuthenticated
    network: str | None = None  # Windows profile name (usually the SSID) / Linux connection

    @property
    def up(self) -> bool:
        return self.status.lower() in ("up", "connected") and bool(self.addresses)

    def ips(self) -> list[str]:
        return [a.split("/")[0] for a in self.addresses]


@dataclass
class WifiLink:
    interface: str
    state: str = ""
    ssid: str | None = None
    bssid: str | None = None
    auth: str | None = None
    cipher: str | None = None
    signal: int | None = None  # percent
    channel: str | None = None
    radio: str | None = None


@dataclass
class NearbyNetwork:
    ssid: str
    auth: str = ""
    encryption: str = ""
    bssids: list[dict[str, Any]] = field(default_factory=list)  # {bssid, signal, channel}


@dataclass
class Device:
    ip: str
    mac: str
    adapter: str
    state: str = ""


@dataclass
class Listener:
    proto: str  # tcp | udp
    address: str  # bound address: 0.0.0.0 / :: = every adapter
    port: int
    pid: int | None = None
    process: str | None = None
    services: list[str] = field(default_factory=list)  # Windows service display names


@dataclass
class LocalNetwork:
    platform: str
    adapters: list[Adapter] = field(default_factory=list)
    wifi: list[WifiLink] = field(default_factory=list)
    nearby: list[NearbyNetwork] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    firewall: dict[str, dict[str, Any]] = field(default_factory=dict)  # profile -> {enabled, inbound}
    errors: list[str] = field(default_factory=list)
    collected_at: float = field(default_factory=time.time)

    def adapter(self, name: str) -> Adapter | None:
        return next((a for a in self.adapters if a.name == name), None)


# -- helpers ------------------------------------------------------------------------------

_VPN_WORDS = (
    "vpn",
    "tap-windows",
    "tap adapter",
    "wireguard",
    "openvpn",
    "anyconnect",
    "fortinet",
    "globalprotect",
    "pangp",
    "tailscale",
    "zerotier",
    "nordlynx",
    "wintun",
    "juniper",
    "pulse secure",
)
_VIRTUAL_WORDS = (
    "hyper-v",
    "vethernet",
    "virtualbox",
    "vmware",
    "wsl",
    "docker",
    "loopback pseudo",
    "npcap loopback",
)


def classify_adapter(name: str, description: str = "", media: str = "") -> str:
    text = f"{name} {description}".lower()
    media = media.lower()
    if "loopback" in text and "npcap" not in text:
        return "loopback"
    if "wi-fi direct" in text or "hosted network" in text:
        return "hotspot"  # the virtual adapter Windows' Mobile hotspot runs on
    if any(w in text for w in _VPN_WORDS):
        return "vpn"
    if any(w in text for w in _VIRTUAL_WORDS):
        return "virtual"
    if "bluetooth" in text:
        return "bluetooth"
    if (
        "802.11" in media
        or "wireless" in media
        or "wi-fi" in text
        or "wireless" in text
        or "wlan" in text
        or "802.11" in text
    ):
        return "wifi"
    if "802.3" in media or "ethernet" in text:
        return "ethernet"
    return "other"


def _as_list(value: Any) -> list[Any]:
    """PowerShell's ConvertTo-Json turns one-item arrays into a bare object."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _mac(value: Any) -> str | None:
    if not value:
        return None
    text = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower()
    return ":".join(text[i : i + 2] for i in range(0, 12, 2)) if len(text) == 12 else None


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).split("%")[0]))
    except ValueError:
        return None


def is_device_neighbour(ip: str, mac: str | None) -> bool:
    """Real devices only: no multicast/broadcast, no empty or group hardware addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback or str(addr).endswith(".255"):
        return False
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    return not int(mac.split(":")[0], 16) & 1  # group (multicast) bit


def randomized_mac(mac: str) -> bool:
    """Locally administered: phones' private Wi-Fi addresses, virtual machines."""
    return bool(int(mac.split(":")[0], 16) & 2)


def _run(cmd: list[str], timeout: float = 30) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(  # noqa: S603 - fixed argument lists, no shell
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=flags,
    ).stdout


# -- Windows -------------------------------------------------------------------------------

# Enum properties are converted to strings ("$(...)"): Windows PowerShell 5.1 would emit numbers.
PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$o.adapters = @(Get-NetAdapter -IncludeHidden | Select-Object Name, InterfaceDescription, InterfaceIndex, MacAddress,
    @{n='Status';e={"$($_.Status)"}}, @{n='MediaType';e={"$($_.MediaType)"}}, @{n='PhysicalMediaType';e={"$($_.PhysicalMediaType)"}})
$o.addresses = @(Get-NetIPAddress | Select-Object InterfaceIndex, IPAddress, PrefixLength)
$o.routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' | Select-Object InterfaceIndex, NextHop, RouteMetric)
$o.dns = @(Get-DnsClientServerAddress | Select-Object InterfaceIndex, ServerAddresses)
$o.profiles = @(Get-NetConnectionProfile | Select-Object InterfaceIndex, Name, @{n='NetworkCategory';e={"$($_.NetworkCategory)"}})
$o.firewall = @(Get-NetFirewallProfile | Select-Object Name, @{n='Enabled';e={"$($_.Enabled)"}}, @{n='DefaultInboundAction';e={"$($_.DefaultInboundAction)"}})
$o.neighbors = @(Get-NetNeighbor | Where-Object { "$($_.State)" -in 'Reachable','Stale','Delay','Probe' } |
    Select-Object InterfaceIndex, IPAddress, LinkLayerAddress, @{n='State';e={"$($_.State)"}})
$o.tcp = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess)
$o.udp = @(Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess)
$o.services = @(Get-CimInstance Win32_Service -Filter "State='Running'" | Select-Object Name, DisplayName, ProcessId)
$o.processes = @(Get-Process | Select-Object Id, ProcessName)
$o | ConvertTo-Json -Depth 4 -Compress
"""

_WLAN_KEYS = {
    "name": "interface",
    "state": "state",
    "ssid": "ssid",
    "bssid": "bssid",
    "ap bssid": "bssid",
    "authentication": "auth",
    "cipher": "cipher",
    "signal": "signal",
    "channel": "channel",
    "radio type": "radio",
}


def parse_netsh_interfaces(text: str) -> list[WifiLink]:
    """``netsh wlan show interfaces`` (English labels)."""
    links: list[WifiLink] = []
    current: dict[str, str] = {}

    def flush() -> None:
        if current.get("interface"):
            signal = re.match(r"(\d+)", current.get("signal", ""))
            links.append(
                WifiLink(
                    interface=current["interface"],
                    state=current.get("state", ""),
                    ssid=current.get("ssid") or None,
                    bssid=_mac(current.get("bssid")),
                    auth=current.get("auth"),
                    cipher=current.get("cipher"),
                    signal=int(signal.group(1)) if signal else None,
                    channel=current.get("channel"),
                    radio=current.get("radio"),
                )
            )
        current.clear()

    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        field_ = _WLAN_KEYS.get(key)
        if field_ is None:
            continue
        if field_ == "interface" and current.get("interface"):
            flush()
        current[field_] = value
    flush()
    return links


def parse_netsh_networks(text: str) -> list[NearbyNetwork]:
    """``netsh wlan show networks mode=bssid`` (English labels)."""
    networks: list[NearbyNetwork] = []
    net: NearbyNetwork | None = None
    bss: dict[str, Any] | None = None
    for line in text.splitlines():
        m = re.match(r"\s*SSID\s+\d+\s*:\s?(.*)$", line)
        if m:
            net = NearbyNetwork(ssid=m.group(1).strip())
            networks.append(net)
            bss = None
            continue
        if net is None or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "authentication":
            net.auth = value
        elif key == "encryption":
            net.encryption = value
        elif re.match(r"bssid \d+", key):
            bss = {"bssid": _mac(value), "signal": None, "channel": None}
            net.bssids.append(bss)
        elif bss is not None and key == "signal":
            sig = re.match(r"(\d+)", value)
            bss["signal"] = int(sig.group(1)) if sig else None
        elif bss is not None and key == "channel":
            bss["channel"] = value
    return networks


def parse_windows(data: dict[str, Any], interfaces: str = "", networks: str = "") -> LocalNetwork:
    """Build the model from the PowerShell JSON and the two netsh outputs."""
    net = LocalNetwork(platform="windows")
    by_index: dict[int, Adapter] = {}
    for a in _as_list(data.get("adapters")):
        adapter = Adapter(
            name=str(a.get("Name") or ""),
            description=str(a.get("InterfaceDescription") or ""),
            index=a.get("InterfaceIndex"),
            status=str(a.get("Status") or ""),
            mac=_mac(a.get("MacAddress")),
            kind=classify_adapter(
                str(a.get("Name") or ""),
                str(a.get("InterfaceDescription") or ""),
                f"{a.get('MediaType') or ''} {a.get('PhysicalMediaType') or ''}",
            ),
        )
        if adapter.index is not None:
            by_index[int(adapter.index)] = adapter
        net.adapters.append(adapter)
    for row in _as_list(data.get("addresses")):
        adapter = by_index.get(int(row.get("InterfaceIndex") or -1))
        ip = _ip(row.get("IPAddress"))
        if adapter and ip:
            adapter.addresses.append(f"{ip}/{row.get('PrefixLength')}")
    for row in _as_list(data.get("routes")):
        adapter = by_index.get(int(row.get("InterfaceIndex") or -1))
        hop = _ip(row.get("NextHop"))
        if adapter and hop and not ipaddress.ip_address(hop).is_unspecified and hop not in adapter.gateways:
            adapter.gateways.append(hop)
    for row in _as_list(data.get("dns")):
        adapter = by_index.get(int(row.get("InterfaceIndex") or -1))
        if adapter:
            adapter.dns += [
                ip for s in _as_list(row.get("ServerAddresses")) if (ip := _ip(s)) and ip not in adapter.dns
            ]
    for row in _as_list(data.get("profiles")):
        adapter = by_index.get(int(row.get("InterfaceIndex") or -1))
        if adapter:
            adapter.profile, adapter.network = row.get("NetworkCategory") or None, row.get("Name") or None
    for row in _as_list(data.get("firewall")):
        inbound = str(row.get("DefaultInboundAction") or "")
        net.firewall[str(row.get("Name"))] = {
            "enabled": str(row.get("Enabled")).lower() == "true",
            # NotConfigured means Windows' default, which blocks inbound.
            "inbound": "Block" if inbound in ("", "NotConfigured") else inbound,
        }
    for row in _as_list(data.get("neighbors")):
        adapter = by_index.get(int(row.get("InterfaceIndex") or -1))
        ip, mac = _ip(row.get("IPAddress")), _mac(row.get("LinkLayerAddress"))
        if adapter and ip and is_device_neighbour(ip, mac):
            net.devices.append(Device(ip, mac or "", adapter.name, str(row.get("State") or "")))

    names = {
        int(p["Id"]): str(p.get("ProcessName") or "")
        for p in _as_list(data.get("processes"))
        if p.get("Id") is not None
    }
    services: dict[int, list[str]] = {}
    for s in _as_list(data.get("services")):
        if s.get("ProcessId"):
            services.setdefault(int(s["ProcessId"]), []).append(str(s.get("DisplayName") or s.get("Name")))
    for proto in ("tcp", "udp"):
        for row in _as_list(data.get(proto)):
            ip, port, pid = _ip(row.get("LocalAddress")), row.get("LocalPort"), row.get("OwningProcess")
            if ip is None or port is None:
                continue
            pid = int(pid) if pid is not None else None
            process = names.get(pid) if pid is not None else None
            if process and not process.lower().endswith(".exe") and process.lower() not in ("system", "idle"):
                process += ".exe"
            net.listeners.append(
                Listener(proto, ip, int(port), pid, process, services.get(pid or -1, [])[:6])
            )

    net.wifi = parse_netsh_interfaces(interfaces)
    if "location permission" in networks.lower() or "location services" in networks.lower():
        net.errors.append(
            "Windows needs Location turned on to list nearby Wi-Fi networks "
            "(Settings > Privacy & security > Location; allow desktop apps)."
        )
    else:
        net.nearby = parse_netsh_networks(networks)
    for link in net.wifi:  # the adapter's SSID, from netsh
        if (adapter := net.adapter(link.interface)) is not None and link.ssid:
            adapter.network = link.ssid
            if adapter.kind == "other":
                adapter.kind = "wifi"
    return net


def collect_windows() -> LocalNetwork:
    encoded = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode()
    raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout=60)
    try:
        data = json.loads(raw) if raw.strip() else {}
    except ValueError:
        data = {}
    interfaces = _run(["netsh", "wlan", "show", "interfaces"])
    networks = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    net = parse_windows(data, interfaces, networks)
    if not data:
        net.errors.insert(
            0, "PowerShell returned nothing: adapter, service and exposure details are missing."
        )
    return net


# -- Linux ---------------------------------------------------------------------------------


def _ipv4_of(ifname: str) -> str | None:
    try:
        import fcntl
    except ImportError:  # pragma: no cover - not Linux
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", ifname.encode()[:15])
        addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24])  # SIOCGIFADDR
        mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, packed)[20:24])  # SIOCGIFNETMASK
        return f"{addr}/{ipaddress.IPv4Network(f'0.0.0.0/{mask}').prefixlen}"
    except OSError:
        return None
    finally:
        s.close()


def parse_proc_route(text: str) -> dict[str, list[str]]:
    """Default gateways per interface from /proc/net/route."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000" and parts[2] != "00000000":
            gw = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
            out.setdefault(parts[0], []).append(gw)
    return out


def parse_proc_arp(text: str) -> list[Device]:
    devices = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[2] != "0x0":
            mac = _mac(parts[3])
            if is_device_neighbour(parts[0], mac):
                devices.append(Device(parts[0], mac or "", parts[5], "reachable"))
    return devices


def parse_nmcli(text: str) -> tuple[list[WifiLink], list[NearbyNetwork]]:
    """``nmcli -t -f IN-USE,SSID,BSSID,SECURITY,SIGNAL,CHAN,DEVICE device wifi list``."""
    links, nearby = [], {}
    for line in text.splitlines():
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 7:
            continue
        in_use, ssid, bssid, security, signal, chan, dev = parts[:7]
        auth = security or "Open"
        if in_use.strip() == "*":
            links.append(
                WifiLink(
                    dev,
                    "connected",
                    ssid or None,
                    _mac(bssid),
                    auth,
                    None,
                    int(signal) if signal.isdigit() else None,
                    chan,
                )
            )
        net = nearby.setdefault((ssid, auth), NearbyNetwork(ssid, auth, ""))
        net.bssids.append(
            {"bssid": _mac(bssid), "signal": int(signal) if signal.isdigit() else None, "channel": chan}
        )
    return links, list(nearby.values())


def collect_linux(sysfs: Path = Path("/sys/class/net"), proc: Path = Path("/proc/net")) -> LocalNetwork:
    from .netwatch import _proc_addr, _socket_owners

    net = LocalNetwork(platform="linux")
    gateways = parse_proc_route((proc / "route").read_text()) if (proc / "route").exists() else {}
    dns = []
    try:
        dns = [
            p[1]
            for line in Path("/etc/resolv.conf").read_text().splitlines()
            if (p := line.split()) and p[0] == "nameserver" and len(p) > 1 and _ip(p[1])
        ]
    except OSError:
        pass
    v6: dict[str, list[str]] = {}
    if (proc / "if_inet6").exists():
        for line in (proc / "if_inet6").read_text().splitlines():
            p = line.split()
            if len(p) >= 6:
                v6.setdefault(p[5], []).append(
                    f"{ipaddress.IPv6Address(bytes.fromhex(p[0]))}/{int(p[2], 16)}"
                )
    for path in sorted(sysfs.iterdir()) if sysfs.exists() else []:
        name = path.name
        kind = (
            "wifi"
            if (path / "wireless").exists() or name.startswith("wl")
            else "loopback"
            if name == "lo"
            else "vpn"
            if name.startswith(("tun", "tap", "wg", "ppp", "tailscale"))
            else "virtual"
            if name.startswith(("docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "lxc"))
            else "ethernet"
            if name.startswith(("eth", "en"))
            else "other"
        )
        try:
            state = (path / "operstate").read_text().strip()
            mac = _mac((path / "address").read_text().strip())
        except OSError:
            state, mac = "unknown", None
        addresses = [a for a in [_ipv4_of(name)] if a] + v6.get(name, [])
        status = (
            "Up"
            if state in ("up", "unknown") and addresses
            else ("Down" if state == "down" else state.title())
        )
        net.adapters.append(
            Adapter(
                name,
                "",
                None,
                status,
                mac,
                kind,
                addresses,
                gateways.get(name, []),
                dns if gateways.get(name) else [],
            )
        )
    if (proc / "arp").exists():
        net.devices = parse_proc_arp((proc / "arp").read_text())
    owners = _socket_owners()
    for proto, files, listen in (("tcp", ("tcp", "tcp6"), "0A"), ("udp", ("udp", "udp6"), "07")):
        for fname in files:
            path = proc / fname
            if not path.exists():
                continue
            for line in path.read_text().splitlines()[1:]:
                p = line.split()
                if len(p) < 10 or p[3] != listen:
                    continue
                try:
                    ip, port = _proc_addr(p[1])
                    _, rport = _proc_addr(p[2])
                except ValueError:
                    continue
                if proto == "udp" and rport != 0:
                    continue
                pid, pname = owners.get(p[9], (None, None))
                net.listeners.append(Listener(proto, ip, port, pid, pname))
    try:
        out = _run(
            ["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,SECURITY,SIGNAL,CHAN,DEVICE", "device", "wifi", "list"]
        )
        net.wifi, net.nearby = parse_nmcli(out)
    except (OSError, subprocess.SubprocessError):
        pass
    for link in net.wifi:
        if (adapter := net.adapter(link.interface)) is not None:
            adapter.network = link.ssid
    return net


PS_ADAPTERS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$o.adapters = @(Get-NetAdapter -IncludeHidden | Select-Object Name, InterfaceDescription, InterfaceIndex, MacAddress,
    @{n='Status';e={"$($_.Status)"}}, @{n='MediaType';e={"$($_.MediaType)"}}, @{n='PhysicalMediaType';e={"$($_.PhysicalMediaType)"}})
$o.addresses = @(Get-NetIPAddress | Select-Object InterfaceIndex, IPAddress, PrefixLength)
$o | ConvertTo-Json -Depth 4 -Compress
"""


def collect_adapters() -> LocalNetwork:
    """Adapters and addresses only: cheap enough to refresh the Wi-Fi scope of live monitoring."""
    if sys.platform == "win32":
        encoded = base64.b64encode(PS_ADAPTERS.encode("utf-16-le")).decode()
        raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout=30)
        try:
            data = json.loads(raw) if raw.strip() else {}
        except ValueError:
            data = {}
        return parse_windows(data, _run(["netsh", "wlan", "show", "interfaces"]))
    return collect()


def collect() -> LocalNetwork:
    if sys.platform == "win32":
        return collect_windows()
    if Path("/proc/net").exists():
        return collect_linux()
    return LocalNetwork(
        platform=sys.platform, errors=["Local network details are available on Windows and Linux."]
    )


# -- analysis ----------------------------------------------------------------------------------

# port -> (severity, what it is, why it matters). Severity: high | medium | low.
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("high", "FTP", "file transfer, usually unencrypted passwords"),
    23: ("high", "Telnet", "remote login without encryption"),
    445: ("high", "SMB file sharing", "shared folders and printers; a classic worm and ransomware target"),
    3389: ("high", "Remote Desktop", "full remote control of this computer if a password is guessed"),
    5900: ("high", "VNC", "remote screen control"),
    5901: ("high", "VNC", "remote screen control"),
    5985: ("high", "WinRM (HTTP)", "remote PowerShell"),
    5986: ("high", "WinRM (HTTPS)", "remote PowerShell"),
    1433: ("high", "SQL Server", "database"),
    3306: ("high", "MySQL", "database"),
    5432: ("high", "PostgreSQL", "database"),
    27017: ("high", "MongoDB", "database, often without a password"),
    6379: ("high", "Redis", "database, often without a password"),
    9200: ("high", "Elasticsearch", "search database"),
    2375: ("high", "Docker API", "control of every container, without authentication"),
    11434: ("high", "Ollama", "local AI server without authentication: others can use your model and GPU"),
    22: ("medium", "SSH", "remote login"),
    135: ("medium", "Windows RPC", "remote management endpoint mapper"),
    139: ("medium", "NetBIOS session", "legacy file sharing"),
    137: ("medium", "NetBIOS name service", "announces this computer's name to the network"),
    138: ("medium", "NetBIOS datagram", "legacy network browsing"),
    5355: ("medium", "LLMNR", "name lookups others can answer falsely to capture password hashes"),
    5353: ("low", "mDNS / Bonjour", "announces this computer and its services on the network"),
    1900: ("medium", "SSDP / UPnP", "device discovery; announces this computer"),
    2869: ("medium", "UPnP host", "device discovery and media sharing"),
    3702: ("low", "WS-Discovery", "Windows device discovery"),
    554: ("medium", "RTSP", "video streaming"),
    80: ("medium", "Web server (HTTP)", "a web server is running"),
    443: ("low", "Web server (HTTPS)", "a web server is running"),
    8080: ("medium", "Web/dev server", "development servers often have no login"),
    8000: ("medium", "Web/dev server", "development servers often have no login"),
    8888: ("medium", "Web/dev server (Jupyter?)", "Jupyter can run code on this computer"),
    3000: ("medium", "Web/dev server", "development servers often have no login"),
    5000: ("medium", "Web/dev server", "development servers often have no login"),
    8765: ("medium", "IntelGraph Lite", "this dashboard (needs a token when shared)"),
    7680: ("low", "Delivery Optimization", "Windows Update peer sharing"),
    5040: ("low", "Windows CDP", "connected devices platform"),
}
_KIND_ORDER = {"wifi": 0, "hotspot": 1, "ethernet": 2, "vpn": 3, "virtual": 4, "bluetooth": 5, "other": 6}
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_LOWER = {"high": "medium", "medium": "low", "low": "low", "info": "info"}


def _wildcard(address: str) -> bool:
    return address in ("0.0.0.0", "::")  # noqa: S104 - comparison only


def reachable_on(listener: Listener, adapter: Adapter) -> bool:
    """Can a device on this adapter's network connect to this listener?"""
    if not adapter.up or adapter.kind == "loopback":
        return False
    try:
        bound = ipaddress.ip_address(listener.address)
    except ValueError:
        return False
    if bound.is_loopback:
        return False
    if _wildcard(listener.address):
        return any(ipaddress.ip_address(ip).version == bound.version for ip in adapter.ips())
    return listener.address in adapter.ips()


def _risk(listener: Listener) -> tuple[str, str, str]:
    if listener.port in RISKY_PORTS:
        return RISKY_PORTS[listener.port]
    if (
        listener.proto == "tcp"
        and 49152 <= listener.port <= 65535
        and (listener.process or "").lower()
        in ("lsass.exe", "wininit.exe", "services.exe", "spoolsv.exe", "svchost.exe")
    ):
        return ("low", "Windows RPC dynamic port", "Windows service endpoint")
    return ("low", "Other service", "a program is accepting connections")


def _firewall_for(net: LocalNetwork, adapter: Adapter) -> dict[str, Any] | None:
    if not net.firewall or not adapter.profile:
        return None
    name = {"DomainAuthenticated": "Domain"}.get(adapter.profile, adapter.profile)
    return net.firewall.get(name)


def exposure(net: LocalNetwork) -> dict[str, Any]:
    """For each adapter: the services and programs reachable on it, riskiest first."""
    # One entry per (proto, port, process): IPv4 and IPv6 sockets of the same service fold together.
    merged: dict[tuple[str, int, int | None], list[Listener]] = {}
    for listener in net.listeners:
        if listener.proto == "udp" and listener.port >= 49152 and listener.port not in RISKY_PORTS:
            continue  # ephemeral client sockets, not services
        merged.setdefault((listener.proto, listener.port, listener.pid), []).append(listener)

    adapters, local_only = [], []
    for adapter in sorted(net.adapters, key=lambda a: (not a.up, _KIND_ORDER.get(a.kind, 9), a.name)):
        if adapter.kind == "loopback" or not adapter.up:
            continue
        fw = _firewall_for(net, adapter)
        shielded = bool(fw and fw["enabled"] and fw["inbound"] == "Block" and adapter.profile == "Public")
        items = []
        for (proto, port, pid), group in merged.items():
            if not any(reachable_on(listener, adapter) for listener in group):
                continue
            sev, label, why = _risk(group[0])
            items.append(
                {
                    "proto": proto,
                    "port": port,
                    "pid": pid,
                    "process": group[0].process,
                    "services": group[0].services,
                    "bound": sorted({listener.address for listener in group}),
                    "label": label,
                    "why": why,
                    "risk": _LOWER[sev] if shielded else sev,
                    "raw_risk": sev,
                }
            )
        items.sort(key=lambda i: (_SEVERITY_ORDER[i["risk"]], i["port"]))
        adapters.append(
            {
                "name": adapter.name,
                "kind": adapter.kind,
                "description": adapter.description,
                "network": adapter.network,
                "addresses": adapter.addresses,
                "profile": adapter.profile,
                "firewall": fw,
                "firewall_shields": shielded,
                "listeners": items,
                "counts": {s: sum(i["risk"] == s for i in items) for s in ("high", "medium", "low")},
            }
        )
    for (proto, port, _pid), group in merged.items():
        if all(
            ipaddress.ip_address(listener.address).is_loopback for listener in group if _ip(listener.address)
        ):
            local_only.append(
                {"proto": proto, "port": port, "process": group[0].process, "services": group[0].services}
            )
    local_only.sort(key=lambda i: i["port"])
    return {"adapters": adapters, "local_only": local_only}


def _norm_auth(auth: str | None) -> str:
    a = (auth or "").lower().replace(" ", "")
    if not a or a in ("open", "none", "--"):
        return "open"
    if "wep" in a:
        return "wep"
    if "wpa3" in a or "sae" in a:
        return "wpa3"
    if "wpa2" in a or "rsn" in a:
        return "wpa2"
    if "wpa" in a:
        return "wpa"
    return a


def wifi_addresses(net: LocalNetwork) -> set[str]:
    """This computer's addresses on Wi-Fi: as a client and on a Mobile hotspot it shares."""
    return {ip for a in net.adapters if a.kind in ("wifi", "hotspot") and a.up for ip in a.ips()}


def network_key(adapter: Adapter) -> str:
    return f"{adapter.network or adapter.name}|{','.join(adapter.gateways)}"


def findings(net: LocalNetwork, previous: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Problems worth knowing about, worst first. ``previous`` is the remembered state per network."""
    previous = previous or {}
    out: list[dict[str, Any]] = []

    def add(severity: str, title: str, detail: str, fix: str = "", adapter: str | None = None) -> None:
        out.append({"severity": severity, "title": title, "detail": detail, "fix": fix, "adapter": adapter})

    current_ssids = set()
    for link in net.wifi:
        if not link.ssid or "connected" not in (link.state or "connected").lower():
            continue
        current_ssids.add(link.ssid)
        auth = _norm_auth(link.auth)
        if auth == "open":
            add(
                "high",
                f'"{link.ssid}" has no password',
                "Anyone nearby can read traffic that isn't encrypted by the website or app itself, "
                "and anyone can join and reach this computer.",
                "Prefer a VPN on this network, and keep the network set to Public.",
                link.interface,
            )
        elif auth == "wep":
            add(
                "high",
                f'"{link.ssid}" uses WEP',
                "WEP can be broken in minutes; treat it as open.",
                "Avoid this network or use a VPN.",
                link.interface,
            )
        elif "tkip" in (link.cipher or "").lower() or auth == "wpa":
            add(
                "medium",
                f'"{link.ssid}" uses outdated Wi-Fi security ({link.auth}, {link.cipher})',
                "WPA/TKIP has known weaknesses.",
                "Use a VPN, or ask for WPA2/WPA3 (AES).",
                link.interface,
            )
        twins = [n for n in net.nearby if n.ssid == link.ssid and _norm_auth(n.auth) != auth]
        if twins:
            kinds = ", ".join(sorted({n.auth or "Open" for n in twins}))
            add(
                "high",
                f'Possible evil twin of "{link.ssid}"',
                f"Another network with the same name uses different security ({kinds}, yours: {link.auth}). "
                "Fake hotspots copy a trusted name to intercept traffic.",
                "Make sure you are connected to the real one; forget and rejoin it if unsure.",
                link.interface,
            )
    for n in net.nearby:  # look-alikes of networks you are not on
        if n.ssid and n.ssid not in current_ssids:
            variants = {_norm_auth(m.auth) for m in net.nearby if m.ssid == n.ssid}
            if (
                "open" in variants
                and len(variants) > 1
                and not any(f["title"].endswith(f'"{n.ssid}"') for f in out)
            ):
                add(
                    "medium",
                    f'Open copy of "{n.ssid}" nearby',
                    "A network with that name exists both with and without a password nearby.",
                    "Don't join the open one.",
                )

    for adapter in net.adapters:
        if not adapter.up or adapter.kind not in ("wifi", "hotspot", "ethernet"):
            continue
        label = f'"{adapter.network}"' if adapter.network else adapter.name
        fw = _firewall_for(net, adapter)
        if fw is not None and not fw["enabled"]:
            add(
                "high",
                f"Windows Firewall is off for the {adapter.profile} profile ({label})",
                "Every listening service on this computer is reachable from that network.",
                "Turn it on: Windows Security > Firewall & network protection.",
                adapter.name,
            )
        if adapter.kind == "wifi" and adapter.profile == "Private":
            add(
                "medium",
                f"Windows trusts {label} as a Private network",
                "On Private networks Windows allows network discovery and file sharing. "
                "Fine at home; not on a hotspot or café Wi-Fi.",
                "If it isn't your own network: Settings > Network & internet > Wi-Fi > this network > Public.",
                adapter.name,
            )
        if adapter.kind == "hotspot":
            count = sum(d.adapter == adapter.name for d in net.devices)
            add(
                "info",
                f"You are sharing a Mobile hotspot ({count} device(s) connected)",
                "Devices on your hotspot can reach services listening on all networks (see the exposure map).",
                "Turn the hotspot off when you don't need it.",
                adapter.name,
            )

        state = previous.get(network_key(adapter)) or {}
        gw_now = {d.ip: d.mac for d in net.devices if d.adapter == adapter.name and d.ip in adapter.gateways}
        for ip, mac in gw_now.items():
            before = (state.get("gateway_macs") or {}).get(ip)
            if before and before != mac:
                add(
                    "high",
                    f"The router's hardware address changed on {label}",
                    f"{ip} was {before}, now {mac}. This happens with a replaced router or a different access "
                    "point, but also when another device impersonates the router (ARP spoofing).",
                    "If you didn't change anything, disconnect and reconnect, and check again.",
                    adapter.name,
                )
        if state.get("dns") and adapter.dns and sorted(state["dns"]) != sorted(adapter.dns):
            add(
                "medium",
                f"DNS servers changed on {label}",
                f"Was {', '.join(state['dns'])}, now {', '.join(adapter.dns)}. Changed DNS can redirect websites.",
                "If you didn't change it, check the router's settings.",
                adapter.name,
            )
        known = set(state.get("devices") or [])
        new = sorted(d.mac for d in net.devices if d.adapter == adapter.name and d.mac not in known)
        if known and new:
            add("info", f"{len(new)} new device(s) on {label}", ", ".join(new[:8]), "", adapter.name)

    for item in exposure(net)["adapters"]:
        if item["kind"] not in ("wifi", "hotspot"):
            continue
        risky = [i for i in item["listeners"] if i["raw_risk"] == "high"]
        where = "your Mobile hotspot" if item["kind"] == "hotspot" else (item["network"] or item["name"])
        if risky:
            names = ", ".join(f"{i['label']} ({i['proto'].upper()} {i['port']})" for i in risky[:5])
            shield = (
                " Windows Firewall (Public, inbound blocked) probably stops them unless an allow rule exists."
                if item["firewall_shields"]
                else ""
            )
            add(
                "medium" if item["firewall_shields"] else "high",
                f"{len(risky)} risky service(s) reachable on {where}",
                f"{names}.{shield}",
                "Stop the services you don't use, or restrict them to this computer.",
                item["name"],
            )
    out.sort(key=lambda f: _SEVERITY_ORDER[f["severity"]])
    return out


def remember(net: LocalNetwork) -> dict[str, Any]:
    """The per-network state to compare against next time."""
    state = {}
    for adapter in net.adapters:
        if not adapter.up or adapter.kind == "loopback":
            continue
        state[network_key(adapter)] = {
            "gateway_macs": {
                d.ip: d.mac for d in net.devices if d.adapter == adapter.name and d.ip in adapter.gateways
            },
            "dns": adapter.dns,
            "devices": sorted({d.mac for d in net.devices if d.adapter == adapter.name}),
        }
    return state


def report(net: LocalNetwork, store: Store | None = None) -> dict[str, Any]:
    """Everything for the dashboard / CLI: inventory, Wi-Fi, devices, exposure and findings."""
    previous = store.get_meta_json("localnet.state") if store is not None else None
    result = {
        "platform": net.platform,
        "collected_at": net.collected_at,
        "adapters": [asdict(a) | {"up": a.up} for a in net.adapters],
        "wifi": [asdict(w) for w in net.wifi],
        "nearby": [
            asdict(n)
            for n in sorted(
                net.nearby, key=lambda n: -max((b["signal"] or 0) for b in n.bssids or [{"signal": 0}])
            )
        ],
        "devices": [
            asdict(d)
            | {
                "randomized_mac": randomized_mac(d.mac) if d.mac else False,
                "gateway": any(d.ip in a.gateways for a in net.adapters if a.name == d.adapter),
            }
            for d in net.devices
        ],
        "firewall": net.firewall,
        "exposure": exposure(net),
        "findings": findings(net, previous),
        "wifi_addresses": sorted(wifi_addresses(net)),
        "errors": net.errors,
    }
    if store is not None:
        merged = dict(previous or {})
        for key, state in remember(net).items():  # remember devices across scans, not just the last one
            old = merged.get(key) or {}
            state["devices"] = sorted(set(state["devices"]) | set(old.get("devices") or []))
            merged[key] = state
        store.set_meta_json("localnet.state", merged)
    return result
