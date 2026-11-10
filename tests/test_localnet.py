"""Local network: Wi-Fi safety, devices on the network, exposure map, and Wi-Fi-only monitoring."""

import json
import threading
import urllib.request

import pytest

from iglite import localnet
from iglite.api import make_server
from iglite.cli import main
from iglite.localnet import Adapter, Listener, LocalNetwork, NearbyNetwork, WifiLink
from iglite.netwatch import Connection, NetWatch, Snapshot

# -- Windows fixtures (shapes as PowerShell 5.1 / netsh print them) ------------------------

PS = {
    "adapters": [
        {
            "Name": "Wi-Fi",
            "InterfaceDescription": "Intel(R) Wi-Fi 6 AX201 160MHz",
            "InterfaceIndex": 12,
            "MacAddress": "AA-BB-CC-00-11-22",
            "Status": "Up",
            "MediaType": "Native 802.11",
            "PhysicalMediaType": "Native 802.11",
        },
        {
            "Name": "Ethernet",
            "InterfaceDescription": "Realtek PCIe GbE Family Controller",
            "InterfaceIndex": 7,
            "MacAddress": "AA-BB-CC-00-11-33",
            "Status": "Disconnected",
            "MediaType": "802.3",
            "PhysicalMediaType": "802.3",
        },
        {
            "Name": "Local Area Connection* 10",
            "InterfaceDescription": "Microsoft Wi-Fi Direct Virtual Adapter #2",
            "InterfaceIndex": 20,
            "MacAddress": "AE-BB-CC-00-11-22",
            "Status": "Up",
            "MediaType": "Native 802.11",
            "PhysicalMediaType": "Native 802.11",
        },
        {
            "Name": "vEthernet (WSL)",
            "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter",
            "InterfaceIndex": 30,
            "MacAddress": "00-15-5D-00-00-01",
            "Status": "Up",
            "MediaType": "802.3",
            "PhysicalMediaType": "Unspecified",
        },
    ],
    "addresses": [
        {"InterfaceIndex": 12, "IPAddress": "192.168.1.23", "PrefixLength": 24},
        {"InterfaceIndex": 12, "IPAddress": "fe80::1c2d:3e4f:5a6b:7c8d%12", "PrefixLength": 64},
        {"InterfaceIndex": 20, "IPAddress": "192.168.137.1", "PrefixLength": 24},
        {"InterfaceIndex": 30, "IPAddress": "172.20.0.1", "PrefixLength": 20},
        {"InterfaceIndex": 1, "IPAddress": "127.0.0.1", "PrefixLength": 8},
    ],
    "routes": {"InterfaceIndex": 12, "NextHop": "192.168.1.1", "RouteMetric": 0},  # single object, not a list
    "dns": [
        {"InterfaceIndex": 12, "ServerAddresses": ["192.168.1.1", "8.8.8.8"]},
        {"InterfaceIndex": 7, "ServerAddresses": []},
    ],
    "profiles": [{"InterfaceIndex": 12, "Name": "CafeFreeWiFi", "NetworkCategory": "Private"}],
    "firewall": [
        {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Public", "Enabled": "True", "DefaultInboundAction": "Block"},
    ],
    "neighbors": [
        {
            "InterfaceIndex": 12,
            "IPAddress": "192.168.1.1",
            "LinkLayerAddress": "10-20-30-40-50-60",
            "State": "Reachable",
        },
        {
            "InterfaceIndex": 12,
            "IPAddress": "192.168.1.57",
            "LinkLayerAddress": "3A-11-22-33-44-55",
            "State": "Stale",
        },
        {
            "InterfaceIndex": 12,
            "IPAddress": "224.0.0.251",
            "LinkLayerAddress": "01-00-5E-00-00-FB",
            "State": "Reachable",
        },
        {
            "InterfaceIndex": 12,
            "IPAddress": "192.168.1.255",
            "LinkLayerAddress": "FF-FF-FF-FF-FF-FF",
            "State": "Reachable",
        },
        {
            "InterfaceIndex": 20,
            "IPAddress": "192.168.137.44",
            "LinkLayerAddress": "5E-AA-BB-CC-DD-EE",
            "State": "Reachable",
        },
    ],
    "tcp": [
        {"LocalAddress": "0.0.0.0", "LocalPort": 445, "OwningProcess": 4},
        {"LocalAddress": "::", "LocalPort": 445, "OwningProcess": 4},
        {"LocalAddress": "0.0.0.0", "LocalPort": 3389, "OwningProcess": 1100},
        {"LocalAddress": "192.168.1.23", "LocalPort": 139, "OwningProcess": 4},
        {"LocalAddress": "127.0.0.1", "LocalPort": 11434, "OwningProcess": 5000},
        {"LocalAddress": "0.0.0.0", "LocalPort": 49664, "OwningProcess": 900},
        {"LocalAddress": "172.20.0.1", "LocalPort": 8000, "OwningProcess": 6000},
    ],
    "udp": [
        {"LocalAddress": "0.0.0.0", "LocalPort": 5355, "OwningProcess": 1500},
        {"LocalAddress": "0.0.0.0", "LocalPort": 61234, "OwningProcess": 1500},
    ],
    "services": [
        {"Name": "TermService", "DisplayName": "Remote Desktop Services", "ProcessId": 1100},
        {"Name": "Dnscache", "DisplayName": "DNS Client", "ProcessId": 1500},
    ],
    "processes": [
        {"Id": 4, "ProcessName": "System"},
        {"Id": 1100, "ProcessName": "svchost"},
        {"Id": 1500, "ProcessName": "svchost"},
        {"Id": 5000, "ProcessName": "ollama"},
        {"Id": 900, "ProcessName": "lsass"},
        {"Id": 6000, "ProcessName": "python"},
    ],
}

NETSH_IF = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 1b2c3d4e-0000-0000-0000-000000000000
    Physical address       : aa:bb:cc:00:11:22
    Interface type         : Primary
    State                  : connected
    SSID                   : CafeFreeWiFi
    AP BSSID               : 10:20:30:40:50:60
    Band                   : 2.4 GHz
    Channel                : 6
    Network type           : Infrastructure
    Radio type             : 802.11n
    Authentication         : Open
    Cipher                 : None
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 144.4
    Signal                 : 81%
    Profile                : CafeFreeWiFi

    Hosted network status  : Not available
"""

NETSH_NETS = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : CafeFreeWiFi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 10:20:30:40:50:60
         Signal             : 81%
         Radio type         : 802.11n
         Channel            : 6

SSID 2 : CafeFreeWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 66:77:88:99:aa:bb
         Signal             : 64%
         Channel            : 11

SSID 3 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : 0a:0b:0c:0d:0e:0f
         Signal             : 30%
         Channel            : 36
"""


@pytest.fixture
def win():
    return localnet.parse_windows(PS, NETSH_IF, NETSH_NETS)


# -- parsing ------------------------------------------------------------------------------


def test_windows_inventory(win):
    kinds = {a.name: a.kind for a in win.adapters}
    assert kinds == {
        "Wi-Fi": "wifi",
        "Ethernet": "ethernet",
        "Local Area Connection* 10": "hotspot",
        "vEthernet (WSL)": "virtual",
    }
    wifi = win.adapter("Wi-Fi")
    assert wifi.addresses == ["192.168.1.23/24", "fe80::1c2d:3e4f:5a6b:7c8d/64"]
    assert wifi.gateways == ["192.168.1.1"] and wifi.dns == ["192.168.1.1", "8.8.8.8"]
    assert (wifi.profile, wifi.network, wifi.mac) == ("Private", "CafeFreeWiFi", "aa:bb:cc:00:11:22")
    assert not win.adapter("Ethernet").up
    assert win.firewall["Private"] == {
        "enabled": True,
        "inbound": "Block",
    }  # NotConfigured = Windows' default


def test_netsh_parsing(win):
    (link,) = win.wifi
    assert (link.ssid, link.bssid, link.auth, link.cipher, link.signal, link.channel) == (
        "CafeFreeWiFi",
        "10:20:30:40:50:60",
        "Open",
        "None",
        81,
        "6",
    )
    assert [(n.ssid, n.auth, n.bssids[0]["signal"]) for n in win.nearby] == [
        ("CafeFreeWiFi", "Open", 81),
        ("CafeFreeWiFi", "WPA2-Personal", 64),
        ("HomeNet", "WPA3-Personal", 30),
    ]


def test_devices_skip_multicast_and_broadcast(win):
    assert [(d.ip, d.adapter) for d in win.devices] == [
        ("192.168.1.1", "Wi-Fi"),
        ("192.168.1.57", "Wi-Fi"),
        ("192.168.137.44", "Local Area Connection* 10"),
    ]
    assert localnet.randomized_mac("3a:11:22:33:44:55") and not localnet.randomized_mac("10:20:30:40:50:60")


def test_location_permission_message():
    net = localnet.parse_windows({}, "", "The wlan service requires location permission to list networks.")
    assert net.nearby == [] and "Location" in net.errors[0]


# -- exposure -------------------------------------------------------------------------------


def test_exposure_map(win):
    exp = localnet.exposure(win)
    by = {a["name"]: a for a in exp["adapters"]}
    wifi_ports = [(i["port"], i["label"], i["risk"]) for i in by["Wi-Fi"]["listeners"]]
    # SMB (v4+v6 folded), RDP with its service name, NetBIOS bound to the Wi-Fi address, LLMNR, RPC dynamic port
    assert wifi_ports == [
        (445, "SMB file sharing", "high"),
        (3389, "Remote Desktop", "high"),
        (139, "NetBIOS session", "medium"),
        (5355, "LLMNR", "medium"),
        (49664, "Windows RPC dynamic port", "low"),
    ]
    rdp = next(i for i in by["Wi-Fi"]["listeners"] if i["port"] == 3389)
    assert rdp["services"] == ["Remote Desktop Services"] and rdp["process"] == "svchost.exe"
    smb = next(i for i in by["Wi-Fi"]["listeners"] if i["port"] == 445)
    assert smb["bound"] == ["0.0.0.0", "::"]
    # The hotspot you share: everything bound to all addresses, but not 139 (bound to the Wi-Fi IP)
    assert 139 not in [i["port"] for i in by["Local Area Connection* 10"]["listeners"]]
    assert 445 in [i["port"] for i in by["Local Area Connection* 10"]["listeners"]]
    # The dev server bound to the WSL switch only shows there
    assert [i["port"] for i in by["vEthernet (WSL)"]["listeners"] if i["port"] == 8000] == [8000]
    assert "Ethernet" not in by  # disconnected
    assert [(i["port"], i["process"]) for i in exp["local_only"]] == [(11434, "ollama.exe")]
    assert 61234 not in [i["port"] for a in exp["adapters"] for i in a["listeners"]]  # ephemeral UDP


def test_public_profile_with_firewall_lowers_risk(win):
    win.adapter("Wi-Fi").profile = "Public"
    rdp = next(i for i in localnet.exposure(win)["adapters"][0]["listeners"] if i["port"] == 3389)
    assert (rdp["risk"], rdp["raw_risk"]) == ("medium", "high")


# -- findings ------------------------------------------------------------------------------


def titles(findings):
    return [(f["severity"], f["title"]) for f in findings]


def test_wifi_findings(win):
    found = titles(localnet.findings(win))
    assert ("high", '"CafeFreeWiFi" has no password') in found
    assert ("high", 'Possible evil twin of "CafeFreeWiFi"') in found
    assert ("medium", 'Windows trusts "CafeFreeWiFi" as a Private network') in found
    assert ("high", "2 risky service(s) reachable on CafeFreeWiFi") in found
    assert ("info", "You are sharing a Mobile hotspot (1 device(s) connected)") in found
    assert found[0][0] == "high" and found[-1][0] == "info"  # worst first


def test_firewall_off_and_weak_security():
    net = LocalNetwork(
        "windows",
        adapters=[Adapter("Wi-Fi", kind="wifi", addresses=["10.0.0.5/24"], profile="Public", network="Lab")],
        wifi=[WifiLink("Wi-Fi", "connected", "Lab", auth="WPA-Personal", cipher="TKIP")],
        firewall={"Public": {"enabled": False, "inbound": "Block"}},
    )
    found = titles(localnet.findings(net))
    assert ("high", 'Windows Firewall is off for the Public profile ("Lab")') in found
    assert ("medium", '"Lab" uses outdated Wi-Fi security (WPA-Personal, TKIP)') in found


def test_changes_between_scans(win, make_engine):
    engine = make_engine()
    localnet.report(win, engine.store)  # first scan: remembered
    again = localnet.parse_windows(json.loads(json.dumps(PS)), NETSH_IF, NETSH_NETS)
    again.devices[0].mac = "de:ad:be:ef:00:01"  # the router's MAC changed
    again.adapter("Wi-Fi").dns = ["203.0.113.53"]
    from iglite.localnet import Device

    again.devices.append(Device("192.168.1.99", "12:34:56:78:9a:bc", "Wi-Fi"))
    found = titles(localnet.report(again, engine.store)["findings"])
    assert ("high", 'The router\'s hardware address changed on "CafeFreeWiFi"') in found
    assert ("medium", 'DNS servers changed on "CafeFreeWiFi"') in found
    assert any(t.startswith("2 new device(s)") or t.startswith("1 new device(s)") for _, t in found)


def test_nothing_to_report_on_a_safe_network():
    net = LocalNetwork(
        "windows",
        adapters=[Adapter("Wi-Fi", kind="wifi", addresses=["10.0.0.5/24"], profile="Public", network="Home")],
        wifi=[WifiLink("Wi-Fi", "connected", "Home", auth="WPA3-Personal", cipher="CCMP")],
        nearby=[NearbyNetwork("Home", "WPA3-Personal", "CCMP")],
        listeners=[Listener("tcp", "127.0.0.1", 8765, 1, "python.exe")],
        firewall={"Public": {"enabled": True, "inbound": "Block"}},
    )
    assert localnet.findings(net) == []


# -- Linux ---------------------------------------------------------------------------------


def test_linux_parsers():
    route = "Iface\tDestination\tGateway\tFlags\nwlan0\t00000000\t0101A8C0\t0003\nwlan0\t0001A8C0\t00000000\t0001\n"
    assert localnet.parse_proc_route(route) == {"wlan0": ["192.168.1.1"]}
    arp = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.1      0x1         0x2         10:20:30:40:50:60     *        wlan0\n"
        "192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
    )
    assert [(d.ip, d.adapter) for d in localnet.parse_proc_arp(arp)] == [("192.168.1.1", "wlan0")]
    links, nearby = localnet.parse_nmcli(
        "*:Cafe:10\\:20\\:30\\:40\\:50\\:60::81:6:wlan0\n :Home:0A\\:0B\\:0C\\:0D\\:0E\\:0F:WPA2:30:36:wlan0\n"
    )
    assert (links[0].ssid, links[0].auth, links[0].bssid) == ("Cafe", "Open", "10:20:30:40:50:60")
    assert {(n.ssid, n.auth) for n in nearby} == {("Cafe", "Open"), ("Home", "WPA2")}


def test_real_collection_on_this_machine():
    net = localnet.collect()
    assert net.adapters and isinstance(localnet.report(net), dict)


# -- Wi-Fi-only monitoring ----------------------------------------------------------------------


def test_wifi_only_scope(make_engine, lists, monkeypatch, win):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    monkeypatch.setattr(
        "iglite.netwatch.is_public", lambda ind: not ind.value.startswith(("192.168.", "10."))
    )
    conns = [
        Connection("tcp", "192.168.1.23:50000", "203.0.113.66", 443, "ESTABLISHED", 7, "chrome.exe"),  # Wi-Fi
        Connection("tcp", "10.8.0.2:50001", "45.155.205.20", 443, "ESTABLISHED", 8, "vpnapp.exe"),  # VPN
        Connection(
            "tcp", "[fe80::1c2d:3e4f:5a6b:7c8d%12]:50002", "45.155.205.21", 443, "ESTABLISHED", 9, "x.exe"
        ),
    ]
    watch = NetWatch(engine, collector=lambda: Snapshot(list(conns)))
    watch.adapter_collector = lambda: win
    watch.scan()
    assert {r["remote_ip"] for r in watch.rows} == {"203.0.113.66", "45.155.205.20", "45.155.205.21"}

    watch.set_scope("wifi")
    watch.scan()
    assert {r["remote_ip"] for r in watch.rows} == {"203.0.113.66", "45.155.205.21"}  # VPN traffic left out
    status = watch.status()
    assert status["scope"] == "wifi" and "192.168.137.1" in status["scope_addresses"]  # hotspot counts too
    with pytest.raises(ValueError):
        watch.set_scope("bluetooth")


def test_scope_from_settings():
    from iglite import config

    assert config.load(env={"IGLITE_WATCH_SCOPE": "WiFi"}).watch_scope == "wifi"


# -- API and CLI -------------------------------------------------------------------------------


def test_localnet_api_and_scope_switch(make_engine, win):
    engine = make_engine()
    engine.localnet_collector = lambda: win
    engine.watcher().adapter_collector = lambda: win
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
        status, rep = call("/api/localnet?refresh=1")
        assert status == 200 and rep["wifi"][0]["ssid"] == "CafeFreeWiFi"
        assert rep["exposure"]["adapters"][0]["name"] == "Wi-Fi" and rep["findings"][0]["severity"] == "high"
        assert call("/api/watch", {"scope": "wifi"})[1]["scope"] == "wifi"
        assert engine.config.watch_scope == "wifi"
        assert call("/api/watch", {"scope": "everything"})[0] == 400
        assert call("/api/watch", {"scope": "all"})[1]["scope"] == "all"
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_wifi_and_exposure(make_engine, win, capsys, monkeypatch):
    engine = make_engine()
    engine.localnet_collector = lambda: win
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    assert main(["wifi"]) == 0
    out = capsys.readouterr().out
    assert "Wi-Fi: CafeFreeWiFi on Wi-Fi  [Open / None, signal 81%]" in out
    assert "Possible evil twin" in out and "192.168.1.1" in out and "router" in out and "HomeNet" in out
    assert main(["exposure"]) == 0
    out = capsys.readouterr().out
    assert "Wi-Fi: CafeFreeWiFi" in out and "SMB file sharing" in out and "Remote Desktop Services" in out
    assert "Mobile hotspot (you share)" in out
