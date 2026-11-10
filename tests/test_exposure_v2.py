"""Firewall-rule verdicts, one-click fixes, change events and device identification."""

import json
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace as NS

import pytest

from iglite import fixes, localnet, oui
from iglite.api import make_server
from iglite.cli import main
from iglite.localnet import LocalNetwork
from test_localnet import NETSH_IF, NETSH_NETS, PS

RULES = [  # Get-NetFirewallRule output as PS_RULES prints it (one rule is a bare object in some shells)
    {
        "name": "File and Printer Sharing (SMB-In)",
        "group": "@FirewallAPI.dll,-28502",
        "action": "Allow",
        "profile": "Private",
        "protocol": "TCP",
        "ports": ["445"],
        "program": "System",
        "service": "Any",
    },
    {
        "name": "Remote Desktop - User Mode (TCP-In)",
        "group": "@FirewallAPI.dll,-28752",
        "action": "Allow",
        "profile": "Any",
        "protocol": "TCP",
        "ports": ["3389"],
        "program": "%SystemRoot%\\system32\\svchost.exe",
        "service": "TermService",
    },
    {
        "name": "Core Networking - LLMNR (UDP-In)",
        "group": "",
        "action": "Allow",
        "profile": "Domain, Private",
        "protocol": "UDP",
        "ports": ["5355"],
        "program": "Any",
        "service": "Any",
    },
    {
        "name": "RPC Dynamic Ports",
        "group": "",
        "action": "Allow",
        "profile": "Private",
        "protocol": "6",
        "ports": "RPC",
        "program": "Any",
        "service": "Any",
    },
]


def windows(profile="Private", rules=RULES):
    data = json.loads(json.dumps(PS))
    data["profiles"][0]["NetworkCategory"] = profile
    data["services"].append({"Name": "LanmanServer", "DisplayName": "Server", "ProcessId": 4})
    net = localnet.parse_windows(data, NETSH_IF, NETSH_NETS)
    net.rules = localnet.parse_rules(rules)
    return net


def wifi_items(net):
    return {i["port"]: i for i in localnet.exposure(net)["adapters"][0]["listeners"]}


# -- firewall rules ------------------------------------------------------------------------------


def test_rule_parsing_handles_powershell_shapes():
    (rule,) = localnet.parse_rules(RULES[3])  # a single rule arrives as an object, ports as a string
    assert rule.ports == ["RPC"] and rule.profiles == {"Private"} and rule.protocol == "6"
    assert localnet.parse_rules(RULES[2])[0].profiles == {"Domain", "Private"}


def test_verdicts_on_a_private_network():
    items = wifi_items(windows("Private"))
    assert (items[445]["firewall"], items[445]["rule"]) == ("allowed", "File and Printer Sharing (SMB-In)")
    assert (items[3389]["firewall"], items[3389]["rule"]) == (
        "allowed",
        "Remote Desktop - User Mode (TCP-In)",
    )
    assert items[5355]["firewall"] == "allowed"
    assert items[49664]["firewall"] == "allowed"  # "RPC" keyword covers the dynamic range
    assert (items[139]["firewall"], items[139]["reachable"]) == ("blocked", False)  # no rule allows NetBIOS


def test_verdicts_on_a_public_network_and_block_rules():
    net = windows(
        "Public",
        RULES
        + [
            {
                "name": "IntelGraph Lite: block TCP 3389 (Public)",
                "action": "Block",
                "profile": "Public",
                "protocol": "TCP",
                "ports": ["3389"],
            }
        ],
    )
    items = wifi_items(net)
    assert (items[445]["firewall"], items[445]["reachable"], items[445]["risk"]) == ("blocked", False, "low")
    assert items[445]["rule"].startswith("no rule allows it")
    assert (items[3389]["firewall"], items[3389]["rule"]) == (
        "blocked",
        "IntelGraph Lite: block TCP 3389 (Public)",
    )
    counts = localnet.exposure(net)["adapters"][0]["counts"]
    assert counts["high"] == 0 and counts["blocked"] >= 3
    exposed = [f for f in localnet.findings(net) if f["kind"] == "exposed"]
    assert all(f["adapter"] != "Wi-Fi" for f in exposed)  # nothing reachable on the Wi-Fi itself


def test_service_and_program_filters():
    net = windows("Private", [dict(RULES[1], service="WinRM")])  # an RDP rule for another service
    assert wifi_items(net)[3389]["firewall"] == "blocked"
    net = windows("Private", [dict(RULES[1], program="C:\\Tools\\other.exe", service="Any")])
    assert wifi_items(net)[3389]["firewall"] == "blocked"


def test_port_specs():
    assert localnet._port_matches("135-139", 137, "udp") and not localnet._port_matches("135-139", 140, "tcp")
    assert localnet._port_matches("RPCEPMap", 135, "tcp") and localnet._port_matches("Any", 1, "udp")
    assert not localnet._port_matches("RPC", 50000, "udp")


def test_firewall_off_and_allow_all():
    net = windows("Private")
    net.firewall["Private"]["enabled"] = False
    assert {i["firewall"] for i in wifi_items(net).values()} == {"off"}
    net.firewall["Private"] = {"enabled": True, "inbound": "Allow"}
    assert {i["firewall"] for i in wifi_items(net).values()} == {"allowed"}


def test_exposed_finding_names_the_allowing_rule():
    exposed = next(f for f in localnet.findings(windows("Private")) if f["kind"] == "exposed")
    assert "File and Printer Sharing (SMB-In)" in exposed["detail"] and exposed["id"].startswith(
        "exposed:CafeFreeWiFi:"
    )
    assert {s["port"] for s in exposed["params"]["services"]} == {445, 3389}


# -- vendors and device names -----------------------------------------------------------------

MANUF = (
    "# Wireshark manuf\n00:00:0C\tCisco\tCisco Systems, Inc\nB8:27:EB\tRaspberr\tRaspberry Pi Foundation\n"
    "70:B3:D5:00:00:00/36\tAcme\tAcme Small Block\nAA:BB:CC\tIntelCor\tIntel Corporate\n"
)
OUI_TXT = "OUI/MA-L\n\n00-1A-11   (hex)\t\tGoogle, Inc.\n001A11     (base 16)\t\tGoogle, Inc.\n"
OUI_CSV = (
    'Registry,Assignment,Organization Name,Organization Address\nMA-L,F0D5BF,"Apple, Inc.",addr\n'
    "MA-M,70B3D51,Mid Block Ltd,addr\n"
)


def test_vendor_parsers_and_lookup(tmp_path):
    assert (
        oui.parse(MANUF)["B827EB"] == "Raspberry Pi Foundation"
        and oui.parse(MANUF)["70B3D5000"] == "Acme Small Block"
    )
    assert oui.parse(OUI_TXT) == {"001A11": "Google, Inc."}
    assert oui.parse(OUI_CSV) == {"F0D5BF": "Apple, Inc.", "70B3D51": "Mid Block Ltd"}
    f = tmp_path / "manuf.txt"
    f.write_text(MANUF)
    v = oui.Vendors(f, extra=[])
    assert v.lookup("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"
    assert v.lookup("70-B3-D5-00-01-02") == "Acme Small Block"  # longest prefix wins
    assert v.lookup("3a:11:22:33:44:55") is None  # random private address
    assert oui.Vendors(tmp_path / "missing", extra=[f]).lookup("00:00:0c:00:00:01") == "Cisco Systems, Inc"


def test_vendor_update(tmp_path):
    big = "Registry,Assignment,Organization Name,Organization Address\n" + "".join(
        f"MA-L,{i:06X},Vendor {i},x\n" for i in range(1500)
    )
    calls = []

    def fetch(url):
        calls.append(url)
        if "wireshark" in url:
            raise OSError("blocked")
        return big

    result = oui.update(tmp_path / "manuf.txt", fetch=fetch)
    assert result["entries"] == 1500 and "ieee" in result["source"] and len(calls) == 2
    assert oui.Vendors(tmp_path / "manuf.txt", extra=[]).lookup("00:00:2a:00:00:00") == "Vendor 42"
    with pytest.raises(RuntimeError, match="only 1 entries"):
        oui.update(tmp_path / "x.txt", fetch=lambda url: "00:00:0C\tCisco\n")


def test_type_guess_and_hostnames():
    assert oui.guess_type("Raspberry Pi Foundation", None, False) == "single-board computer"
    assert oui.guess_type(None, "Annas-iPhone.lan", True) == "phone"
    assert oui.guess_type(None, None, True) == "phone or laptop (private address)"
    assert oui.guess_type("Anything", None, False, router=True) == "router"
    names = oui.hostnames(
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        resolver=lambda ip: (
            {"10.0.0.1": "printer.lan.", "10.0.0.2": "10.0.0.2"}.get(ip) or (_ for _ in ()).throw(OSError())
        ),
    )
    assert names == {"10.0.0.1": "printer.lan"}


def test_devices_are_identified_remembered_and_trusted(make_engine):
    engine = make_engine()
    vendors = NS(lookup=lambda mac: "Intel Corporate" if mac.startswith("10:20") else None, source="test")
    rep = localnet.report(
        windows(), engine.store, vendors=vendors, resolver=lambda ip: {"192.168.1.57": "annas-phone.lan"}[ip]
    )
    by_ip = {d["ip"]: d for d in rep["devices"]}
    assert by_ip["192.168.1.1"]["vendor"] == "Intel Corporate" and by_ip["192.168.1.1"]["type"] == "router"
    assert by_ip["192.168.1.57"]["hostname"] == "annas-phone.lan" and by_ip["192.168.1.57"]["type"] == "phone"
    assert rep["vendor_list"] == "test"

    localnet.set_device(engine.store, "12:34:56:78:9A:BC", name="Office printer", trusted=True)
    later = windows()
    later.devices.append(localnet.Device("192.168.1.99", "12:34:56:78:9a:bc", "Wi-Fi"))
    later.devices.append(localnet.Device("192.168.1.98", "02:00:00:00:00:98", "Wi-Fi"))
    rep2 = localnet.report(
        later, engine.store, vendors=vendors, resolver=lambda ip: (_ for _ in ()).throw(OSError())
    )
    new = next(f for f in rep2["findings"] if f["kind"] == "new_devices")
    assert new["params"]["macs"] == ["02:00:00:00:00:98"]  # the trusted printer isn't news
    printer = next(d for d in rep2["devices"] if d["ip"] == "192.168.1.99")
    assert (printer["name"], printer["trusted"]) == ("Office printer", True)
    assert by_ip["192.168.1.57"]["first_seen"] <= printer["first_seen"]
    with pytest.raises(ValueError):
        localnet.set_device(engine.store, "not-a-mac")


# -- fixes ------------------------------------------------------------------------------------


def test_fix_validation():
    assert (
        fixes.build("block-port:tcp:445:Public")["undo"]
        == "remove-rule:IntelGraph Lite: block TCP 445 (Public)"
    )
    for bad in (
        "profile-public:12;x",
        "block-port:tcp:99999:Public",
        "block-port:icmp:1:Any",
        "stop-service:RpcSs",
        "stop-service:Dnscache",
        "remove-rule:Remote Desktop - User Mode (TCP-In)",
        "firewall-on:All",
        "stop-service:x';Remove-Item C:\\",
        "disable-llmnr:1",
    ):
        with pytest.raises(ValueError):
            fixes.build(bad)
    assert (
        fixes.stoppable("MSSQL$SQLEXPRESS")
        and fixes.stoppable("TermService")
        and not fixes.stoppable("WinDefend")
    )


def test_fixes_are_offered_for_findings_and_services():
    rep = fixes.attach(localnet.report(windows("Private"), identify=False))
    priv = next(f for f in rep["findings"] if f["kind"] == "private_profile")
    assert priv["fix_ids"] == ["profile-public:12"]
    rdp = wifi_items_from(rep)[3389]
    assert rdp["fix_ids"] == ["block-port:tcp:3389:Private", "stop-service:TermService"]
    smb = wifi_items_from(rep)[445]
    assert "stop-service:LanmanServer" in smb["fix_ids"]
    llmnr = wifi_items_from(rep)[5355]
    assert "disable-llmnr" in llmnr["fix_ids"] and "stop-service:Dnscache" not in llmnr["fix_ids"]
    assert set(rep["fixes"]) >= {"profile-public:12", "block-port:tcp:445:Private", "disable-llmnr"}
    linux = fixes.attach(localnet.report(LocalNetwork("linux"), identify=False))
    assert linux["fixes"] == {}


def wifi_items_from(rep):
    return {i["port"]: i for i in rep["exposure"]["adapters"][0]["listeners"]}


def test_apply_and_undo(make_engine):
    engine = make_engine()
    engine.localnet_collector = lambda: windows("Private")
    engine.localnet_vendors = NS(lookup=lambda mac: None, source=None)
    engine.localnet_resolver = lambda ip: (_ for _ in ()).throw(OSError())
    ran = []

    def runner(cmd):
        ran.append(cmd)
        return True, "OK"

    with pytest.raises(ValueError, match="isn't offered"):
        engine.apply_fix("block-port:tcp:9999:Private", runner)
    result = engine.apply_fix("block-port:tcp:3389:Private", runner)
    assert result["ok"] and "New-NetFirewallRule" in ran[0] and "-LocalPort 3389" in ran[0]
    history = engine.store.get_meta_json("localnet.fixes")
    assert history[0]["undo"] == "remove-rule:IntelGraph Lite: block TCP 3389 (Private)"
    engine.apply_fix(history[0]["undo"], runner)  # undo is accepted although no scan offers it
    assert engine.store.get_meta_json("localnet.fixes")[0]["undone"]
    declined = engine.apply_fix(
        "profile-public:12", lambda cmd: (False, "You declined the administrator prompt")
    )
    assert not declined["ok"] and len(engine.store.get_meta_json("localnet.fixes")) == 1


def test_run_elevated_is_windows_only():
    import sys

    if sys.platform != "win32":
        assert fixes.run_elevated("Get-Date") == (False, "fixes run on Windows only")


# -- change events ---------------------------------------------------------------------------


def test_events_are_raised_resolved_reopened_and_dismissed(make_engine):
    engine = make_engine()
    engine.localnet_vendors = NS(lookup=lambda mac: None, source=None)
    engine.localnet_resolver = lambda ip: (_ for _ in ()).throw(OSError())
    current = {"net": windows("Private")}
    engine.localnet_collector = lambda: current["net"]
    first = engine.localnet_check()
    kinds = {e["kind"] for e in first}
    assert {"open_wifi", "evil_twin", "private_profile", "exposed"} <= kinds
    assert engine.localnet_check() == []  # nothing new

    current["net"] = windows("Public")  # the user switched to Public: private-profile + exposure go away
    engine.localnet_check()
    statuses = {e["kind"]: e["status"] for e in engine.store.netevents()}
    assert statuses["private_profile"] == "resolved" and statuses["open_wifi"] == "open"

    current["net"] = windows("Private")  # ...and back: raised again
    again = engine.localnet_check()
    assert "private_profile" in {e["kind"] for e in again}

    twin = next(e for e in engine.store.netevents("open") if e["kind"] == "evil_twin")
    engine.store.dismiss_netevent(twin["id"])
    current["net"] = windows("Public")
    engine.localnet_check()
    current["net"] = windows("Private")
    assert "evil_twin" not in {e["kind"] for e in engine.localnet_check()}  # dismissed stays quiet


def test_event_notifications_respect_the_threshold(make_engine):
    from iglite.notify import Notifier

    engine = make_engine()
    engine.config.notify = {"webhook": "https://example.invalid/hook"}
    sent = []
    notifier = Notifier(
        engine.config, engine.store, senders={"webhook": lambda dest, msg, **kw: sent.append(msg)}
    )
    high = {"id": 1, "severity": "high", "title": "t", "detail": "d"}
    assert notifier.on_netevent(high) is True
    assert notifier.on_netevent({**high, "severity": "medium"}) is False
    engine.config.localnet_notify = "off"
    assert notifier.on_netevent(high) is False


# -- API and CLI ----------------------------------------------------------------------------


@pytest.fixture
def served(make_engine):
    engine = make_engine()
    engine.localnet_collector = lambda: windows("Private")
    engine.localnet_vendors = NS(lookup=lambda mac: None, source=None)
    engine.localnet_resolver = lambda ip: (_ for _ in ()).throw(OSError())
    srv = make_server(engine, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(path, body=None, origin=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} | ({"Origin": origin} if origin else {})
        req = urllib.request.Request(base + path, data=data, headers=headers)
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    yield engine, call, base
    srv.shutdown()
    srv.server_close()


def test_api(served):
    engine, call, base = served
    status, rep = call("/api/localnet?refresh=1")
    assert status == 200 and rep["rules_known"] and "profile-public:12" in rep["fixes"]
    assert call("/api/localnet/fix", {"fix": "nonsense"})[0] == 400
    status, result = call("/api/localnet/fix", {"fix": "profile-public:12"})
    assert status == 200 and result["ok"] is False  # no Windows here: refused, nothing changed
    engine.localnet_check()
    events = call("/api/localnet/events?status=open")[1]
    assert events and call("/api/localnet/events/dismiss", {"id": events[0]["id"]})[1] == {"ok": True}
    assert call("/api/localnet/events/dismiss", {"id": 999})[0] == 404
    status, dev = call(
        "/api/localnet/device", {"mac": "10-20-30-40-50-60", "name": "Router", "trusted": True}
    )
    assert status == 200 and dev["mac"] == "10:20:30:40:50:60" and dev["trusted"]
    assert call("/api/localnet/device", {"mac": "x"})[0] == 400


def test_cross_site_posts_are_refused(served):
    _, call, base = served
    assert call("/api/localnet/fix", {"fix": "profile-public:12"}, origin="https://evil.example")[0] == 403
    assert call("/api/localnet/device", {"mac": "10:20:30:40:50:60"}, origin=base)[0] == 200
    assert call("/api/localnet", origin="https://evil.example")[0] == 200  # reads aren't state changes


def test_cli(make_engine, capsys, monkeypatch):
    engine = make_engine()
    engine.localnet_collector = lambda: windows("Private")
    engine.localnet_vendors = NS(lookup=lambda mac: None, source=None)
    engine.localnet_resolver = lambda ip: (_ for _ in ()).throw(OSError())
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    ran = []
    monkeypatch.setattr("iglite.fixes.run_elevated", lambda cmd: (ran.append(cmd), (True, "OK"))[1])

    assert main(["exposure"]) == 0
    out = capsys.readouterr().out
    assert "ALLOWED (File and Printer Sharing (SMB-In))" in out and "fixes: block-port:tcp:445:Private" in out
    assert main(["fix"]) == 0
    assert "profile-public:12" in capsys.readouterr().out
    assert main(["fix", "profile-public:12", "--yes"]) == 0
    out = capsys.readouterr().out
    assert (
        "Done." in out
        and "Undo with: iglite fix profile-private:12" in out
        and "Set-NetConnectionProfile" in ran[0]
    )
    assert main(["wifi", "--trust", "10:20:30:40:50:60", "--name", "Router"]) == 0
    assert "trusted, named Router" in capsys.readouterr().out
    engine.localnet_check()
    assert main(["wifi", "--events"]) == 0
    assert "Possible evil twin" in capsys.readouterr().out
