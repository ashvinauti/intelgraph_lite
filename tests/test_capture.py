"""Windows Mobile hotspot: a tshark capture of the hotspot adapter (192.168.137.0/24)."""

import stat
import sys
import threading
import time

import pytest

from iglite.config import Config
from iglite.gateway import (
    CAPTURE_FIELDS,
    CaptureSource,
    DnsEvent,
    Flow,
    GatewayCollector,
    Lease,
    parse_capture_line,
    resolve_interface,
)


def line(**values):
    """A tshark -T fields line with CAPTURE_FIELDS in order, tab separated."""
    return "\t".join(values.get(f.replace(".", "_"), "") for f in CAPTURE_FIELDS) + "\n"


SYN = line(
    frame_time_epoch="1762000000.1",
    ip_src="192.168.137.23",
    ip_dst="142.250.180.14",
    tcp_srcport="51000",
    tcp_dstport="443",
)
QUIC = line(ip_src="192.168.137.23", ip_dst="157.240.1.35", udp_srcport="60000", udp_dstport="443")
QUERY = line(
    ip_src="192.168.137.23",
    ip_dst="192.168.137.1",
    udp_srcport="5353",
    udp_dstport="53",
    dns_flags_response="False",
    dns_qry_name="chat.example.com",
)
ANSWER = line(
    ip_src="192.168.137.1",
    ip_dst="192.168.137.23",
    udp_srcport="53",
    udp_dstport="5353",
    dns_flags_response="True",
    dns_qry_name="chat.example.com",
    dns_a="203.0.113.7,203.0.113.8",
)
DHCP = line(
    ip_src="0.0.0.0",
    ip_dst="255.255.255.255",
    udp_srcport="68",
    udp_dstport="67",
    dhcp_option_hostname="Pixel-7",
    dhcp_option_requested_ip_address="192.168.137.23",
)
INBOUND = line(ip_src="45.155.205.20", ip_dst="192.168.137.23", tcp_srcport="40000", tcp_dstport="22")
V6 = line(ipv6_src="2a02:c7c:1::5", ipv6_dst="2606:4700::1111", tcp_srcport="50000", tcp_dstport="443")


def test_capture_lines_become_events():
    assert parse_capture_line(SYN) == [Flow("192.168.137.23", "142.250.180.14", 51000, 443, "tcp", "pass")]
    assert parse_capture_line(QUIC) == [Flow("192.168.137.23", "157.240.1.35", 60000, 443, "udp", "pass")]
    assert parse_capture_line(QUERY) == [DnsEvent("192.168.137.23", "chat.example.com")]
    assert parse_capture_line(ANSWER) == [DnsEvent(None, "chat.example.com", ("203.0.113.7", "203.0.113.8"))]
    assert parse_capture_line(DHCP) == [Lease("192.168.137.23", "Pixel-7")]
    assert parse_capture_line(V6)[0].dst == "2606:4700::1111"
    assert parse_capture_line(QUERY.replace("False", "0")) == parse_capture_line(QUERY)  # older tshark: 0/1
    assert parse_capture_line("garbage\n") == [] and parse_capture_line("\t" * 20) == []


def test_only_hotspot_clients_count_as_devices():
    gw = GatewayCollector(Config(lan_networks=["192.168.137.0/24"]))
    gw.started = True
    gw.lan.own = {"192.168.137.1", "192.168.1.20"}  # the Windows PC on both networks
    pc_own = line(ip_src="192.168.1.20", ip_dst="142.250.1.1", tcp_srcport="50001", tcp_dstport="443")
    for text in (DHCP, QUERY, ANSWER, SYN, INBOUND, pc_own):
        for event in parse_capture_line(text):
            gw.add(event)
    snap = gw.collect()
    flows = {(c.device, c.remote_ip, c.remote_port, c.inbound) for c in snap.connections}
    assert flows == {
        ("192.168.137.23", "142.250.180.14", 443, False),
        ("192.168.137.23", "45.155.205.20", 22, True),
    }
    assert snap.devices == {"192.168.137.23": "Pixel-7"}
    assert snap.queries == {"chat.example.com": ["192.168.137.23"]}
    assert (
        "capture Local Area Connection* 10"
        in GatewayCollector(Config(gateway_capture="Local Area Connection* 10")).inputs
    )


LISTING = r"""1. \Device\NPF_{11111111-2222-3333-4444-555555555555} (Ethernet)
2. \Device\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} (Local Area Connection* 10)
3. \Device\NPF_Loopback (Adapter for loopback traffic capture)
4. etwdump (Event Tracing for Windows (ETW) reader)
"""


def test_interface_by_friendly_name_number_or_device():
    assert resolve_interface(LISTING, "Local Area Connection* 10") == "2"
    assert resolve_interface(LISTING, "local area connection* 10") == "2"
    assert resolve_interface(LISTING, "1") == "1"
    assert resolve_interface(LISTING, r"\Device\NPF_Loopback") == "3"
    assert resolve_interface(LISTING, "wlan0") == "wlan0"  # not listed: passed through


@pytest.mark.skipif(sys.platform == "win32", reason="the fake tshark is a shebang script")
def test_capture_streams_from_tshark(tmp_path):
    fake = tmp_path / "tshark"
    out = tmp_path / "argv.txt"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import sys, time\n"
        "if sys.argv[1:] == ['-D']:\n"
        f"    print({LISTING!r}); sys.exit(0)\n"
        f"open({str(out)!r}, 'w').write(repr(sys.argv[1:]))\n"
        f"sys.stdout.write({(DHCP + SYN + QUERY + ANSWER)!r}); sys.stdout.flush()\n"
        "time.sleep(30)\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    events, errors, stop = [], [], threading.Event()
    src = CaptureSource("Local Area Connection* 10", str(fake))
    t = threading.Thread(target=src.follow, args=(events.extend, stop, errors.append), daemon=True)
    t.start()
    deadline = time.time() + 10
    while time.time() < deadline and len(events) < 4:
        time.sleep(0.05)
    stop.set()
    t.join(5)
    assert [type(e).__name__ for e in events] == ["Lease", "Flow", "DnsEvent", "DnsEvent"]
    argv = eval(out.read_text())  # noqa: S307 - our own fake's record
    assert argv[:2] == ["-i", "2"] and "-Y" in argv and argv[argv.index("-E") + 1] == "separator=/t"
    assert not errors


def test_missing_tshark_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    src = CaptureSource("Local Area Connection* 10", str(tmp_path / "nope.exe"))
    errors = []
    src.follow(lambda e: None, threading.Event(), errors.append)
    assert len(errors) == 1 and "nope.exe" in errors[0] and "install Wireshark" in errors[0]
