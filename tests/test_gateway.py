import json
import socket
import struct
import threading
import time
import urllib.error
import urllib.request

import pytest

from iglite import attack, export
from iglite.api import make_server
from iglite.config import Config
from iglite.extract import classify
from iglite.gateway import (
    DnsEvent,
    Flow,
    GatewayCollector,
    Lan,
    Lease,
    LineParser,
    NetFlowParser,
    parse_conntrack,
    parse_leases,
    parse_text,
)
from iglite.netwatch import GATEWAY, NetWatch

LAN, BAD, BAD2 = "192.168.1.23", "45.155.205.20", "45.155.205.30"


def flow(events):
    assert len(events) == 1 and isinstance(events[0], Flow), events
    f = events[0]
    return f.src, f.dst, f.sport, f.dport, f.proto, f.action


# -- syslog formats --------------------------------------------------------------


def test_netfilter_ufw_and_openwrt_lines():
    line = (
        "Oct 14 10:00:00 OpenWrt kernel: [12345.6] ACCEPT(fwd) IN=br-lan OUT=eth0 MAC=aa:bb SRC=192.168.1.23 "
        "DST=45.155.205.20 LEN=60 TOS=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=50000 DPT=443 WINDOW=64240 SYN URGP=0"
    )
    assert flow(parse_text(line)) == (LAN, BAD, 50000, 443, "tcp", "accept")
    ufw = "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.20 DST=192.168.1.10 PROTO=TCP SPT=4444 DPT=22"
    assert flow(parse_text(ufw))[5] == "block"


def test_pfsense_opnsense_filterlog_v4_and_v6():
    v4 = (
        "<134>Oct 14 10:00:00 fw filterlog[1234]: 5,,,1000000103,igb1,match,pass,out,4,0x0,,64,0,0,DF,6,tcp,60,"
        "192.168.1.23,45.155.205.20,50000,443,0,S,1,,64240,,mss"
    )
    assert flow(parse_text(v4)) == (LAN, BAD, 50000, 443, "tcp", "pass")
    v6 = (
        "filterlog[1]: 9,,,1000000003,igb1,match,block,in,6,0x00,0x00000,64,udp,17,40,"
        "2a00:1450:4001:80b::200e,fd00::23,443,53000,40"
    )
    assert flow(parse_text(v6)) == ("2a00:1450:4001:80b::200e", "fd00::23", 443, 53000, "udp", "block")


def test_key_value_firewalls():
    forti = (
        'date=2026-10-14 time=10:00:00 devname="FGT60F" type="traffic" subtype="forward" srcip=10.0.0.5 '
        'srcport=51000 srcintf="internal" dstip=45.155.205.20 dstport=8443 proto=6 action="accept" service="HTTPS"'
    )
    assert flow(parse_text(forti)) == ("10.0.0.5", BAD, 51000, 8443, "tcp", "accept")
    sonicwall = 'id=firewall sn=0017C5 m=537 msg="Connection Closed" src=192.168.1.23:50000:X0 dst=45.155.205.20:443:X1 proto=tcp/https'
    assert flow(parse_text(sonicwall)) == (LAN, BAD, 50000, 443, "tcp", "")
    sophos = 'log_type="Firewall" src_ip="192.168.1.23" src_port="5000" dst_ip="45.155.205.20" dst_port="80" protocol="TCP" status="Allow"'
    assert flow(parse_text(sophos)) == (LAN, BAD, 5000, 80, "tcp", "allow")


def test_cisco_asa_juniper_mikrotik_paloalto():
    asa = (
        "%ASA-6-302013: Built outbound TCP connection 123456 for outside:45.155.205.20/443 (45.155.205.20/443) "
        "to inside:192.168.1.23/50000 (198.51.100.1/50000)"
    )
    assert flow(parse_text(asa)) == (LAN, BAD, 50000, 443, "tcp", "pass")
    asa_in = "%ASA-6-302013: Built inbound TCP connection 9 for outside:45.155.205.30/40000 (45.155.205.30/40000) to dmz:192.168.1.50/22 (192.168.1.50/22)"
    assert flow(parse_text(asa_in))[:4] == (BAD2, "192.168.1.50", 40000, 22)
    srx = "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.1.23/50000->45.155.205.20/443 0x0 junos-https"
    assert flow(parse_text(srx))[:4] == (LAN, BAD, 50000, 443)
    mikrotik = "firewall,info forward: in:bridge out:ether1, src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 192.168.88.10:50000->45.155.205.20:443, len 60"
    assert flow(parse_text(mikrotik))[:5] == ("192.168.88.10", BAD, 50000, 443, "tcp")
    fields = ["<14>Oct 14 PA-VM 1", "2026/10/14", "0123", "TRAFFIC", "end", "2561", "2026/10/14", LAN, BAD]
    fields += [
        "198.51.100.1",
        BAD,
        "allow-out",
        "",
        "",
        "ssl",
        "vsys1",
        "trust",
        "untrust",
        "e1/2",
        "e1/1",
        "fwd",
    ]
    fields += ["", "12345", "1", "50000", "443", "12345", "443", "0x400000", "tcp", "allow", "1200"]
    assert flow(parse_text(",".join(fields))) == (LAN, BAD, 50000, 443, "tcp", "allow")


def test_dns_and_dhcp_logs():
    assert parse_text("dnsmasq[123]: query[A] evil-c2.example from 192.168.1.23") == [
        DnsEvent(LAN, "evil-c2.example")
    ]
    assert parse_text("dnsmasq[123]: reply evil-c2.example is 45.155.205.20") == [
        DnsEvent(None, "evil-c2.example", (BAD,))
    ]
    assert parse_text("unbound: [1234:0] info: 192.168.1.23 evil-c2.example. A IN") == [
        DnsEvent(LAN, "evil-c2.example")
    ]
    assert parse_text("dnsmasq-dhcp[1]: DHCPACK(br-lan) 192.168.1.23 aa:bb:cc:dd:ee:ff pixel-7") == [
        Lease(LAN, "pixel-7")
    ]
    assert parse_text("sshd[1]: Accepted publickey for root") == []


def test_zeek_tsv_and_json_and_suricata():
    p = LineParser()
    assert p.parse("#separator \\x09") == []
    assert p.parse("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto") == []
    assert flow(p.parse(f"1700000000.1\tCx1\t{LAN}\t50000\t{BAD}\t443\ttcp")) == (
        LAN,
        BAD,
        50000,
        443,
        "tcp",
        "",
    )
    dns = {"id.orig_h": LAN, "id.orig_p": 5353, "id.resp_h": "192.168.1.1", "id.resp_p": 53}
    dns |= {"query": "evil-c2.example", "answers": [BAD, "cname.example"]}
    assert p.parse(json.dumps(dns)) == [DnsEvent(LAN, "evil-c2.example", (BAD,))]
    alert = {
        "event_type": "alert",
        "src_ip": LAN,
        "src_port": 50000,
        "dest_ip": BAD,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature": "ET MALWARE Win32/Emotet CnC Activity",
            "metadata": {"mitre_technique_id": ["T1071", "nonsense"]},
        },
    }
    (f,) = p.parse(json.dumps(alert))
    assert f.signature.startswith("ET MALWARE") and f.techniques == ("T1071",)
    answer = {"event_type": "dns", "src_ip": "192.168.1.1", "dest_ip": LAN}
    answer["dns"] = {
        "type": "answer",
        "rrname": "evil-c2.example",
        "answers": [{"rrtype": "A", "rdata": BAD}],
    }
    assert p.parse(json.dumps(answer)) == [DnsEvent(None, "evil-c2.example", (BAD,))]
    assert p.parse("{not json") == []


def test_conntrack_and_leases():
    table = f"""\
ipv4     2 tcp      6 431999 ESTABLISHED src={LAN} dst={BAD} sport=50000 dport=443 src={BAD} dst=198.51.100.5 sport=443 dport=50000 [ASSURED] mark=0 use=2
udp      17 29 src=192.168.1.40 dst=8.8.8.8 sport=40000 dport=53 [UNREPLIED] src=8.8.8.8 dst=198.51.100.5 sport=53 dport=40000 mark=0 use=1
tcp      6 100 TIME_WAIT src={LAN} dst=45.155.205.21 sport=1 dport=443 src=45.155.205.21 dst=198.51.100.5 sport=443 dport=1
"""
    flows = parse_conntrack(table)
    assert [(f.src, f.dst, f.dport, f.proto) for f in flows] == [
        (LAN, BAD, 443, "tcp"),
        ("192.168.1.40", "8.8.8.8", 53, "udp"),
    ]
    leases = "1760000000 aa:bb:cc:dd:ee:ff 192.168.1.23 pixel-7 01:aa\n1760000000 aa:bb 192.168.1.24 * *\n"
    leases += 'lease 192.168.1.30 {\n  client-hostname "nas";\n}\n'
    assert parse_leases(leases) == [Lease(LAN, "pixel-7"), Lease("192.168.1.30", "nas")]


def test_lan_orientation():
    lan = Lan()
    assert lan.orient(Flow(LAN, BAD, 1, 443)) == (LAN, BAD, 443, False)
    assert lan.orient(Flow(BAD2, "192.168.1.50", 40000, 22)) == ("192.168.1.50", BAD2, 22, True)
    assert lan.orient(Flow(LAN, "192.168.1.1", 1, 53)) is None  # internal
    assert lan.orient(Flow(BAD, BAD2, 1, 2)) is None  # transit, not ours
    corp = Lan(["45.155.205.0/24"])  # a company using public space inside
    assert corp.orient(Flow(BAD, "8.8.8.8", 1, 53)) == (BAD, "8.8.8.8", 53, False)


# -- NetFlow / IPFIX ---------------------------------------------------------------------


def _v5(*records):
    header = struct.pack("!HHIIIIBBH", 5, len(records), 0, 0, 0, 0, 0, 0, 0)
    body = b"".join(
        struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            socket.inet_aton(src),
            socket.inet_aton(dst),
            b"\0" * 4,
            0,
            0,
            1,
            60,
            0,
            0,
            sport,
            dport,
            0,
            0,
            proto,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        for src, dst, sport, dport, proto in records
    )
    return header + body


def test_netflow_v5():
    flows = NetFlowParser().parse(_v5((LAN, BAD, 50000, 443, 6), (LAN, "8.8.8.8", 4000, 53, 17)))
    assert [(f.src, f.dst, f.sport, f.dport, f.proto) for f in flows] == [
        (LAN, BAD, 50000, 443, "tcp"),
        (LAN, "8.8.8.8", 4000, 53, "udp"),
    ]


def test_netflow_v9_templates_per_exporter():
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1)]
    tmpl = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields)
    tmpl_set = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl
    rec = socket.inet_aton(LAN) + socket.inet_aton(BAD) + struct.pack("!HHB", 50000, 443, 6)
    data = rec + b"\0" * 3  # padded to 4 bytes
    data_set = struct.pack("!HH", 256, 4 + len(data)) + data
    header = struct.pack("!HHIIII", 9, 2, 0, 0, 0, 7)
    p = NetFlowParser()
    assert p.parse(header + data_set, "10.0.0.1") == []  # data before its template: unknown, skipped
    flows = p.parse(header + tmpl_set + data_set, "10.0.0.1")
    assert [(f.src, f.dst, f.dport) for f in flows] == [(LAN, BAD, 443)]
    assert p.parse(header + data_set, "10.0.0.2") == []  # templates don't leak across exporters
    assert p.parse(b"\x00\x09garbage") == []


def test_ipfix_with_ipv6_and_enterprise_fields():
    fields = struct.pack("!HH", 27, 16) + struct.pack("!HH", 28, 16)
    fields += struct.pack("!HHI", 0x8000 | 100, 4, 9)  # vendor field with a PEN
    fields += struct.pack("!HH", 11, 2) + struct.pack("!HH", 4, 1)
    tmpl = struct.pack("!HH", 300, 5) + fields
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl
    src, dst = (
        socket.inet_pton(socket.AF_INET6, "fd00::23"),
        socket.inet_pton(socket.AF_INET6, "2606:4700::1111"),
    )
    rec = src + dst + b"\0\0\0\1" + struct.pack("!HB", 443, 6)
    data_set = struct.pack("!HH", 300, 4 + len(rec)) + rec
    msg = tmpl_set + data_set
    header = struct.pack("!HHIII", 10, 16 + len(msg), 0, 0, 1)
    (f,) = NetFlowParser().parse(header + msg, "10.0.0.1")
    assert (f.src, f.dst, f.dport, f.proto) == ("fd00::23", "2606:4700::1111", 443, "tcp")


# -- the collector feeding the watcher --------------------------------------------------------


@pytest.fixture
def feeds(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text(f"{BAD}\nevil-c2.example\n")
    other = tmp_path / "other.txt"
    other.write_text(f"{BAD}\nevil-c2.example\n")
    return {"bad": str(bad), "other": str(other)}


def _gateway(make_engine, feeds, **cfg):
    engine = make_engine(blocklists=feeds, ai_triage="off")
    gw = GatewayCollector(Config(**cfg))
    gw.started = True  # no listeners in unit tests; events are fed directly
    watch = NetWatch(engine, collector=gw.collect, origin=GATEWAY, gateway=gw)
    return engine, gw, watch


def test_gateway_scan_alerts_with_device_dns_and_attack(make_engine, feeds):
    engine, gw, watch = _gateway(make_engine, feeds, devices={"192.168.1.40": "Office printer"})
    for line in (
        "dnsmasq-dhcp[1]: DHCPACK(br-lan) 192.168.1.23 aa:bb:cc:dd:ee:ff pixel-7",
        "dnsmasq[1]: query[A] evil-c2.example from 192.168.1.23",
        f"dnsmasq[1]: reply evil-c2.example is {BAD}",
        f"kernel: ACCEPT IN=br-lan OUT=eth0 SRC={LAN} DST={BAD} PROTO=TCP SPT=50000 DPT=443",
        f"kernel: ACCEPT IN=br-lan OUT=eth0 SRC={LAN} DST={BAD} PROTO=TCP SPT=50001 DPT=443",
        f"kernel: [UFW BLOCK] IN=eth0 SRC={BAD2} DST=192.168.1.10 PROTO=TCP SPT=1 DPT=22",
        "kernel: ACCEPT SRC=192.168.1.40 DST=192.168.1.1 PROTO=UDP SPT=1 DPT=53",
        "kernel: ACCEPT SRC=192.168.1.40 DST=8.8.8.8 PROTO=UDP SPT=1 DPT=53",
    ):
        gw.feed_line(line)
    gw.add(Flow(LAN, BAD, 50002, 443, "tcp", "", "ET MALWARE CnC Activity", ("T1071",)))

    result = watch.scan()
    assert result["public_ips"] == 2 and result["domains"] == 1 and result["alerts"] == 2
    assert gw.stats.blocked_skipped == 1 and gw.stats.internal_skipped == 1

    rows = {(r["device"], r["remote_ip"]): r for r in watch.rows}
    conn = rows[(LAN, BAD)]
    assert conn["device_name"] == "pixel-7" and conn["verdict"] == "malicious" and conn["count"] == 3
    assert conn["names"] == ["evil-c2.example"]
    assert rows[(LAN, "evil-c2.example")]["proto"] == "dns"
    assert rows[("192.168.1.40", "8.8.8.8")]["device_name"] == "Office printer"

    alerts = {a["key"]: a for a in engine.store.alerts()}
    ctx = alerts[f"ip:{BAD}"]["context"]
    assert ctx["device"] == LAN and ctx["device_name"] == "pixel-7" and ctx["attack"] == ["T1071.001"]
    assert ctx["mode"] == "gateway" and "inbound" not in ctx
    assert alerts["domain:evil-c2.example"]["context"]["query"] is True

    edges = {(e["src"], e["rel"], e["dst"]) for e in engine.store.edges_of(f"host:{LAN}")}
    assert ("host:gateway", "routes_for", f"host:{LAN}") in edges
    assert (f"host:{LAN}", "connected_to", f"ip:{BAD}") in edges
    assert (f"host:{LAN}", "queried", "domain:evil-c2.example") in edges
    assert engine.store.node(f"host:{LAN}")["attrs"]["name"] == "pixel-7"
    techs = {t["id"]: t["basis"] for t in attack.techniques_of(engine.store, f"ip:{BAD}", associated=False)}
    assert techs == {"T1071.001": ["inferred"], "T1071": ["observed"]}
    device_techs = {t["id"] for t in attack.techniques_of(engine.store, f"host:{LAN}")}
    assert device_techs == {"T1071", "T1071.001"}
    assert watch.status()["mode"] == "gateway" and watch.status()["devices"] == 2

    # The next window starts empty; the same flow again doesn't re-alert.
    gw.feed_line(f"kernel: ACCEPT SRC={LAN} DST={BAD} PROTO=TCP SPT=50003 DPT=443")
    assert watch.scan()["alerts"] == 0


def test_device_suppression(make_engine, feeds):
    engine, gw, watch = _gateway(make_engine, feeds)
    engine.store.add_suppression("device", LAN)
    gw.feed_line(f"kernel: ACCEPT SRC={LAN} DST={BAD} PROTO=TCP SPT=50000 DPT=443")
    assert watch.scan()["alerts"] == 0
    assert watch.rows[0]["suppressed"] is True


def test_blocked_flows_can_be_included(make_engine, feeds):
    engine, gw, watch = _gateway(make_engine, feeds, gateway_include_blocked=True)
    gw.feed_line(f"kernel: [UFW BLOCK] IN=eth0 SRC={BAD} DST=192.168.1.10 PROTO=TCP SPT=1 DPT=22")
    watch.scan()
    (row,) = watch.rows
    assert row["inbound"] is True and row["device"] == "192.168.1.10" and row["remote_port"] == 22


def test_udp_listeners_and_sender_allowlist():
    gw = GatewayCollector(Config(gateway_syslog="127.0.0.1:0", gateway_netflow="127.0.0.1:0"))
    gw.start()
    try:
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.sendto(
            f"<134>kernel: ACCEPT SRC={LAN} DST={BAD} PROTO=TCP SPT=1 DPT=443".encode(),
            gw.addresses["syslog"],
        )
        out.sendto(_v5((LAN, BAD2, 2, 8443, 6)), gw.addresses["netflow"])
        deadline = time.time() + 5
        while gw.stats.events < 2 and time.time() < deadline:
            time.sleep(0.05)
        snap = gw.collect()
        assert {(c.device, c.remote_ip, c.remote_port) for c in snap.connections} == {
            (LAN, BAD, 443),
            (LAN, BAD2, 8443),
        }
    finally:
        gw.stop()

    strict = GatewayCollector(Config(gateway_syslog="127.0.0.1:0", gateway_senders=["10.9.9.9/32"]))
    strict.start()
    try:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(
            b"SRC=1.1.1.1 DST=8.8.8.8", strict.addresses["syslog"]
        )
        deadline = time.time() + 5
        while strict.stats.rejected_senders < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert strict.stats.rejected_senders == 1 and strict.stats.events == 0
    finally:
        strict.stop()


def test_engine_tails_a_log_file_in_gateway_mode(make_engine, feeds, tmp_path):
    log = tmp_path / "eve.json"
    log.write_text(
        '{"event_type":"flow","src_ip":"192.168.1.9","dest_ip":"1.1.1.1","dest_port":53,"proto":"UDP"}\n'
    )
    engine = make_engine(blocklists=feeds, gateway_files=[str(log)])
    watch = engine.watcher()
    try:
        assert watch.mode == "gateway" and watch.origin == GATEWAY
        time.sleep(0.3)
        with log.open("a") as fh:  # history before start is skipped; new lines are read
            fh.write(
                json.dumps({"event_type": "flow", "src_ip": LAN, "dest_ip": BAD, "dest_port": 443}) + "\n"
            )
        deadline = time.time() + 5
        while watch.gateway.stats.events < 1 and time.time() < deadline:
            time.sleep(0.1)
        watch.scan()
        assert [(r["device"], r["remote_ip"]) for r in watch.rows] == [(LAN, BAD)]
        assert watch.status()["gateway"]["inputs"] == [f"file {log}"]
    finally:
        watch.gateway.stop()


# -- blocklist feed for the firewall ---------------------------------------------------------


def test_blocklist_feed(make_engine, feeds, tmp_path):
    more = tmp_path / "more.txt"
    more.write_text("45.155.205.40\n45.155.205.41\n45.155.205.42\nhttp://evil-c2.example/x\n")
    engine = make_engine(blocklists={**feeds, "more": str(more), "again": str(more)})
    keys = [
        BAD,
        "45.155.205.40",
        "45.155.205.41",
        "45.155.205.42",
        "evil-c2.example",
        "http://evil-c2.example/x",
    ]
    engine.investigate([classify(k) for k in keys], depth=0)
    engine.set_feedback("ip:45.155.205.41", "false_positive")
    engine.store.add_suppression("indicator", "ip:45.155.205.42")
    engine.store.upsert_node(classify("45.155.205.40"), {"rdap.net_name": "CLOUDFLARENET"})

    ips = export.blocklist(engine.store, "ip", shared_infra=engine.shared_infra)
    assert ips.splitlines() == [BAD]  # FP, suppressed and Cloudflare IPs are never blocked
    assert export.blocklist(engine.store, "domain").splitlines() == ["evil-c2.example"]
    assert export.blocklist(engine.store, "url", comments=True).splitlines()[1:] == [
        "http://evil-c2.example/x"
    ]
    with pytest.raises(ValueError):
        export.blocklist(engine.store, "hash")

    engine.config.api_token = "s3cret"
    srv = make_server(engine, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(base + "/api/blocklist/ip.txt?token=s3cret", timeout=5) as resp:
            assert resp.read().decode().split() == [BAD]
            assert resp.headers["Content-Type"].startswith("text/plain")
        for path in ("/api/blocklist/ip.txt", "/api/blocklist/ip.txt?token=wrong", "/api/stats?token=s3cret"):
            with pytest.raises(urllib.error.HTTPError) as err:
                opener.open(base + path, timeout=5)
            assert err.value.code == 401, path  # ?token= works for blocklists only
        req = urllib.request.Request(base + "/api/attack", headers={"Authorization": "Bearer s3cret"})
        with opener.open(req, timeout=5) as resp:
            assert json.loads(resp.read())["version"] == attack.catalogue().version
    finally:
        srv.shutdown()
        srv.server_close()


def test_flows_stay_in_the_table_for_the_window():
    gw = GatewayCollector(Config(gateway_window=60))
    gw.started = True
    gw.add(Flow(LAN, BAD, 1, 443))
    gw.feed_line("dnsmasq[1]: query[A] evil-c2.example from 192.168.1.23")
    first = gw.collect(now=1000.0)
    assert [(c.remote_ip, c.state) for c in first.connections] == [(BAD, "NEW")]
    gw.add(Flow(LAN, BAD, 2, 443))
    again = gw.collect(now=1030.0)
    assert [(c.state, c.count) for c in again.connections] == [("NEW", 2)]
    assert again.queries == {"evil-c2.example": [LAN]}  # still inside the window
    later = gw.collect(now=1080.0)
    assert [(c.state, c.count) for c in later.connections] == [("RECENT", 2)]
    assert later.queries == {}  # last asked at 1000, older than 60 s
    assert gw.collect(now=1100.0).connections == []
