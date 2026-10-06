"""Parser tests for each remote source, using responses shaped like the real APIs."""

import time
from datetime import UTC, datetime, timedelta

from iglite.config import Config
from iglite.extract import classify
from iglite.fetch import Fetcher
from iglite.model import Kind, Verdict
from iglite.sources import build, describe
from iglite.sources.base import Context
from iglite.sources.cti import OTX, URLhaus, VirusTotal
from iglite.sources.osint import RDAP, CertTransparency, InternetDB
from iglite.store import Store


def ctx(transport, **keys):
    return Context(Fetcher(Store(), transport=transport), Config(db=":memory:", keys=keys))


def test_rdap_young_domain_is_suspicious(transport):
    created = (datetime.now(UTC) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    transport.add(
        "https://rdap.org/domain/fresh.example",
        body={
            "events": [{"eventAction": "registration", "eventDate": created}],
            "entities": [
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Registrar LLC"]]]}
            ],
        },
    )
    f = RDAP().lookup(classify("fresh.example"), ctx(transport))
    assert f.attributes["age_days"] == 3
    assert f.evidence[0].verdict is Verdict.SUSPICIOUS
    assert f.relations[0].dst.key == "org:Cheap Registrar LLC"


def test_rdap_ip_network(transport):
    transport.add(
        "https://rdap.org/ip/45.155.205.1",
        body={
            "name": "EXAMPLE-NET",
            "country": "NL",
            "entities": [{"roles": ["registrant"], "handle": "ORG-X"}],
        },
    )
    f = RDAP().lookup(classify("45.155.205.1"), ctx(transport))
    assert f.attributes == {"net_name": "EXAMPLE-NET", "net_country": "NL"}
    assert f.relations[0].rel == "allocated_to" and not f.relations[0].pivot


def test_crtsh_subdomains(transport):
    transport.add(
        "https://crt.sh/",
        body=[
            {"name_value": "a.corp.example\n*.b.corp.example"},
            {"name_value": "corp.example"},
            {"name_value": "unrelated.example"},
        ],
    )
    f = CertTransparency().lookup(classify("corp.example"), ctx(transport))
    assert sorted(r.dst.value for r in f.relations) == ["a.corp.example", "b.corp.example"]


def test_internetdb_unknown_ip(transport):
    transport.add("https://internetdb.shodan.io/", status=404, body={"detail": "No information available"})
    assert InternetDB().lookup(classify("45.155.205.1"), ctx(transport)) is None


def test_otx_pulses_and_tags(transport):
    transport.add(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/45.155.205.1/general",
        body={
            "pulse_info": {
                "pulses": [
                    {"name": "Cobalt Strike C2", "tags": ["C2", "cobaltstrike"], "malware_families": []},
                    {"name": "Botnet", "tags": [], "malware_families": [{"display_name": "Mirai"}]},
                ]
            }
        },
    )
    f = OTX().lookup(classify("45.155.205.1"), ctx(transport, otx="k"))
    assert f.evidence[0].verdict is Verdict.MALICIOUS
    assert "Cobalt Strike C2" in f.evidence[0].detail
    assert {r.dst.value for r in f.relations} == {"c2", "cobaltstrike", "mirai"}


def test_virustotal_thresholds(transport):
    def vt(stats, reputation=0):
        return {"data": {"attributes": {"last_analysis_stats": stats, "reputation": reputation}}}

    transport.add(
        "https://www.virustotal.com/api/v3/domains/bad.example",
        body=vt({"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 10}),
    )
    transport.add(
        "https://www.virustotal.com/api/v3/domains/meh.example",
        body=vt({"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 10}),
    )
    transport.add(
        "https://www.virustotal.com/api/v3/domains/ok.example",
        body=vt({"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10}),
    )
    c, src = ctx(transport, virustotal="k"), VirusTotal()
    assert src.lookup(classify("bad.example"), c).evidence[0].verdict is Verdict.MALICIOUS
    assert src.lookup(classify("meh.example"), c).evidence[0].verdict is Verdict.SUSPICIOUS
    assert src.lookup(classify("ok.example"), c).evidence[0].verdict is Verdict.BENIGN


def test_urlhaus_host_and_url(transport):
    transport.add(
        "https://urlhaus-api.abuse.ch/v1/host/",
        body={
            "query_status": "ok",
            "urlhaus_reference": "https://urlhaus.abuse.ch/host/x/",
            "urls": [{"url": "http://bad.example/a.exe", "url_status": "online"}],
        },
    )
    f = URLhaus().lookup(classify("bad.example"), ctx(transport, urlhaus="k"))
    assert f.evidence[0].verdict is Verdict.MALICIOUS and "1 online" in f.evidence[0].detail
    assert f.relations[0].src.kind is Kind.URL

    transport.routes.clear()
    transport.add(
        "https://urlhaus-api.abuse.ch/v1/url/",
        body={
            "query_status": "ok",
            "url_status": "offline",
            "threat": "malware_download",
            "payloads": [{"response_sha256": "A" * 64}],
            "tags": ["emotet"],
        },
    )
    f = URLhaus().lookup(classify("http://bad.example/a.exe"), ctx(transport, urlhaus="k"))
    assert f.evidence[0].confidence == 0.7
    assert {r.rel for r in f.relations} == {"serves", "tagged"}

    transport.routes.clear()
    transport.add("https://urlhaus-api.abuse.ch/v1/host/", body={"query_status": "no_results"})
    assert URLhaus().lookup(classify("fine.example"), ctx(transport, urlhaus="k")) is None


def test_keyed_sources_are_off_without_keys():
    status = {s["name"]: s["status"] for s in describe(Config())}
    assert status["virustotal"] == "missing key" and status["rdap"] == "enabled"
    names = {s.name for s in build(Config(keys={"virustotal": "k"}, trust={"virustotal": 0.95}))}
    assert "virustotal" in names and "otx" not in names
    vt = next(
        s
        for s in build(Config(keys={"virustotal": "k"}, trust={"virustotal": 0.95}))
        if s.name == "virustotal"
    )
    assert vt.trust == 0.95


def test_rate_limit_spaces_requests(transport):
    transport.add("https://slow.example/", body={})
    fetcher = Fetcher(Store(), transport=transport, min_interval={"slow.example": 0.2})
    started = time.monotonic()
    for i in range(3):
        fetcher.json(f"https://slow.example/{i}", ttl=60)
    assert time.monotonic() - started >= 0.4
