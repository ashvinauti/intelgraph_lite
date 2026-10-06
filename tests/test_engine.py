import time

from iglite.engine import Engine
from iglite.extract import classify
from iglite.model import Finding, Indicator, Kind, Relation
from iglite.sources.base import Source


def seeds(*values):
    return [classify(v) for v in values]


def test_blocklists_and_corroboration(make_engine, lists):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    report = engine.investigate(seeds("203.0.113.66", "evil.example", "192.0.2.10"), depth=0)
    a = report.assessments
    assert a["ip:203.0.113.66"]["verdict"] == "malicious"  # two lists agree
    assert a["domain:evil.example"]["verdict"] == "suspicious"  # only one list
    assert a["ip:192.0.2.10"]["verdict"] == "unknown"
    assert report.network_calls == 0


def test_allowlist_counters_false_positive(make_engine, lists, tmp_path):
    fp = tmp_path / "fp.txt"
    fp.write_text("cdn.example\n")
    engine = make_engine(blocklists={"bad": str(fp)}, allowlists={"good": lists["good"]})
    a = engine.investigate(seeds("cdn.example"), depth=0).assessments["domain:cdn.example"]
    assert a["verdict"] == "benign"
    assert a["contradiction"] is True


def test_url_pivots_to_its_host_and_inherits_suspicion(make_engine, lists):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    report = engine.investigate(seeds("http://evil.example/payload.bin"), depth=1)
    assert engine.store.node("domain:evil.example") is not None
    edges = engine.store.edges_of("url:http://evil.example/payload.bin")
    assert {"rel": "hosted_on", "dst": "domain:evil.example"}.items() <= edges[0].items()
    assert report.assessments["url:http://evil.example/payload.bin"]["verdict"] in ("suspicious", "malicious")


def test_private_ips_are_never_sent_out(make_engine, transport):
    engine = make_engine()
    transport.add("https://internetdb.shodan.io/", body={"ip": "x"})
    engine.investigate(seeds("10.1.2.3"), depth=0)
    assert transport.calls == []


def test_internetdb_tags_and_pivots(make_engine, transport):
    transport.add(
        "https://internetdb.shodan.io/45.155.205.20",
        body={
            "ip": "45.155.205.20",
            "ports": [443],
            "tags": ["c2"],
            "hostnames": ["cnc.example"],
            "vulns": ["CVE-2021-44228"],
            "cpes": [],
        },
    )
    engine = make_engine(disabled=["dns", "crtsh", "rdap"])
    report = engine.investigate(seeds("45.155.205.20"), depth=1)
    assert report.assessments["ip:45.155.205.20"]["verdict"] == "suspicious"
    assert engine.store.node("cve:CVE-2021-44228") is not None
    # The hostname was pivoted to and inherits a hint from the malicious IP? Not yet:
    # one source is not enough to call the IP malicious, so no association hint.
    dom = engine.assess("domain:cnc.example")
    assert dom.verdict.value == "unknown"


def test_cache_means_second_run_is_free(make_engine, transport):
    transport.add("https://internetdb.shodan.io/", body={"ip": "45.155.205.30", "tags": ["scanner"]})
    engine = make_engine(disabled=["dns", "crtsh", "rdap"])
    first = engine.investigate(seeds("45.155.205.30"), depth=0)
    second = engine.investigate(seeds("45.155.205.30"), depth=0)
    assert first.network_calls == 1
    assert second.network_calls == 0
    assert second.assessments == first.assessments


def test_transient_errors_are_reported_not_cached(make_engine, transport):
    transport.add("https://internetdb.shodan.io/", status=503, body=b"")
    engine = make_engine(disabled=["dns", "crtsh", "rdap"])
    r1 = engine.investigate(seeds("45.155.205.40"), depth=0)
    assert any("HTTP 503" in e for e in r1.errors)
    engine.investigate(seeds("45.155.205.40"), depth=0)
    assert len(transport.calls) == 2


class FanOut(Source):
    """Every domain links to ten fresh domains: an infinitely large graph."""

    name = "fanout"
    kinds = frozenset({Kind.DOMAIN})

    def lookup(self, ind, ctx):
        return Finding(
            relations=[
                Relation(ind, "linked", Indicator(Kind.DOMAIN, f"n{i}.{ind.value}")) for i in range(10)
            ]
        )


class Slow(Source):
    name = "slow"
    kinds = frozenset({Kind.DOMAIN})

    def lookup(self, ind, ctx):
        time.sleep(2)
        return Finding()


class Broken(Source):
    name = "broken"
    kinds = frozenset({Kind.DOMAIN})

    def lookup(self, ind, ctx):
        raise RuntimeError("boom")


def _engine_with(make_engine, *sources):
    base = make_engine()
    return Engine(base.config, store=base.store, sources=list(sources), fetcher=base.fetcher)


def test_budget_caps_explosive_graphs(make_engine):
    engine = _engine_with(make_engine, FanOut())
    report = engine.investigate(seeds("root.example"), depth=5, budget=25)
    assert report.looked_up == 25
    assert report.partial


def test_deadline_abandons_slow_sources(make_engine):
    engine = _engine_with(make_engine, Slow())
    started = time.monotonic()
    report = engine.investigate(seeds("slow.example"), depth=0, deadline=0.3)
    assert time.monotonic() - started < 1.5
    assert report.partial


def test_broken_source_does_not_sink_the_run(make_engine, lists):
    base = make_engine(blocklists={"bad": lists["bad"]})
    engine = Engine(base.config, store=base.store, sources=[Broken(), *base.sources], fetcher=base.fetcher)
    report = engine.investigate(seeds("evil.example"), depth=0)
    assert any("boom" in e for e in report.errors)
    assert report.assessments["domain:evil.example"]["verdict"] == "suspicious"


def test_delisted_indicator_loses_evidence(make_engine, tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("gone.example\n")
    engine = make_engine(blocklists={"feed": str(feed)})
    assert engine.investigate(seeds("gone.example"), depth=0).assessments["domain:gone.example"]["reasons"]
    feed.write_text("")
    src = next(s for s in engine.sources if s.name == "feed")
    src._expires = 0  # force reload as if the TTL had elapsed
    assert not engine.investigate(seeds("gone.example"), depth=0).assessments["domain:gone.example"][
        "reasons"
    ]


def test_ingest_records_report_links(make_engine):
    engine = make_engine()
    found = engine.ingest("C2 at 203.0.113[.]9 and evil[.]example", "apt-report.txt")
    assert {i.key for i in found} == {"ip:203.0.113.9", "domain:evil.example"}
    hood = engine.store.neighbourhood("report:apt-report.txt", depth=1)
    assert len(hood["nodes"]) == 3 and len(hood["edges"]) == 2
