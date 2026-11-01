import io
import json
import zipfile

import pytest

from iglite import cases, common, demo, respond
from iglite.cli import main
from iglite.common import Common, filter_graph, parse_tranco
from iglite.extract import treat_as_public
from iglite.model import Indicator, Kind, Relation


@pytest.fixture
def c():
    return Common(extra=["intranet.corp.example"], ignore=["zoom.us"], top=["popular-shop.example", "bit.ly"])


def test_domains_match_the_catalogue_by_parent_domain(c):
    assert c.domain("r3---sn-aig.googlevideo.com") == "Google"
    assert c.domain("ICLOUD.COM") == "Apple"
    assert c.domain("ocsp.digicert.com") == "Certificate checks"
    assert c.domain("wiki.intranet.corp.example") == "Your common services"
    assert c.domain("www.popular-shop.example") == "Popular site"


def test_lookalikes_abused_services_and_ignores_are_never_common(c):
    assert c.domain("google.com.evil.example") is None  # lookalike: the suffix must match whole labels
    assert c.domain("notgoogle.com") is None
    assert c.domain("goog1e.com") is None
    assert c.domain("docs.google.com") is None and c.abused_by("docs.google.com") == "docs.google.com"
    assert c.domain("payload.blogspot.com") is None
    assert c.domain("raw.githubusercontent.com") is None
    assert c.domain("bit.ly") is None  # popular (in the top list) but abused
    assert c.domain("x.duckdns.org") is None
    assert c.domain("zoom.us") is None  # in the catalogue, but you said otherwise
    assert c.domain("com") is None


def test_ips_need_a_cdn_operator_or_only_common_names(make_engine, c):
    engine = make_engine()
    store = engine.store
    for value, attrs in (
        ("198.51.100.1", {"rdap.net_name": "AKAMAI-AS"}),
        ("198.51.100.2", {"rdap.net_name": "GOOGLE"}),
        ("198.51.100.3", {}),
        ("198.51.100.4", {}),
    ):
        store.upsert_node(Indicator(Kind.IP, value), attrs)
    for name, ip in (
        ("www.netflix.com", "198.51.100.3"),
        ("www.netflix.com", "198.51.100.4"),
        ("odd-host.example", "198.51.100.4"),
    ):
        store.upsert_node(Indicator(Kind.DOMAIN, name))
        store.add_relation(
            Relation(Indicator(Kind.DOMAIN, name), "resolves_to", Indicator(Kind.IP, ip)), "dns"
        )
    labels = c.classify(store, store.nodes([f"ip:198.51.100.{i}" for i in range(1, 5)]))
    assert labels == {
        "ip:198.51.100.1": "Akamai",
        "ip:198.51.100.3": "Netflix",
    }  # Google rents servers: not by owner


@pytest.fixture
def busy(tmp_path):
    """The demo a minute in: everyday sites, four incidents, a quarantined plug."""
    engine, watch, network = demo.build(str(tmp_path / "demo.db"))
    for ip, name in demo.DEVICES.items():
        network.gw.add(demo.Lease(ip, name))
    network.incidents(60)
    for _ in range(6):
        network.background()
    for device, site in (
        ("10.42.0.11", "maps.example"),
        ("10.42.0.11", "news-site.example"),
        ("10.42.0.23", "video-stream.example"),
        ("10.42.0.23", "gaming.example"),
    ):
        network.visit(device, site)  # the sites the tests below look for, whatever the random traffic did
    watch.scan()
    try:
        yield engine
    finally:
        engine.store.close()
        treat_as_public([])


def test_the_graph_keeps_what_matters(busy):
    store = busy.store
    full = store.neighbourhood("host:gateway", 3, 2000)
    graph = filter_graph(busy.common(), store, full, keep=["host:gateway"])
    keys = {n["key"] for n in graph["nodes"]}
    # every incident is still there, with its path back to the device
    for k in (
        f"ip:{demo.C2_IP}",
        f"domain:{demo.PHISH}",
        f"domain:{demo.MINER}",
        f"domain:{demo.DROPPER}",
        f"ip:{demo.SCANNER}",
    ):
        assert k in keys, k
    assert {"host:10.42.0.61", "host:10.42.0.23", "host:10.42.0.52"} <= keys
    # everyday services are gone, with their IPs
    assert "domain:video-stream.example" not in keys and "ip:198.51.100.11" not in keys
    assert "domain:static-cdn.example" not in keys  # the shared CDN: known-good, common
    assert "domain:gaming.example" in keys  # not on the list: still shown
    assert graph["hidden"]["common"] >= 10 and graph["hidden"]["services"]["Everyday services (demo)"] >= 5
    assert len(graph["nodes"]) < len(full["nodes"])
    edges_ok = all(e["src"] in keys and e["dst"] in keys for e in graph["edges"])
    assert edges_ok


def test_flagged_blocked_and_case_nodes_are_never_hidden(busy):
    store = busy.store
    respond.block(busy, "news-site.example")  # you blocked a "common" site
    cid = cases.create(store, "Look at this", indicators=["domain:maps.example"])
    graph = filter_graph(
        busy.common(), store, store.neighbourhood("host:gateway", 3, 2000), keep=["host:gateway"]
    )
    keys = {n["key"] for n in graph["nodes"]}
    assert {"domain:news-site.example", "domain:maps.example"} <= keys
    cases.update(store, cid, status="closed")


def test_api_hides_common_only_when_asked(busy):
    import threading
    import urllib.request

    from iglite.api import make_server

    busy.config.api_token = None
    srv = make_server(busy, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def get(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        with opener.open(urllib.request.Request(base + path, data=data), timeout=5) as resp:
            return json.loads(resp.read())

    try:
        full = get("/api/graph?key=host:gateway&depth=3&limit=500")
        lean = get("/api/graph?key=host:gateway&depth=3&limit=500&hide_common=1")
        assert "hidden" not in full and lean["hidden"]["common"] > 0
        assert "domain:video-stream.example" in lean["hidden"]["keys"]
        assert len(lean["nodes"]) < len(full["nodes"])
        info = get("/api/indicator?key=host:10.42.0.11")  # the phone: mostly everyday sites
        assert info["neighbours"]["domain:news-site.example"]["common"] == "Everyday services (demo)"
        assert get("/api/indicator?key=domain:news-site.example")["common"] == "Everyday services (demo)"
        assert get(f"/api/indicator?key=domain:{demo.PHISH}")["common"] is None
        feed = get("/api/lookups?limit=400")
        assert any(x["common"] for x in feed) and all(
            x["common"] is None for x in feed if x["domain"] == demo.PHISH
        )
        assert get("/api/common/check", {"name": "docs.google.com"})["abused"] == "docs.google.com"
        assert "Google" in get("/api/common")["services"]
    finally:
        srv.shutdown()
        srv.server_close()


# -- Tranco ---------------------------------------------------------------------------------


def _zip(text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top-1m.csv", text)
    return buf.getvalue()


def test_tranco_parsing_and_download(tmp_path):
    csv = "1,google.com\n2,facebook.com\n3,bad row\n4,netflix.com\n"
    assert parse_tranco(csv.encode(), 2) == ["google.com", "facebook.com"]
    assert parse_tranco(_zip(csv), 10) == ["google.com", "facebook.com", "netflix.com"]

    calls = []

    def api_ok(url, timeout=0):
        calls.append(url)
        if url == common.TRANCO_API:
            return json.dumps({"list_id": "ABC12", "available": True}).encode()
        assert url == "https://tranco-list.eu/download/ABC12/3"
        return csv.encode()

    assert common.download_tranco(3, get=api_ok) == (["google.com", "facebook.com", "netflix.com"], "ABC12")

    def api_down(url, timeout=0):
        if url == common.TRANCO_API:
            raise OSError("503")
        return _zip(csv)

    domains, list_id = common.download_tranco(2, get=api_down)
    assert (domains, list_id) == (["google.com", "facebook.com"], "top-1m")
    path = common.save_tranco(domains, list_id, tmp_path / "t.txt")
    top, header = common.read_top(path)
    assert top == domains and header.startswith("Tranco list top-1m, top 2")


def test_cli_common(make_engine, capsys, monkeypatch, tmp_path):
    engine = make_engine()
    engine.config.common_top_file = str(tmp_path / "tranco.txt")
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    monkeypatch.setattr(common, "download_tranco", lambda top: (["popular-shop.example"], "XYZ"))
    monkeypatch.setattr(
        common,
        "download_ranges",
        lambda: {
            "Google": {"include": ["142.250.0.0/15"], "exclude": []},
            "Amazon CloudFront": {"include": ["13.32.0.0/15"]},
        },
    )
    assert main(["common", "update", "--top", "5"]) == 0
    out = capsys.readouterr().out
    assert "saved 1 domains" in out and "Google 1 ranges" in out
    engine._common = None
    assert main(["common", "check", "www.popular-shop.example", "docs.google.com", "evil.example"]) == 0
    out = capsys.readouterr().out
    assert "www.popular-shop.example: common (Popular site)" in out
    assert "docs.google.com: popular but often abused" in out and "evil.example: not a common service" in out
    assert main(["common"]) == 0
    assert "Google:" in capsys.readouterr().out


GOOG = {
    "syncToken": "1",
    "prefixes": [
        {"ipv4Prefix": "8.8.8.0/24"},
        {"ipv4Prefix": "142.250.0.0/15"},
        {"ipv4Prefix": "34.0.0.0/9"},
        {"ipv6Prefix": "2a00:1450::/32"},
    ],
}
CLOUD = {
    "syncToken": "1",
    "prefixes": [{"ipv4Prefix": "34.0.0.0/9", "service": "Google Cloud", "scope": "us-east1"}],
}
AWS_RANGES = {
    "prefixes": [
        {"ip_prefix": "13.32.0.0/15", "region": "GLOBAL", "service": "CLOUDFRONT"},
        {"ip_prefix": "3.0.0.0/15", "region": "eu-west-1", "service": "EC2"},
    ],
    "ipv6_prefixes": [{"ipv6_prefix": "2600:9000::/28", "region": "GLOBAL", "service": "CLOUDFRONT"}],
}


def test_provider_ranges_cover_their_own_services_not_rented_servers(make_engine, tmp_path):
    docs = {common.GOOGLE_ALL: GOOG, common.GOOGLE_CLOUD: CLOUD, common.AWS: AWS_RANGES}
    ranges = common.download_ranges(get=lambda url, timeout=0: json.dumps(docs[url]).encode())
    assert ranges["Google"]["exclude"] == ["34.0.0.0/9"]
    assert ranges["Amazon CloudFront"]["include"] == ["13.32.0.0/15", "2600:9000::/28"]
    path = common.save_ranges(ranges, tmp_path / "ip_ranges.json")
    loaded, when = common.read_ranges(path)
    assert loaded == ranges and when
    c = Common(ranges=loaded)
    assert c.network("142.250.180.14") == "Google" and c.network("2a00:1450:4009::1") == "Google"
    assert c.network("8.8.8.8") == "Google"
    assert c.network("34.120.1.1") is None  # Google Cloud: anyone can rent it
    assert c.network("13.33.10.10") == "Amazon CloudFront"
    assert c.network("3.0.5.5") is None  # EC2
    assert c.network("17.253.1.1") == "Apple"  # from the built-in catalogue
    assert c.network("not an ip") is None

    store = make_engine().store
    for ip in ("142.250.180.14", "34.120.1.1", "198.51.100.1"):
        store.upsert_node(Indicator(Kind.IP, ip))
    labels = c.classify(store, store.nodes(["ip:142.250.180.14", "ip:34.120.1.1"]))
    assert labels == {"ip:142.250.180.14": "Google"}

    with pytest.raises(ValueError):  # an empty list is refused, not saved
        common.download_ranges(get=lambda url, timeout=0: json.dumps({"prefixes": []}).encode())


def test_ranges_load_from_next_to_the_popular_site_list(tmp_path):
    from types import SimpleNamespace

    common.save_ranges(
        {"Google": {"include": ["142.250.0.0/15"], "exclude": []}}, tmp_path / "ip_ranges.json"
    )
    cfg = SimpleNamespace(common_top_file=str(tmp_path / "tranco.txt"), common_domains=[], common_ignore=[])
    assert common.from_config(cfg).network("142.251.1.1") == "Google"


def test_feeds_count_at_half_weight_for_popular_services(make_engine):
    from iglite.model import Evidence, Verdict
    from iglite.scoring import assess

    trust = {"otx": 0.6, "behaviour": 0.8}
    plain = assess([Evidence("otx", Verdict.MALICIOUS, "pulse", 0.9)], trust)
    popular = assess([Evidence("otx", Verdict.MALICIOUS, "pulse", 0.9)], trust, popular="Google")
    assert plain.verdict.value == "suspicious" and popular.verdict.value == "unknown"
    assert any("popular service (Google)" in r.detail for r in popular.reasons)
    beh = assess([Evidence("behaviour", Verdict.SUSPICIOUS, "beacons", 1.0)], trust, popular="Google")
    assert beh.score == assess([Evidence("behaviour", Verdict.SUSPICIOUS, "beacons", 1.0)], trust).score

    engine = make_engine()
    store = engine.store
    for ind in (
        Indicator(Kind.DOMAIN, "gmail.com"),
        Indicator(Kind.DOMAIN, "odd-site.example"),
        Indicator(Kind.URL, "https://github.com/x/y/releases/download/v1/a.exe"),
    ):
        store.upsert_node(ind)
        store.replace_evidence(ind.key, "otx", [Evidence("otx", Verdict.MALICIOUS, "pulse", 0.9)])
        a = engine.assess(ind.key)
        store.set_assessment(ind.key, a.score, a.verdict)
    v = {
        k: store.node(k)["verdict"]
        for k in (
            "domain:gmail.com",
            "domain:odd-site.example",
            "url:https://github.com/x/y/releases/download/v1/a.exe",
        )
    }
    assert v["domain:gmail.com"] == "unknown"  # a popular service listed by one feed
    assert v["domain:odd-site.example"] != "unknown"  # an unknown site: full weight
    assert (
        v["url:https://github.com/x/y/releases/download/v1/a.exe"] != "unknown"
    )  # a specific URL: full weight


def test_rescore_flagged_rejudges_old_verdicts(make_engine):
    from iglite.model import Evidence, Verdict

    engine = make_engine()
    store = engine.store
    store.upsert_node(Indicator(Kind.DOMAIN, "gmail.com"))
    store.replace_evidence("domain:gmail.com", "otx", [Evidence("otx", Verdict.MALICIOUS, "pulse", 0.9)])
    store.set_assessment("domain:gmail.com", 44, Verdict.SUSPICIOUS)  # as an older version scored it
    assert engine.rescore_flagged() == 1
    assert store.node("domain:gmail.com")["verdict"] == "unknown"
    assert engine.rescore_flagged() == 0
