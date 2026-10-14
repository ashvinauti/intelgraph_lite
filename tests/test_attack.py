import json

from iglite import attack, export
from iglite.cli import main
from iglite.extract import classify, extract
from iglite.model import Indicator, Kind, Relation
from iglite.sources.base import Context
from iglite.sources.cti import OTX, URLhaus


def test_catalogue_has_the_matrix():
    cat = attack.catalogue()
    assert len(cat) > 500
    assert [t["short"] for t in cat.tactics][:3] == [
        "reconnaissance",
        "resource-development",
        "initial-access",
    ]
    web = cat.technique("t1071.001")
    assert web["name"] == "Application Layer Protocol: Web Protocols"
    assert web["tactics"] == ["command-and-control"]
    assert web["url"] == "https://attack.mitre.org/techniques/T1071/001"
    assert web["stix_id"].startswith("attack-pattern--")
    assert cat.technique("T9999") is None


def test_every_mapping_points_at_a_real_technique():
    cat = attack.catalogue()
    for tid in {*attack.TAG_TECHNIQUES.values(), *attack.PORT_TECHNIQUES.values(), "T1571"}:
        assert cat.technique(tid) is not None, tid


def test_tags_match_malware_and_groups_but_not_tools():
    cat = attack.catalogue()
    assert cat.match_tag("Emotet") == Indicator(Kind.SOFTWARE, "S0367")
    assert cat.match_tag("fancy bear") == Indicator(Kind.GROUP, "G0007")
    assert cat.match_tag("cobalt-strike") == Indicator(Kind.SOFTWARE, "S0154")
    for word in ("ftp", "tor", "net", "rat", "trojan", "c2"):
        assert cat.match_tag(word) is None, word
    assert cat.entity("software", "S0367")["techniques"]


def test_build_from_a_stix_bundle():
    bundle = {
        "objects": [
            {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "99.0"},
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--c2",
                "name": "Command and Control",
                "x_mitre_shortname": "command-and-control",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0011"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--a",
                "name": "Application Layer Protocol",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
                ],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--old",
                "name": "Gone",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}],
            },
            {
                "type": "malware",
                "id": "malware--m",
                "name": "BadThing",
                "x_mitre_aliases": ["BadThing", "Nasty"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "S9999"}],
            },
            {
                "type": "relationship",
                "id": "relationship--r",
                "relationship_type": "uses",
                "source_ref": "malware--m",
                "target_ref": "attack-pattern--a",
            },
        ]
    }
    data = attack.build(bundle)
    assert data["version"] == "99.0"
    assert data["tactics"] == [["TA0011", "command-and-control", "Command and Control"]]
    assert set(data["techniques"]) == {"T1071"}
    assert data["software"]["S9999"] == ["BadThing", ["BadThing", "Nasty"], ["T1071"], "malware"]
    cat = attack.Catalogue(data)
    assert cat.match_tag("nasty") == Indicator(Kind.SOFTWARE, "S9999")


def test_extract_and_classify_technique_ids():
    found = extract("The actor used T1566.001 for access, then T1059 and CVE-2024-3400. Not T99 or AT1234x.")
    keys = [i.key for i in found]
    assert "technique:T1566.001" in keys and "technique:T1059" in keys and "cve:CVE-2024-3400" in keys
    assert classify("t1071.001") == Indicator(Kind.TECHNIQUE, "T1071.001")


def test_ingested_report_maps_techniques(make_engine):
    engine = make_engine()
    engine.ingest(
        "Spearphishing (T1566.001) delivered a loader that beaconed over HTTPS (T1071.001).", "apt.txt"
    )
    node = engine.store.node("technique:T1566.001")
    assert node["attrs"]["attack.name"] == "Phishing: Spearphishing Attachment"
    s = attack.summary(engine.store)
    initial = next(t for t in s["tactics"] if t["short"] == "initial-access")
    assert [(t["id"], t["basis"]) for t in initial["techniques"]] == [("T1566.001", ["report"])]
    assert s["techniques"] == 2 and s["indicators"] == 1


def test_otx_attack_ids_tags_and_families_become_techniques(make_engine, transport):
    transport.add(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/45.155.205.20/general",
        body={
            "pulse_info": {
                "pulses": [
                    {
                        "name": "Emotet C2",
                        "tags": ["c2"],
                        "malware_families": [{"display_name": "Emotet"}],
                        "attack_ids": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "bogus"}],
                    }
                ]
            }
        },
    )
    engine = make_engine(enabled=["otx"])
    engine.config.keys = {"otx": "k"}
    engine.sources = [OTX()]
    engine.investigate([classify("45.155.205.20")], depth=0)
    techs = {t["id"]: t for t in attack.techniques_of(engine.store, "ip:45.155.205.20", associated=False)}
    assert techs["T1071.001"]["basis"] == ["reported"]
    assert techs["T1071"]["basis"] == ["inferred"]  # from the "c2" tag
    assert "bogus" not in techs
    edges = {(e["rel"], e["dst"]) for e in engine.store.edges_of("ip:45.155.205.20")}
    assert ("associated_with", "software:S0367") in edges
    with_assoc = attack.techniques_of(engine.store, "ip:45.155.205.20")
    assert any(t["basis"] == ["associated"] and t["via"] == ["Emotet"] for t in with_assoc)
    d = attack.detail(engine.store, "T1071.001")
    assert d["indicators"][0]["key"] == "ip:45.155.205.20"
    assert "reported" in d["indicators"][0]["basis"]


def test_urlhaus_threat_maps_to_ingress_tool_transfer(make_engine, transport):
    transport.add(
        "https://urlhaus-api.abuse.ch/v1/url/",
        body={"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["exe"]},
    )
    engine = make_engine()
    engine.config.keys = {"urlhaus": "k"}
    f = URLhaus().lookup(classify("http://bad.example/a.exe"), Context(engine.fetcher, engine.config))
    assert {r.dst.value for r in f.relations if r.rel == "tagged"} == {"malware_download", "exe"}
    url = classify("http://bad.example/a.exe")
    engine._save_relation(Relation(url, "tagged", Indicator(Kind.TAG, "malware_download")), "urlhaus", set())
    assert [t["id"] for t in attack.techniques_of(engine.store, url.key)] == ["T1105"]


def _linked_engine(make_engine, lists):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    engine.investigate([classify("203.0.113.66")], depth=0)
    engine.link_technique(classify("203.0.113.66"), "T1071.001", "uses_technique", "test")
    return engine


def test_stix_export_carries_mitre_attack_patterns(make_engine, lists):
    engine = _linked_engine(make_engine, lists)
    bundle = json.loads(export.to_stix(engine.store))
    patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert len(patterns) == 1
    p = patterns[0]
    assert (
        p["id"] == attack.catalogue().technique("T1071.001")["stix_id"]
    )  # MITRE's own id: merges in OpenCTI
    assert p["external_references"][0] == {
        "source_name": "mitre-attack",
        "external_id": "T1071.001",
        "url": "https://attack.mitre.org/techniques/T1071/001",
    }
    rel = next(o for o in bundle["objects"] if o["type"] == "relationship" and o["target_ref"] == p["id"])
    assert rel["relationship_type"] == "indicates" and rel["source_ref"].startswith("indicator--")


def test_navigator_layer(make_engine, lists):
    engine = _linked_engine(make_engine, lists)
    layer = attack.navigator_layer(engine.store)
    assert (
        layer["domain"] == "enterprise-attack"
        and layer["versions"]["attack"] == attack.catalogue().version.split(".")[0]
    )
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1071.001"]
    assert "1 malicious" in layer["techniques"][0]["comment"]


def test_cli_attack(make_engine, lists, capsys, tmp_path, monkeypatch):
    engine = _linked_engine(make_engine, lists)
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: engine)
    monkeypatch.setattr(engine.store, "close", lambda: None)
    assert main(["attack"]) == 0
    out = capsys.readouterr().out
    assert "Command and Control (TA0011)" in out and "T1071.001" in out
    assert main(["attack", "T1071.001"]) == 0
    assert "ip:203.0.113.66" in capsys.readouterr().out
    assert main(["attack", "--indicator", "203.0.113.66"]) == 0
    assert "reported" in capsys.readouterr().out
    layer = tmp_path / "layer.json"
    assert main(["attack", "navigator", "-o", str(layer)]) == 0
    assert json.loads(layer.read_text())["techniques"]
    assert main(["show", "203.0.113.66"]) == 0
    assert "MITRE ATT&CK" in capsys.readouterr().out


def test_user_copy_of_the_catalogue_takes_precedence(tmp_path, monkeypatch):
    data = attack.load_data()
    data["version"] = "123.4"
    target = attack.save(data, tmp_path / "attack.json.gz")
    monkeypatch.setattr(attack, "USER_COPY", target)
    attack._cached = None
    try:
        assert attack.catalogue().version == "123.4"
    finally:
        attack._cached = None
