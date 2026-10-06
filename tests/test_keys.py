"""API key handling: .env files, variable aliases, Shodan, and keys never stored."""

import pytest

from iglite import config
from iglite.config import Config, read_dotenv
from iglite.extract import classify
from iglite.fetch import Fetcher, FetchError
from iglite.model import Verdict
from iglite.sources import build
from iglite.sources.base import Context
from iglite.sources.cti import Shodan
from iglite.store import Store

DUMMY = "dummy-key-123"


def test_dotenv_parsing(tmp_path):
    f = tmp_path / ".env"
    f.write_text(
        "# --- API Keys ---\n"
        "SHODAN_API_KEY=abc   \n"  # trailing spaces, as pasted
        'export OTX_API_KEY="quoted value"\n'
        "VIRUSTOTAL_API_KEY=xyz # comment\n"
        "EMPTY=\n"
        "not a pair\n"
    )
    assert read_dotenv(f) == {
        "SHODAN_API_KEY": "abc",
        "OTX_API_KEY": "quoted value",
        "VIRUSTOTAL_API_KEY": "xyz",
        "EMPTY": "",
    }


def test_dotenv_loaded_and_real_env_wins(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("SHODAN_API_KEY=from-file\nVIRUSTOTAL_API_KEY=vt-file\nOTX_API_KEY=\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    for var in (
        "SHODAN_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "VT_API_KEY",
        "OTX_API_KEY",
        "IGLITE_CONFIG",
        "IGLITE_ENV_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SHODAN_API_KEY", "from-env")
    cfg = config.load()
    assert cfg.keys == {"shodan": "from-env", "virustotal": "vt-file"}  # empty OTX stays off


def test_aliases_and_whitespace():
    cfg = config.load(env={"VIRUSTOTAL_API_KEY": f"  {DUMMY} ", "OTX_API_KEY": DUMMY})
    assert cfg.keys == {"virustotal": DUMMY, "otx": DUMMY}
    assert config.load(env={"VT_API_KEY": "a", "VIRUSTOTAL_API_KEY": "b"}).keys["virustotal"] == "a"


def test_keyed_sources_switch_on():
    names = {s.name for s in build(Config(keys={"shodan": DUMMY, "virustotal": DUMMY, "otx": DUMMY}))}
    assert {"shodan", "virustotal", "otx"} <= names
    assert "shodan" not in {s.name for s in build(Config())}


SHODAN_HOST = {
    "ip_str": "45.155.205.20",
    "org": "Example Hosting",
    "isp": "Example ISP",
    "asn": "AS64500",
    "country_name": "Netherlands",
    "ports": [22, 443],
    "hostnames": ["cnc.example"],
    "tags": ["c2"],
    "vulns": ["CVE-2021-44228"],
    "last_update": "2026-10-01T00:00:00",
}


def _ctx(transport, store=None):
    store = store or Store()
    return Context(Fetcher(store, transport=transport), Config(db=":memory:", keys={"shodan": DUMMY})), store


def test_shodan_parse_and_key_not_stored(transport):
    transport.add("https://api.shodan.io/shodan/host/45.155.205.20", body=SHODAN_HOST)
    ctx, store = _ctx(transport)
    f = Shodan().lookup(classify("45.155.205.20"), ctx)
    assert f.evidence[0].verdict is Verdict.MALICIOUS and "c2" in f.evidence[0].detail
    assert f.attributes["org"] == "Example Hosting" and f.attributes["vulns"] == 1
    rels = {(r.rel, r.dst.key if r.src.value == "45.155.205.20" else r.src.key) for r in f.relations}
    assert ("operated_by", "org:Example Hosting") in rels
    assert ("announced_by", "asn:AS64500") in rels
    assert ("resolves_to", "domain:cnc.example") in rels
    assert ("has_vuln", "cve:CVE-2021-44228") in rels
    # The key was sent...
    assert transport.calls == [f"https://api.shodan.io/shodan/host/45.155.205.20?minify=true&key={DUMMY}"]
    # ...but never written to the database.
    rows = store._query("SELECT key FROM cache")
    assert rows and all(DUMMY not in r["key"] for r in rows)


def test_bad_key_is_reported_and_not_cached(transport):
    transport.add("https://api.shodan.io/", status=401, body={"error": "Invalid API key"})
    ctx, store = _ctx(transport)
    with pytest.raises(FetchError, match="check the API key") as err:
        Shodan().lookup(classify("45.155.205.20"), ctx)
    assert DUMMY not in str(err.value)
    assert store._query("SELECT COUNT(*) FROM cache")[0][0] == 0
