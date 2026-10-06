from iglite.extract import classify, derive, extract, is_public, refang
from iglite.model import Indicator, Kind


def test_refang_common_styles():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("bad(dot)example[.]org") == "bad.example.org"
    assert refang("user[@]mail[.]com") == "user@mail.com"


def test_classify_each_kind():
    assert classify("8.8.8.8") == Indicator(Kind.IP, "8.8.8.8")
    assert classify("2001:DB8::1") == Indicator(Kind.IP, "2001:db8::1")
    assert classify("Example.COM.") == Indicator(Kind.DOMAIN, "example.com")
    assert classify("hxxp://Evil[.]Example/x?y=1") == Indicator(Kind.URL, "http://evil.example/x?y=1")
    assert classify("d41d8cd98f00b204e9800998ecf8427e").kind is Kind.HASH
    assert classify("cve-2024-3400") == Indicator(Kind.CVE, "CVE-2024-3400")
    assert classify("as13335") == Indicator(Kind.ASN, "AS13335")
    assert classify("Admin@Example.com") == Indicator(Kind.EMAIL, "admin@example.com")
    assert classify("not an indicator") is None
    assert classify("report.pdf") is None


def test_url_normalisation_strips_credentials_and_keeps_port():
    assert classify("http://user:pw@Host.example:8080/p").value == "http://host.example:8080/p"
    assert classify("http://[2001:db8::1]/x").value == "http://[2001:db8::1]/x"


def test_extract_from_report_text():
    text = """
    The actor used hxxps://login-portal[.]example/auth to phish users and
    staged payloads on 203.0.113[.]66. Dropper SHA256:
    9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    It exploits CVE-2024-3400. See setup.exe and notes.txt (not indicators).
    Contact: ops@actor-mail.example. Version 1.2.3.4.5 is not an IP.
    """
    keys = [i.key for i in extract(text)]
    assert "url:https://login-portal.example/auth" in keys
    assert "ip:203.0.113.66" in keys
    assert "hash:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in keys
    assert "cve:CVE-2024-3400" in keys
    assert "email:ops@actor-mail.example" in keys
    assert not any(k.endswith((".exe", ".txt")) for k in keys)
    # The URL's host is not double-reported as a bare domain.
    assert "domain:login-portal.example" not in keys
    assert len(keys) == len(set(keys))


def test_private_addresses_are_not_public():
    assert not is_public(Indicator(Kind.IP, "10.0.0.5"))
    assert not is_public(Indicator(Kind.IP, "127.0.0.1"))
    assert not is_public(Indicator(Kind.DOMAIN, "fileserver.corp"))
    assert is_public(Indicator(Kind.IP, "8.8.8.8"))


def test_derive_url_and_email():
    (rel,) = derive(Indicator(Kind.URL, "http://evil.example/x"))
    assert (rel.rel, rel.dst) == ("hosted_on", Indicator(Kind.DOMAIN, "evil.example"))
    (rel,) = derive(Indicator(Kind.EMAIL, "a@b.example"))
    assert rel.dst == Indicator(Kind.DOMAIN, "b.example")
