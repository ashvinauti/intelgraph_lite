"""Indicator extraction, normalisation and local derivation.

This is the OSINT entry point: give it the text of a blog post, advisory or
paste and it returns the indicators inside, after undoing common "defanging"
(``hxxp``, ``[.]``, ``(dot)``). It also derives relations that need no
network call at all, e.g. a URL is hosted on its domain.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .model import Indicator, Kind, Relation

_REFANG = [
    (re.compile(r"h[xX]{2}p(s?)", re.I), r"http\1"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]|\(\s*at\s*\)|\[\s*at\s*\]", re.I), "@"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]

_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]{0,4}(?![\w:])")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,23}\b")
_HASH = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_ASN = re.compile(r"^AS(\d{1,10})$", re.I)

# Things that look like domains in prose but are almost always file names.
_FILE_SUFFIXES = frozenset(
    "exe dll sys bat cmd ps1 vbs txt log json yaml yml xml html htm php js css png jpg "
    "jpeg gif svg zip rar 7z gz tar doc docx xls xlsx ppt pptx pdf py sh tmp dat bin ini "
    "cfg conf lnk iso msi jar apk".split()
)


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def _norm_domain(value: str) -> str | None:
    value = value.strip().strip(".").lower()
    if not value or "." not in value or len(value) > 253:
        return None
    if value.rsplit(".", 1)[1] in _FILE_SUFFIXES:
        return None
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _norm_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _norm_url(value: str) -> str | None:
    value = value.strip().rstrip(".,;")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        return None
    host = parts.hostname  # already lower-cased, credentials stripped
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port else host
    rebuilt = f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}"
    if parts.query:
        rebuilt += f"?{parts.query}"
    return rebuilt


def classify(raw: str) -> Indicator | None:
    """Turn one user-supplied value into an indicator, or ``None``."""
    value = refang(raw.strip()).rstrip(".")
    if not value:
        return None
    if _CVE.fullmatch(value):
        return Indicator(Kind.CVE, value.upper())
    if m := _ASN.match(value):
        return Indicator(Kind.ASN, f"AS{m.group(1)}")
    if value.lower().startswith(("http://", "https://", "ftp://")):
        url = _norm_url(value)
        return Indicator(Kind.URL, url) if url else None
    if ip := _norm_ip(value):
        return Indicator(Kind.IP, ip)
    if _HASH.fullmatch(value):
        return Indicator(Kind.HASH, value.lower())
    if _EMAIL.fullmatch(value):
        local, _, domain = value.rpartition("@")
        domain = _norm_domain(domain)
        return Indicator(Kind.EMAIL, f"{local.lower()}@{domain}") if domain else None
    if _DOMAIN.fullmatch(value):
        domain = _norm_domain(value)
        return Indicator(Kind.DOMAIN, domain) if domain else None
    return None


def extract(text: str) -> list[Indicator]:
    """Return every distinct indicator found in free text, in order of appearance."""
    text = refang(text)
    found: dict[str, Indicator] = {}

    def add(ind: Indicator | None) -> None:
        if ind is not None:
            found.setdefault(ind.key, ind)

    # Remove each match from the text so a URL's host isn't also reported as
    # a bare domain unless it appears on its own elsewhere.
    for pattern, norm in (
        (_URL, lambda v: classify(v)),
        (_EMAIL, lambda v: classify(v)),
        (_CVE, lambda v: Indicator(Kind.CVE, v.upper())),
        (_HASH, lambda v: Indicator(Kind.HASH, v.lower())),
        (_IPV4, lambda v: Indicator(Kind.IP, ip) if (ip := _norm_ip(v)) else None),
        (_IPV6, lambda v: Indicator(Kind.IP, ip) if (ip := _norm_ip(v)) else None),
        (_DOMAIN, lambda v: Indicator(Kind.DOMAIN, d) if (d := _norm_domain(v)) else None),
    ):
        for match in pattern.finditer(text):
            add(norm(match.group(0)))
        text = pattern.sub(" ", text)
    return list(found.values())


def is_public(ind: Indicator) -> bool:
    """False for private, loopback, reserved addresses and internal names.

    Non-public indicators are never sent to third-party services: it would
    waste a request and leak internal infrastructure.
    """
    if ind.kind is Kind.IP:
        return ipaddress.ip_address(ind.value).is_global
    if ind.kind is Kind.DOMAIN:
        return not ind.value.endswith((".local", ".internal", ".lan", ".corp", ".localhost"))
    return True


def derive(ind: Indicator) -> list[Relation]:
    """Relations implied by the indicator's own structure (no lookups)."""
    if ind.kind is Kind.URL:
        host = urlsplit(ind.value).hostname or ""
        target = classify(host)
        if target is not None and target.kind in (Kind.DOMAIN, Kind.IP):
            return [Relation(ind, "hosted_on", target)]
    if ind.kind is Kind.EMAIL:
        return [Relation(ind, "uses_domain", Indicator(Kind.DOMAIN, ind.value.rpartition("@")[2]))]
    return []
