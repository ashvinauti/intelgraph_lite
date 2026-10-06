"""Free, keyless OSINT sources: DNS, RDAP, certificate transparency, Shodan InternetDB."""

from __future__ import annotations

import socket
import time
from datetime import UTC, datetime
from urllib.parse import quote

from ..extract import classify
from ..model import Evidence, Finding, Indicator, Kind, Relation, Verdict
from .base import Context, Source


class DNS(Source):
    name = "dns"
    kinds = frozenset({Kind.DOMAIN})
    ttl = 6 * 3600
    trust = 0.0
    description = "Resolve A/AAAA records with the system resolver"

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        def resolve() -> list[str]:
            try:
                infos = socket.getaddrinfo(ind.value, None, proto=socket.IPPROTO_TCP)
            except (socket.gaierror, UnicodeError):
                return []
            return sorted({info[4][0] for info in infos})

        addresses = ctx.fetcher.memo(f"dns {ind.value}", ctx.ttl(self), resolve)
        if addresses is None:
            return None
        finding = Finding(attributes={"resolves": bool(addresses)})
        for addr in addresses[:16]:
            if (ip := classify(addr)) is not None:
                finding.relations.append(Relation(ind, "resolves_to", ip))
        return finding


class RDAP(Source):
    name = "rdap"
    kinds = frozenset({Kind.DOMAIN, Kind.IP})
    ttl = 7 * 86400
    trust = 0.3
    description = "Registration data (registrar, age, network owner) via rdap.org"
    young_days = 30

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        path = "ip" if ind.kind is Kind.IP else "domain"
        data = ctx.fetcher.json(f"https://rdap.org/{path}/{quote(ind.value)}", ttl=ctx.ttl(self))
        if not data:
            return None
        finding = Finding()
        if ind.kind is Kind.IP:
            for key in ("name", "country", "handle", "startAddress", "endAddress"):
                if data.get(key):
                    finding.attributes[f"net_{key}"] = data[key]
            if owner := _entity_name(data, "registrant"):
                finding.relations.append(
                    Relation(ind, "allocated_to", Indicator(Kind.ORG, owner), pivot=False)
                )
            return finding

        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        if created := _parse_date(events.get("registration")):
            age = (time.time() - created.timestamp()) / 86400
            finding.attributes["registered"] = created.date().isoformat()
            finding.attributes["age_days"] = int(age)
            if age < self.young_days:
                finding.evidence.append(
                    Evidence(
                        self.name,
                        Verdict.SUSPICIOUS,
                        f"domain registered {int(age)} days ago",
                        confidence=0.6,
                    )
                )
        if registrar := _entity_name(data, "registrar"):
            finding.attributes["registrar"] = registrar
            finding.relations.append(
                Relation(ind, "registered_via", Indicator(Kind.ORG, registrar), pivot=False)
            )
        return finding


class CertTransparency(Source):
    name = "crtsh"
    kinds = frozenset({Kind.DOMAIN})
    ttl = 3 * 86400
    trust = 0.0
    description = "Subdomains seen in certificate transparency logs (crt.sh)"
    max_names = 25

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        if ind.value.count(".") > 2:  # only enumerate apex-ish names
            return None
        url = f"https://crt.sh/?q={quote('%.' + ind.value)}&output=json&exclude=expired"
        rows = ctx.fetcher.json(url, ttl=ctx.ttl(self))
        if not rows:
            return None
        names: set[str] = set()
        for row in rows:
            for name in str(row.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name != ind.value and name.endswith("." + ind.value):
                    names.add(name)
        finding = Finding(attributes={"ct_subdomains": len(names)})
        for name in sorted(names)[: self.max_names]:
            if (sub := classify(name)) is not None:
                # Subdomains are recorded but not auto-expanded: they are
                # numerous and rarely change the parent's verdict.
                finding.relations.append(Relation(ind, "has_subdomain", sub, pivot=False))
        return finding


class InternetDB(Source):
    name = "internetdb"
    kinds = frozenset({Kind.IP})
    ttl = 86400
    trust = 0.6
    description = "Open ports, hostnames, CVEs and tags from Shodan InternetDB (free)"

    MALICIOUS_TAGS = {"c2", "malware", "compromised"}
    SUSPICIOUS_TAGS = {"tor", "proxy", "vpn", "scanner", "honeypot"}

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        data = ctx.fetcher.json(f"https://internetdb.shodan.io/{ind.value}", ttl=ctx.ttl(self))
        if not data or "ip" not in data:
            return None
        tags = set(data.get("tags") or [])
        finding = Finding(
            attributes={
                "ports": data.get("ports") or [],
                "tags": sorted(tags),
                "cpes": data.get("cpes") or [],
            }
        )
        if bad := tags & self.MALICIOUS_TAGS:
            finding.evidence.append(
                Evidence(self.name, Verdict.MALICIOUS, f"tagged {', '.join(sorted(bad))}", 0.8)
            )
        elif odd := tags & self.SUSPICIOUS_TAGS:
            finding.evidence.append(
                Evidence(self.name, Verdict.SUSPICIOUS, f"tagged {', '.join(sorted(odd))}", 0.5)
            )
        for host in (data.get("hostnames") or [])[:10]:
            if (dom := classify(host)) is not None and dom.kind is Kind.DOMAIN:
                finding.relations.append(Relation(dom, "resolves_to", ind))
        for cve in (data.get("vulns") or [])[:20]:
            if (c := classify(cve)) is not None:
                finding.relations.append(Relation(ind, "has_vuln", c, pivot=False))
        return finding


def _entity_name(data: dict, role: str) -> str | None:
    for entity in data.get("entities", []):
        if role in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn" and item[3]:
                    return str(item[3]).strip()
            if entity.get("handle"):
                return str(entity["handle"])
    return None


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
