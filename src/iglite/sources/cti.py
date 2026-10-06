"""Threat-intelligence reputation sources that need a (free) API key."""

from __future__ import annotations

import base64
from urllib.parse import quote

from ..extract import classify
from ..model import Evidence, Finding, Indicator, Kind, Relation, Verdict
from .base import Context, Source


class OTX(Source):
    name = "otx"
    kinds = frozenset({Kind.IP, Kind.DOMAIN, Kind.URL, Kind.HASH, Kind.CVE})
    trust = 0.6
    ttl = 12 * 3600
    needs_key = True
    description = "AlienVault OTX pulse membership (OTX_API_KEY)"

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        section = {
            Kind.DOMAIN: "domain",
            Kind.URL: "url",
            Kind.HASH: "file",
            Kind.CVE: "cve",
        }.get(ind.kind) or ("IPv6" if ":" in ind.value else "IPv4")
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(ind.value, safe='')}/general"
        data = ctx.fetcher.json(
            url, ttl=ctx.ttl(self), headers={"X-OTX-API-KEY": ctx.config.key(self.name) or ""}
        )
        if not data:
            return None
        pulses = (data.get("pulse_info") or {}).get("pulses") or []
        finding = Finding(attributes={"otx_pulses": len(pulses)})
        if pulses:
            names = ", ".join(p.get("name", "?") for p in pulses[:3])
            finding.evidence.append(
                Evidence(
                    self.name,
                    Verdict.MALICIOUS,
                    f"in {len(pulses)} OTX pulse(s): {names}",
                    confidence=min(1.0, 0.4 + 0.15 * len(pulses)),
                    url=f"https://otx.alienvault.com/indicator/{section.lower()}/{ind.value}",
                )
            )
        tags = {t.lower() for p in pulses for t in p.get("tags", [])}
        families = {
            (f.get("display_name") or "").lower() for p in pulses for f in p.get("malware_families", [])
        }
        for tag in sorted((tags | families) - {""})[:10]:
            finding.relations.append(Relation(ind, "tagged", Indicator(Kind.TAG, tag), pivot=False))
        return finding


class VirusTotal(Source):
    name = "virustotal"
    kinds = frozenset({Kind.IP, Kind.DOMAIN, Kind.URL, Kind.HASH})
    trust = 0.8
    ttl = 24 * 3600
    needs_key = True
    description = "VirusTotal engine verdicts (VT_API_KEY, free tier is 4 req/min)"
    rate_limits = {"www.virustotal.com": 15.0}
    API_PATH = {Kind.IP: "ip_addresses", Kind.DOMAIN: "domains", Kind.HASH: "files"}
    GUI_PATH = {Kind.IP: "ip-address", Kind.DOMAIN: "domain", Kind.HASH: "file", Kind.URL: "search"}

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        if ind.kind is Kind.URL:
            path = "urls/" + base64.urlsafe_b64encode(ind.value.encode()).decode().rstrip("=")
        else:
            path = self.API_PATH[ind.kind] + "/" + quote(ind.value)
        link = f"https://www.virustotal.com/gui/{self.GUI_PATH[ind.kind]}/{quote(ind.value, safe='')}"
        data = ctx.fetcher.json(
            f"https://www.virustotal.com/api/v3/{path}",
            ttl=ctx.ttl(self),
            headers={"x-apikey": ctx.config.key(self.name) or ""},
        )
        attrs = ((data or {}).get("data") or {}).get("attributes")
        if not attrs:
            return None
        stats = attrs.get("last_analysis_stats") or {}
        bad, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0) + stats.get("undetected", 0)
        total = bad + sus + harmless
        finding = Finding(attributes={"vt_detections": f"{bad}/{total}"})
        if bad >= 3:
            finding.evidence.append(
                Evidence(
                    self.name, Verdict.MALICIOUS, f"{bad}/{total} engines flag it", min(1.0, bad / 10), link
                )
            )
        elif bad or sus >= 2:
            finding.evidence.append(
                Evidence(
                    self.name, Verdict.SUSPICIOUS, f"{bad} malicious, {sus} suspicious of {total}", 0.5, link
                )
            )
        elif total >= 50 and attrs.get("reputation", 0) >= 0:
            finding.evidence.append(
                Evidence(self.name, Verdict.BENIGN, f"0/{total} engines flag it", 0.5, link)
            )
        return finding


class URLhaus(Source):
    name = "urlhaus"
    kinds = frozenset({Kind.IP, Kind.DOMAIN, Kind.URL, Kind.HASH})
    trust = 0.8
    ttl = 6 * 3600
    needs_key = True
    description = "abuse.ch URLhaus malware distribution database (ABUSECH_AUTH_KEY)"

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        if ind.kind is Kind.HASH and len(ind.value) not in (32, 64):
            return None
        endpoint, form = {
            Kind.URL: ("url", {"url": ind.value}),
            Kind.HASH: ("payload", {("sha256_hash" if len(ind.value) == 64 else "md5_hash"): ind.value}),
        }.get(ind.kind, ("host", {"host": ind.value}))
        data = ctx.fetcher.json(
            f"https://urlhaus-api.abuse.ch/v1/{endpoint}/",
            ttl=ctx.ttl(self),
            method="POST",
            form=form,
            headers={"Auth-Key": ctx.config.key(self.name) or ""},
        )
        if not data or data.get("query_status") != "ok":
            return None
        finding = Finding()
        ref = data.get("urlhaus_reference")
        if ind.kind in (Kind.IP, Kind.DOMAIN):
            urls = data.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            finding.evidence.append(
                Evidence(
                    self.name,
                    Verdict.MALICIOUS,
                    f"hosted {len(urls)} malware URL(s), {online} online",
                    0.9 if online else 0.6,
                    ref,
                )
            )
            for u in urls[:10]:
                if (url := classify(u.get("url", ""))) is not None:
                    finding.relations.append(Relation(url, "hosted_on", ind, pivot=False))
        elif ind.kind is Kind.URL:
            status = data.get("url_status", "unknown")
            finding.evidence.append(
                Evidence(
                    self.name,
                    Verdict.MALICIOUS,
                    f"{data.get('threat', 'malware')} URL ({status})",
                    0.9 if status == "online" else 0.7,
                    ref,
                )
            )
            for p in (data.get("payloads") or [])[:10]:
                if sha := p.get("response_sha256"):
                    finding.relations.append(Relation(ind, "serves", Indicator(Kind.HASH, sha.lower())))
        else:
            sig = data.get("signature") or "malware payload"
            finding.evidence.append(Evidence(self.name, Verdict.MALICIOUS, f"known {sig}", 0.9))
            for u in (data.get("urls") or [])[:10]:
                if (url := classify(u.get("url", ""))) is not None:
                    finding.relations.append(Relation(url, "serves", ind, pivot=False))
        for tag in (data.get("tags") or [])[:10]:
            finding.relations.append(
                Relation(ind, "tagged", Indicator(Kind.TAG, str(tag).lower()), pivot=False)
            )
        return finding
