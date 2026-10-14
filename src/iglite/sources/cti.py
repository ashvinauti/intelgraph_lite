"""Threat-intelligence reputation sources that need a (free) API key."""

from __future__ import annotations

import base64
from urllib.parse import quote

from .. import attack
from ..extract import classify
from ..model import Evidence, Finding, Indicator, Kind, Relation, Verdict
from .base import Context, Source, latest, parse_time


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
        link = f"https://otx.alienvault.com/indicator/{section.lower()}/{ind.value}"
        finding = Finding(attributes={"otx_pulses": len(pulses)})
        if pulses:
            names = ", ".join(p.get("name", "?") for p in pulses[:3])
            finding.evidence.append(
                Evidence(
                    self.name,
                    Verdict.MALICIOUS,
                    f"in {len(pulses)} OTX pulse(s): {names}",
                    confidence=min(1.0, 0.4 + 0.15 * len(pulses)),
                    url=link,
                    # Pulses are often years old; date the sighting by the newest one.
                    last_seen=latest(p.get("modified") or p.get("created") for p in pulses),
                )
            )
        # OTX's own counter-signals: known-good lists (e.g. popular domains, its
        # whitelist) and community false-positive reports.
        if validation := data.get("validation") or []:
            why = "; ".join(str(v.get("message") or v.get("name") or v.get("source")) for v in validation[:3])
            finding.evidence.append(
                Evidence("otx_validation", Verdict.BENIGN, f"OTX validation: {why}", 0.7, link)
            )
        if reports := data.get("false_positive") or []:
            finding.evidence.append(
                Evidence(
                    "otx_validation",
                    Verdict.BENIGN,
                    f"{len(reports)} OTX false-positive report(s)",
                    0.8,
                    link,
                )
            )
        tags = {t.lower() for p in pulses for t in p.get("tags", [])}
        families = {
            (f.get("display_name") or "").lower() for p in pulses for f in p.get("malware_families", [])
        }
        for tag in sorted((tags | families) - {""})[:10]:
            finding.relations.append(Relation(ind, "tagged", Indicator(Kind.TAG, tag), pivot=False))
        # Pulse authors map their reports to ATT&CK; keep those techniques as reported.
        for tid in attack.ids_in(a for p in pulses for a in p.get("attack_ids") or [])[:20]:
            finding.relations.append(
                Relation(ind, "uses_technique", Indicator(Kind.TECHNIQUE, tid), pivot=False)
            )
        return finding


class VirusTotal(Source):
    name = "virustotal"
    kinds = frozenset({Kind.IP, Kind.DOMAIN, Kind.URL, Kind.HASH})
    trust = 0.8
    ttl = 24 * 3600
    needs_key = True
    description = "VirusTotal engine verdicts (VIRUSTOTAL_API_KEY; free tier is 4 req/min)"
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
        seen = parse_time(attrs.get("last_analysis_date"))
        # One or two engines out of ~90 is routine noise (heuristics, stale
        # signatures); real detections are usually broad.
        if bad >= 5:
            finding.evidence.append(
                Evidence(
                    self.name,
                    Verdict.MALICIOUS,
                    f"{bad}/{total} engines flag it",
                    min(1.0, bad / 10),
                    link,
                    seen,
                )
            )
        elif bad >= 2 or (bad == 1 and sus >= 2):
            finding.evidence.append(
                Evidence(
                    self.name,
                    Verdict.SUSPICIOUS,
                    f"{bad} malicious, {sus} suspicious of {total}",
                    0.3 + 0.1 * bad,
                    link,
                    seen,
                )
            )
        elif bad == 0 and sus == 0 and total >= 50 and attrs.get("reputation", 0) >= 0:
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
                    None if online else latest(u.get("date_added") for u in urls),
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
                    None
                    if status == "online"
                    else parse_time(data.get("last_online") or data.get("date_added")),
                )
            )
            for p in (data.get("payloads") or [])[:10]:
                if sha := p.get("response_sha256"):
                    finding.relations.append(Relation(ind, "serves", Indicator(Kind.HASH, sha.lower())))
        else:
            sig = data.get("signature") or "malware payload"
            finding.evidence.append(
                Evidence(
                    self.name,
                    Verdict.MALICIOUS,
                    f"known {sig}",
                    0.9,
                    None,
                    parse_time(data.get("lastseen") or data.get("firstseen")),
                )
            )
            for u in (data.get("urls") or [])[:10]:
                if (url := classify(u.get("url", ""))) is not None:
                    finding.relations.append(Relation(url, "serves", ind, pivot=False))
        threat = [data["threat"]] if isinstance(data.get("threat"), str) else []
        for tag in dict.fromkeys([*threat, *(data.get("tags") or [])[:10]]):
            finding.relations.append(
                Relation(ind, "tagged", Indicator(Kind.TAG, str(tag).lower()), pivot=False)
            )
        return finding


class Shodan(Source):
    name = "shodan"
    kinds = frozenset({Kind.IP})
    trust = 0.6
    ttl = 24 * 3600
    needs_key = True
    description = "Shodan host data: owner, ASN, ports, CVEs, tags (SHODAN_API_KEY)"
    rate_limits = {"api.shodan.io": 1.0}  # API allows about 1 request/second

    MALICIOUS_TAGS = {"c2", "malware", "compromised", "doublepulsar"}
    # VPN, proxy and honeypot tags describe a service, not an attack, and fire
    # constantly for ordinary privacy tools, so they are kept as attributes only.
    SUSPICIOUS_TAGS = {"tor": 0.4, "scanner": 0.3}

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        # The key travels as a query parameter but is kept out of the cache key.
        data = ctx.fetcher.json(
            f"https://api.shodan.io/shodan/host/{quote(ind.value)}?minify=true",
            ttl=ctx.ttl(self),
            secret_params={"key": ctx.config.key(self.name) or ""},
        )
        if not data or "ip_str" not in data:
            return None
        tags = {str(t).lower() for t in data.get("tags") or []}
        vulns = sorted(data.get("vulns") or [])
        finding = Finding(
            attributes={
                k: v
                for k, v in {
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                    "country": data.get("country_name"),
                    "os": data.get("os"),
                    "ports": data.get("ports") or [],
                    "tags": sorted(tags),
                    "vulns": len(vulns),
                    "last_update": data.get("last_update"),
                }.items()
                if v not in (None, "", [])
            }
        )
        link, seen = f"https://www.shodan.io/host/{ind.value}", parse_time(data.get("last_update"))
        if bad := tags & self.MALICIOUS_TAGS:
            finding.evidence.append(
                Evidence(self.name, Verdict.MALICIOUS, f"tagged {', '.join(sorted(bad))}", 0.8, link, seen)
            )
        elif odd := tags & self.SUSPICIOUS_TAGS.keys():
            conf = max(self.SUSPICIOUS_TAGS[t] for t in odd)
            finding.evidence.append(
                Evidence(self.name, Verdict.SUSPICIOUS, f"tagged {', '.join(sorted(odd))}", conf, link, seen)
            )
        if org := data.get("org"):
            finding.relations.append(Relation(ind, "operated_by", Indicator(Kind.ORG, str(org)), pivot=False))
        if (asn := classify(str(data.get("asn") or ""))) is not None and asn.kind is Kind.ASN:
            finding.relations.append(Relation(ind, "announced_by", asn, pivot=False))
        for host in (data.get("hostnames") or [])[:10]:
            if (dom := classify(host)) is not None and dom.kind is Kind.DOMAIN:
                finding.relations.append(Relation(dom, "resolves_to", ind))
        for cve in vulns[:20]:
            if (c := classify(cve)) is not None:
                finding.relations.append(Relation(ind, "has_vuln", c, pivot=False))
        return finding
