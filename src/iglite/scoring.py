"""Explainable scoring.

The score is a log-odds sum, squashed to 0-100:

    z = PRIOR + sum over sources of (trust x confidence x sign(verdict) x SCALE)
                + one capped contribution from malicious neighbours

* Only each source's strongest piece of evidence counts, so a single noisy
  feed cannot outvote independent sources. Corroboration is what pushes an
  indicator over the "malicious" line.
* Benign evidence (allowlists, clean scans) pulls the score down, and if
  trusted sources disagree the assessment is flagged as a contradiction
  instead of silently averaging.
* Every term that moved the score is returned as a ``Reason``.

False-positive controls (all visible in the reasons):

* **Freshness.** Bad evidence fades with age: its weight halves every
  ``half_life_days`` since the source last saw the indicator misbehave
  (floor 10%), so a two-year-old sighting can't convict on its own.
* **Shared infrastructure.** IP-level reputation on large CDN/cloud ranges
  (one IP, thousands of tenants) counts at half weight.
* **Analyst feedback** overrides the computed verdict: "false positive" forces
  benign, "confirmed" forces malicious. The evidence is still listed.

It is a pure function of stored evidence: cheap, deterministic and easy to
re-run after tuning trust weights.
"""

from __future__ import annotations

import math
import time
from collections.abc import Iterable, Mapping

from .model import Assessment, Evidence, Reason, Verdict

PRIOR = -2.0
SCALE = 3.0
SIGN = {Verdict.MALICIOUS: 1.0, Verdict.SUSPICIOUS: 0.5, Verdict.BENIGN: -1.0, Verdict.UNKNOWN: 0.0}
MALICIOUS_AT = 70
SUSPICIOUS_AT = 30
CONTRADICTION_TRUST = 0.5
NEIGHBOUR_WEIGHT = 1.0

HALF_LIFE_DAYS = 180.0
MIN_FRESHNESS = 0.1
SHARED_INFRA_FACTOR = 0.5

# Relations through which guilt-by-association is allowed to flow.
PROPAGATING = frozenset({"resolves_to", "hosted_on", "serves", "uses_domain"})


def freshness(last_seen: float | None, now: float, half_life_days: float = HALF_LIFE_DAYS) -> float:
    if last_seen is None or half_life_days <= 0:
        return 1.0
    age_days = max(0.0, (now - last_seen) / 86400)
    return max(MIN_FRESHNESS, 0.5 ** (age_days / half_life_days))


def _age(last_seen: float, now: float) -> str:
    days = (now - last_seen) / 86400
    if days < 2:
        return "recently"
    if days < 60:
        return f"{int(days)} days ago"
    if days < 730:
        return f"{int(days / 30)} months ago"
    return f"{days / 365:.0f} years ago"


def assess(
    evidence: Iterable[Evidence],
    trust: Mapping[str, float],
    neighbours: Iterable[tuple[str, str]] = (),
    *,
    shared_infra: str | None = None,
    feedback: Mapping[str, str] | None = None,
    half_life_days: float = HALF_LIFE_DAYS,
    now: float | None = None,
) -> Assessment:
    """Score one indicator.

    ``neighbours`` are ``(neighbour_key, rel)`` pairs for adjacent indicators
    that are themselves *directly* malicious (computed by the caller so there
    are no feedback loops). ``shared_infra`` names the CDN/cloud operator when
    the indicator is an IP on shared infrastructure. ``feedback`` is the
    analyst's mark (``{"verdict": ..., "note": ...}``), if any.
    """
    now = time.time() if now is None else now
    strongest: dict[str, tuple[float, Evidence, str]] = {}
    for ev in evidence:
        c = trust.get(ev.source, 0.5) * max(0.0, min(1.0, ev.confidence)) * SIGN[ev.verdict] * SCALE
        if c == 0:
            continue
        notes = []
        if c > 0:  # only accusations fade or get discounted; exonerations stand
            fresh = freshness(ev.last_seen, now, half_life_days)
            if fresh < 0.99:
                c *= fresh
                notes.append(f"last seen {_age(ev.last_seen, now)}, weight {fresh:.0%}")
            if shared_infra:
                c *= SHARED_INFRA_FACTOR
        best = strongest.get(ev.source)
        if best is None or abs(c) > abs(best[0]):
            strongest[ev.source] = (c, ev, "; ".join(notes))

    reasons = [
        Reason(ev.source, ev.verdict, c, f"{ev.detail} ({note})" if note else ev.detail)
        for c, ev, note in strongest.values()
    ]
    if shared_infra and any(r.contribution > 0 for r in reasons):
        reasons.append(
            Reason(
                "context",
                Verdict.UNKNOWN,
                0.0,
                f"shared {shared_infra} infrastructure: IP reputation counted at half weight",
            )
        )
    for key, rel in neighbours:
        reasons.append(Reason("graph", Verdict.SUSPICIOUS, NEIGHBOUR_WEIGHT, f"{rel} malicious {key}"))
        break  # one hop of association is a hint, never a conviction

    z = PRIOR + sum(r.contribution for r in reasons)
    score = round(100 / (1 + math.exp(-z)))

    has_bad = any(
        r.verdict is Verdict.MALICIOUS and trust.get(r.source, 0.5) >= CONTRADICTION_TRUST for r in reasons
    )
    has_good = any(
        r.verdict is Verdict.BENIGN and trust.get(r.source, 0.5) >= CONTRADICTION_TRUST for r in reasons
    )

    if score >= MALICIOUS_AT:
        verdict = Verdict.MALICIOUS
    elif score >= SUSPICIOUS_AT:
        verdict = Verdict.SUSPICIOUS
    elif any(r.verdict is Verdict.BENIGN for r in reasons):
        verdict = Verdict.BENIGN
    else:
        verdict = Verdict.UNKNOWN

    reasons.sort(key=lambda r: -abs(r.contribution))
    override = None
    if feedback and feedback.get("verdict") in ("false_positive", "confirmed"):
        override = feedback["verdict"]
        note = f": {feedback['note']}" if feedback.get("note") else ""
        if override == "false_positive":
            verdict, score = Verdict.BENIGN, min(score, 5)
            reasons.insert(
                0, Reason("analyst", Verdict.BENIGN, 0.0, f"marked false positive by analyst{note}")
            )
        else:
            verdict, score = Verdict.MALICIOUS, max(score, 95)
            reasons.insert(
                0, Reason("analyst", Verdict.MALICIOUS, 0.0, f"confirmed malicious by analyst{note}")
            )
    return Assessment(score, verdict, has_bad and has_good, tuple(reasons), override)
