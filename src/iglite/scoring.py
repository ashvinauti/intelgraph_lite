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

It is a pure function of stored evidence: cheap, deterministic and easy to
re-run after tuning trust weights.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping

from .model import Assessment, Evidence, Reason, Verdict

PRIOR = -2.0
SCALE = 3.0
SIGN = {Verdict.MALICIOUS: 1.0, Verdict.SUSPICIOUS: 0.5, Verdict.BENIGN: -1.0, Verdict.UNKNOWN: 0.0}
MALICIOUS_AT = 70
SUSPICIOUS_AT = 30
CONTRADICTION_TRUST = 0.5
NEIGHBOUR_WEIGHT = 1.0

# Relations through which guilt-by-association is allowed to flow.
PROPAGATING = frozenset({"resolves_to", "hosted_on", "serves", "uses_domain"})


def assess(
    evidence: Iterable[Evidence],
    trust: Mapping[str, float],
    neighbours: Iterable[tuple[str, str]] = (),
) -> Assessment:
    """Score one indicator.

    ``neighbours`` are ``(neighbour_key, rel)`` pairs for adjacent indicators
    that are themselves *directly* malicious (computed by the caller so there
    are no feedback loops).
    """
    strongest: dict[str, tuple[float, Evidence]] = {}
    for ev in evidence:
        c = trust.get(ev.source, 0.5) * max(0.0, min(1.0, ev.confidence)) * SIGN[ev.verdict] * SCALE
        if c == 0:
            continue
        best = strongest.get(ev.source)
        if best is None or abs(c) > abs(best[0]):
            strongest[ev.source] = (c, ev)

    reasons = [Reason(ev.source, ev.verdict, c, ev.detail) for c, ev in strongest.values()]
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
    return Assessment(score, verdict, has_bad and has_good, tuple(reasons))
