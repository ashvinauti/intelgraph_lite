"""Core data model.

Everything the system knows is expressed with four small immutable types:

* ``Indicator`` - a thing we can look up (IP, domain, URL, hash, ...).
* ``Evidence``  - one source's opinion about one indicator.
* ``Relation``  - a typed, directed link between two indicators.
* ``Finding``   - what a single source returned for a single lookup.

Sources produce ``Finding`` objects, the engine persists them, and the scorer
turns stored evidence into an ``Assessment``. Nothing else crosses layer
boundaries.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Kind(enum.StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"
    EMAIL = "email"
    ASN = "asn"
    ORG = "org"
    TAG = "tag"
    REPORT = "report"


class Verdict(enum.StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class Indicator:
    kind: Kind
    value: str

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.value}"

    @classmethod
    def from_key(cls, key: str) -> Indicator:
        kind, _, value = key.partition(":")
        return cls(Kind(kind), value)

    def __str__(self) -> str:
        return self.key


@dataclass(frozen=True)
class Evidence:
    source: str
    verdict: Verdict
    detail: str
    confidence: float = 1.0
    url: str | None = None


@dataclass(frozen=True)
class Relation:
    src: Indicator
    rel: str
    dst: Indicator
    # Whether the engine may follow this link to look up the other end.
    pivot: bool = True


@dataclass
class Finding:
    evidence: list[Evidence] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Reason:
    source: str
    verdict: Verdict
    contribution: float
    detail: str


@dataclass(frozen=True)
class Assessment:
    score: int
    verdict: Verdict
    contradiction: bool
    reasons: tuple[Reason, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "verdict": self.verdict.value,
            "contradiction": self.contradiction,
            "reasons": [
                {
                    "source": r.source,
                    "verdict": r.verdict.value,
                    "contribution": round(r.contribution, 3),
                    "detail": r.detail,
                }
                for r in self.reasons
            ],
        }
