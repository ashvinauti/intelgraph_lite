"""The source plug-in contract.

A source is a small class with a name, the indicator kinds it understands, a
default trust weight and cache TTL, and one method: ``lookup``. It must not
touch the database; it only returns a ``Finding``. That keeps sources trivial
to write and to test with a fake transport.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from ..config import Config
from ..fetch import Fetcher
from ..model import Finding, Indicator, Kind


@dataclass
class Context:
    fetcher: Fetcher
    config: Config

    def ttl(self, source: Source) -> int:
        return int(self.config.ttl.get(source.name, source.ttl))


class Source:
    name: ClassVar[str]
    kinds: ClassVar[frozenset[Kind]]
    trust: ClassVar[float] = 0.5  # 0..1, how much a verdict from here moves the score
    ttl: ClassVar[int] = 86400  # seconds a cached answer stays fresh
    needs_key: ClassVar[bool] = False
    # Remote sources never see non-public indicators (private IPs, internal names).
    remote: ClassVar[bool] = True
    description: ClassVar[str] = ""
    # Minimum seconds between requests to a host (free-tier rate limits).
    rate_limits: ClassVar[dict[str, float]] = {}

    def handles(self, ind: Indicator) -> bool:
        return ind.kind in self.kinds

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        """Return what this source knows. ``None`` means "no answer" and leaves
        previously stored evidence untouched; an empty ``Finding`` clears it."""
        raise NotImplementedError
