"""Indicator lists: local files or plain-text feeds (one indicator per line).

Blocklists produce malicious evidence, allowlists produce benign evidence that
counters false positives. A list is loaded once into a set; each lookup is
then an O(1) membership test with no network call.

Free feeds that work out of the box, for example::

    [blocklists]
    feodo = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    urlhaus_online = "https://urlhaus.abuse.ch/downloads/text_online/"
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from ..extract import classify
from ..fetch import FetchError
from ..model import Evidence, Finding, Indicator, Kind, Verdict
from .base import Context, Source


class IndicatorList(Source):
    kinds = frozenset(Kind) - {Kind.ORG, Kind.TAG, Kind.REPORT}
    ttl = 6 * 3600
    RETRY_AFTER = 300.0
    remote = False  # membership test runs locally, safe for internal indicators

    def __init__(self, name: str, location: str, verdict: Verdict, trust: float) -> None:
        self.name = name  # type: ignore[misc]  # instance-level name per list
        self.location = location
        self.verdict = verdict
        self.trust = trust  # type: ignore[misc]
        self.description = f"{verdict.value} list: {location}"  # type: ignore[misc]
        self._keys: frozenset[str] = frozenset()
        self._ok = False
        self._expires = 0.0
        self._lock = threading.Lock()

    def _read(self, ctx: Context) -> str:
        if self.location.startswith(("http://", "https://")):
            result = ctx.fetcher.request("GET", self.location, ttl=ctx.ttl(self))
            if result is None or result[0] >= 400:
                raise FetchError(f"{self.name}: list unavailable")
            return result[1].decode("utf-8", "replace")
        return Path(self.location).expanduser().read_text(encoding="utf-8")

    def _load(self, ctx: Context) -> bool:
        """Refresh the in-memory set when stale. Returns whether it is usable."""
        with self._lock:
            now = time.monotonic()
            if now < self._expires:
                return self._ok
            try:
                text = self._read(ctx)
            except (OSError, FetchError):
                self._expires = now + self.RETRY_AFTER  # keep the last good copy, retry later
                if not self._ok:
                    raise  # surfaced once in the report, then quiet until the retry
                return True
            keys = set()
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip().split(",", 1)[0].strip()
                if line and (ind := classify(line)) is not None:
                    keys.add(ind.key)
            self._keys, self._ok = frozenset(keys), True
            self._expires = now + ctx.ttl(self)
            return True

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        if not self._load(ctx):
            return None
        if ind.key not in self._keys:
            return Finding()  # empty, so a delisted indicator loses its old evidence
        return Finding(evidence=[Evidence(self.name, self.verdict, f"listed in {self.name}", 1.0)])
