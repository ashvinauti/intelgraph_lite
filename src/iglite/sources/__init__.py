"""Source registry.

Adding a source = write a ``Source`` subclass and append it to ``BUILTIN``.
"""

from __future__ import annotations

from ..config import Config
from ..model import Verdict
from .base import Context, Source
from .cti import OTX, URLhaus, VirusTotal
from .lists import IndicatorList
from .osint import DNS, RDAP, CertTransparency, InternetDB

BUILTIN: list[type[Source]] = [DNS, RDAP, CertTransparency, InternetDB, OTX, VirusTotal, URLhaus]

__all__ = ["BUILTIN", "Context", "Source", "build", "describe"]


def _all(cfg: Config) -> list[Source]:
    sources: list[Source] = [cls() for cls in BUILTIN]
    for name, loc in cfg.blocklists.items():
        sources.append(IndicatorList(name, loc, Verdict.MALICIOUS, cfg.trust.get(name, 0.7)))
    for name, loc in cfg.allowlists.items():
        sources.append(IndicatorList(name, loc, Verdict.BENIGN, cfg.trust.get(name, 0.9)))
    return sources


def _status(src: Source, cfg: Config) -> str:
    if src.name in cfg.disabled:
        return "disabled"
    if cfg.enabled is not None and src.name not in cfg.enabled:
        return "disabled"
    if src.needs_key and not cfg.key(src.name):
        return "missing key"
    return "enabled"


def build(cfg: Config) -> list[Source]:
    """Instantiate the enabled sources with trust overrides applied."""
    active = []
    for src in _all(cfg):
        if _status(src, cfg) == "enabled":
            if src.name in cfg.trust:
                src.trust = float(cfg.trust[src.name])  # type: ignore[misc]
            active.append(src)
    return active


def describe(cfg: Config) -> list[dict[str, object]]:
    return [
        {
            "name": s.name,
            "status": _status(s, cfg),
            "kinds": sorted(k.value for k in s.kinds),
            "trust": cfg.trust.get(s.name, s.trust),
            "description": s.description,
        }
        for s in _all(cfg)
    ]
