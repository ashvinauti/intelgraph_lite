"""Configuration: an optional TOML file plus environment variables.

Precedence (highest first): environment, ``iglite.toml``, defaults. API keys
are read from the environment only, so the config file can be committed.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ENV_KEYS = {
    "otx": "OTX_API_KEY",
    "virustotal": "VT_API_KEY",
    "urlhaus": "ABUSECH_AUTH_KEY",
}


@dataclass
class Config:
    db: str = "~/.iglite/iglite.db"
    workers: int = 8  # concurrent lookups (I/O bound, not CPU bound)
    timeout: float = 10.0  # per HTTP request
    deadline: float = 60.0  # wall-clock cap for one investigation
    budget: int = 50  # max indicators looked up per investigation
    depth: int = 1  # pivot hops away from the seeds
    offline: bool = False  # serve only from cache / local lists
    enabled: list[str] | None = None  # None = every source whose key is present
    disabled: list[str] = field(default_factory=list)
    trust: dict[str, float] = field(default_factory=dict)
    ttl: dict[str, int] = field(default_factory=dict)  # per-source cache seconds
    blocklists: dict[str, str] = field(default_factory=dict)  # name -> path or URL
    allowlists: dict[str, str] = field(default_factory=dict)
    api_token: str | None = None
    keys: dict[str, str] = field(default_factory=dict)

    @property
    def db_path(self) -> str:
        return self.db if self.db == ":memory:" else str(Path(self.db).expanduser())

    def key(self, source: str) -> str | None:
        return self.keys.get(source)


def load(path: str | Path | None = None, env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    data: dict[str, Any] = {}
    candidate = path or env.get("IGLITE_CONFIG")
    if candidate is None and Path("iglite.toml").is_file():
        candidate = "iglite.toml"
    if candidate:
        with open(candidate, "rb") as fh:
            data = tomllib.load(fh)

    cfg = Config()
    for name in cfg.__dataclass_fields__:
        if name in data and name not in ("keys", "api_token"):
            setattr(cfg, name, data[name])

    if "IGLITE_DB" in env:
        cfg.db = env["IGLITE_DB"]
    if env.get("IGLITE_OFFLINE", "").lower() in ("1", "true", "yes"):
        cfg.offline = True
    cfg.api_token = env.get("IGLITE_API_TOKEN") or None
    cfg.keys = {src: env[var] for src, var in ENV_KEYS.items() if env.get(var)}
    return cfg
