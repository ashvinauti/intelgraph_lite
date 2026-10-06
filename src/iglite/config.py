"""Configuration: an optional TOML file, environment variables and ``.env`` files.

Precedence (highest first): real environment, ``.env`` in the current folder,
``~/.iglite/.env``, ``iglite.toml``, defaults. API keys are read from the
environment or ``.env`` only, never from ``iglite.toml``, so the TOML file can
be committed while ``.env`` stays private (it is git-ignored).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# source -> accepted variable names (first one set wins)
ENV_KEYS = {
    "otx": ("OTX_API_KEY",),
    "virustotal": ("VT_API_KEY", "VIRUSTOTAL_API_KEY"),
    "shodan": ("SHODAN_API_KEY",),
    "urlhaus": ("ABUSECH_AUTH_KEY", "URLHAUS_AUTH_KEY"),
    "anthropic": ("ANTHROPIC_API_KEY",),  # the optional AI analyst
}


def read_dotenv(path: str | Path) -> dict[str, str]:
    """Parse KEY=VALUE lines; ignores blanks, comments and ``export``; strips quotes."""
    out: dict[str, str] = {}
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8-sig")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        out[key.strip()] = value
    return out


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
    watch_interval: float = 30.0  # seconds between live network snapshots
    ai_model: str = "claude-opus-5-5"  # AI analyst model
    ai_effort: str = "high"  # low | medium | high | xhigh | max: depth vs. token cost
    ai_max_steps: int = 10  # model turns per question
    api_token: str | None = None
    keys: dict[str, str] = field(default_factory=dict)

    @property
    def db_path(self) -> str:
        return self.db if self.db == ":memory:" else str(Path(self.db).expanduser())

    def key(self, source: str) -> str | None:
        return self.keys.get(source)


def load(path: str | Path | None = None, env: dict[str, str] | None = None) -> Config:
    real = dict(os.environ if env is None else env)
    merged: dict[str, str] = {}
    if env is None:  # an explicit env (tests, embedding) is used as-is
        for dotenv in ("~/.iglite/.env", real.get("IGLITE_ENV_FILE") or ".env"):
            merged.update(read_dotenv(dotenv))
    merged.update(real)
    env = merged
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
    cfg.api_token = (env.get("IGLITE_API_TOKEN") or "").strip() or None
    cfg.keys = {}
    for src, names in ENV_KEYS.items():
        for name in names:
            if value := (env.get(name) or "").strip():
                cfg.keys[src] = value
                break
    return cfg
