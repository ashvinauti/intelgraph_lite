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

# Alert notification destinations (secrets, so environment / .env only).
NOTIFY_ENV = {
    "slack": "IGLITE_NOTIFY_SLACK",  # Slack incoming-webhook URL
    "teams": "IGLITE_NOTIFY_TEAMS",  # Microsoft Teams workflow webhook URL
    "webhook": "IGLITE_NOTIFY_WEBHOOK",  # any URL: receives the alert as JSON
    "email": "IGLITE_NOTIFY_EMAIL",  # comma-separated addresses (needs the SMTP settings)
}
SMTP_ENV = {
    "host": "IGLITE_SMTP_HOST",
    "port": "IGLITE_SMTP_PORT",  # 587 (STARTTLS, default) or 465 (TLS)
    "user": "IGLITE_SMTP_USER",
    "password": "IGLITE_SMTP_PASSWORD",
    "from": "IGLITE_SMTP_FROM",
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


# Operators whose IPs serve many unrelated customers (CDNs, big platforms).
# Matched case-insensitively against the network owner from RDAP/Shodan.
SHARED_INFRA = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "google",
    "microsoft",
    "apple",
    "facebook",
    "meta platforms",
    "edgecast",
    "limelight",
    "stackpath",
    "imperva",
    "incapsula",
    "sucuri",
    "bunny",
    "github",
    "level 3",
    "lumen",
)


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
    watch_max_new: int = 25  # new IPs/domains looked up per snapshot (bounds API use)
    # Gateway mode: watch a whole network from its router/firewall (see gateway.py).
    gateway_syslog: str | None = None  # "[host:]port" to receive syslog on, e.g. "0.0.0.0:5514"
    gateway_netflow: str | None = None  # "[host:]port" for NetFlow v5/v9/IPFIX, e.g. "0.0.0.0:2055"
    gateway_conntrack: bool = False  # read the kernel NAT table (when running on the gateway)
    gateway_ssh: str | None = None  # "user@router": read it over SSH (key auth), nothing installed there
    gateway_ssh_port: int = 22
    gateway_ssh_key: str | None = None  # private key file; default: your SSH agent / ~/.ssh keys
    gateway_ssh_logs: bool = True  # also follow the router's system log over the same SSH login
    gateway_files: list[str] = field(default_factory=list)  # logs to tail: Zeek, Suricata eve.json, syslog
    gateway_leases: list[str] = field(default_factory=list)  # DHCP lease files, for device names
    gateway_senders: list[str] = field(default_factory=list)  # exporters allowed; default: private IPs
    gateway_include_blocked: bool = False  # also check flows the firewall blocked
    gateway_window: float = 300.0  # seconds a flow stays in the live table after it was last seen
    lan_networks: list[str] = field(default_factory=list)  # inside addresses; default: non-public
    devices: dict[str, str] = field(default_factory=dict)  # LAN ip -> friendly name
    # Response: enforce blocks on this machine (when it is the gateway). See respond.py.
    enforce: str = "none"  # none | nftables
    block_hosts: str | None = (
        None  # dnsmasq hosts file for blocked domains, e.g. /var/lib/iglite/blocked.hosts
    )
    auto_case: bool = True  # file new alerts into an open case that already holds their indicator/device
    # Alert notifications. Destinations come from the environment (they are secrets); see notify.py.
    notify_min_verdict: str = "malicious"  # malicious | suspicious
    notify_per_hour: int = 30
    dashboard_url: str | None = None  # links in notifications, e.g. http://10.42.0.1:8765
    notify: dict[str, str] = field(default_factory=dict)  # channel -> destination (from the environment)
    smtp: dict[str, str] = field(default_factory=dict)
    # Database of every connection and DNS lookup live monitoring sees (one row per endpoint per day).
    connection_log: bool = True
    connection_log_days: float = 90  # older rows are deleted; 0 keeps everything
    # Common services (Google, Apple, CDNs...): hidden from the graph by default. See common.py.
    common_domains: list[str] = field(default_factory=list)  # your own routine services, e.g. your company's
    common_ignore: list[str] = field(default_factory=list)  # never treat these as common
    common_top_file: str | None = "~/.iglite/tranco.txt"  # written by `iglite common update`
    # False-positive controls
    evidence_half_life_days: float = 180.0  # bad evidence halves in weight this often
    alert_min_score: int = 60  # live-monitoring alerts need at least this score
    shared_infra: list[str] = field(default_factory=lambda: list(SHARED_INFRA))
    ai_provider: str = "anthropic"  # anthropic (Claude) | ollama (local model)
    ai_model: str | None = None  # None = the provider's default model
    ollama_url: str = "http://localhost:11434"
    ai_triage: str = "auto"  # auto: triage new alerts in the background | manual | off
    ai_triage_per_hour: int = 20  # cap on automatic triage runs
    ai_base_url: str | None = None  # None = Anthropic's API; set for a compatible gateway
    ai_effort: str = "high"  # low | medium | high | xhigh | max: depth vs. token cost
    ai_max_steps: int = 10  # model turns per question
    api_token: str | None = None
    keys: dict[str, str] = field(default_factory=dict)

    @property
    def gateway(self) -> bool:
        """True when any gateway input is configured: monitor the network, not this computer."""
        return bool(
            self.gateway_syslog
            or self.gateway_netflow
            or self.gateway_conntrack
            or self.gateway_ssh
            or self.gateway_files
        )

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
        if name in data and name not in ("keys", "api_token", "notify", "smtp"):
            setattr(cfg, name, data[name])

    if "IGLITE_DB" in env:
        cfg.db = env["IGLITE_DB"]
    if env.get("IGLITE_OFFLINE", "").lower() in ("1", "true", "yes"):
        cfg.offline = True
    cfg.api_token = (env.get("IGLITE_API_TOKEN") or "").strip() or None
    if base := (env.get("ANTHROPIC_BASE_URL") or "").strip():
        cfg.ai_base_url = base
    if model := (env.get("IGLITE_AI_MODEL") or "").strip():
        cfg.ai_model = model
    if provider := (env.get("IGLITE_AI_PROVIDER") or "").strip().lower():
        cfg.ai_provider = provider
    if host := (env.get("OLLAMA_HOST") or "").strip():
        cfg.ollama_url = host
    if triage := (env.get("IGLITE_AI_TRIAGE") or "").strip().lower():
        cfg.ai_triage = triage
    if url := (env.get("IGLITE_DASHBOARD_URL") or "").strip():
        cfg.dashboard_url = url
    cfg.notify = {
        channel: value for channel, var in NOTIFY_ENV.items() if (value := (env.get(var) or "").strip())
    }
    cfg.smtp = {key: value for key, var in SMTP_ENV.items() if (value := (env.get(var) or "").strip())}
    cfg.keys = {}
    for src, names in ENV_KEYS.items():
        for name in names:
            if value := (env.get(name) or "").strip():
                cfg.keys[src] = value
                break
    return cfg
