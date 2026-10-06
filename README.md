# IntelGraph Lite

A lightweight **threat intelligence and OSINT** correlation tool. It looks up
IPs, domains, URLs, hashes and CVEs across free OSINT services and threat
feeds, links them into a knowledge graph, and gives every indicator a score
with the reasons behind it.

It is built for low resource use: **no runtime dependencies**, SQLite as the graph, hard time and lookup
limits, and a response cache, so repeat questions cost nothing. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Install

Python 3.11+ is the only requirement.

```bash
pip install .            # or: uv pip install .
iglite --help
```

## Use

```bash
# Investigate indicators (defanged input is fine)
iglite investigate 45.155.205.20 hxxps://login-portal[.]example/auth

# Pull every indicator out of a threat report and investigate them
iglite ingest https://example.org/apt-report.html --investigate

# Why is this indicator scored the way it is?
iglite show 45.155.205.20

# Browse, graph, export
iglite list --verdict malicious
iglite graph example.com --depth 2
iglite export stix -o bundle.json       # STIX 2.1 for MISP / OpenCTI

# Dashboard and JSON API on http://127.0.0.1:8765
iglite serve
```

Example output:

```
MALICIOUS   91  ip:45.155.205.20
           +2.16  urlhaus      hosted 4 malware URL(s), 2 online
           +2.10  feodo        listed in feodo
           +0.72  internetdb   tagged scanner
```

## Sources

| Source | Kind | Key needed | What it adds |
|--------|------|------------|--------------|
| `dns` | OSINT | no | A/AAAA records (domain → IP pivots) |
| `rdap` | OSINT | no | Registrar, domain age (new domains are suspicious), network owner |
| `crtsh` | OSINT | no | Subdomains from certificate transparency logs |
| `internetdb` | OSINT | no | Open ports, hostnames, CVEs, tags (c2, tor, scanner, …) from Shodan InternetDB |
| `otx` | CTI | `OTX_API_KEY` | AlienVault OTX pulses, malware families |
| `virustotal` | CTI | `VT_API_KEY` | Engine detections (rate-limited to the free tier) |
| `urlhaus` | CTI | `ABUSECH_AUTH_KEY` | Malware distribution URLs and payloads |
| *your lists* | feed | no | Any text blocklist/allowlist, local file or URL |

`iglite sources` shows which are active. Keyed sources switch on automatically
when their environment variable is set.

## Configure

Everything is optional. Copy [`iglite.example.toml`](iglite.example.toml) to
`iglite.toml` in your working directory, or point `IGLITE_CONFIG` at it.

| Setting | Default | Meaning |
|---------|---------|---------|
| `depth` | 1 | Pivot hops from the starting indicators |
| `budget` | 50 | Max indicators looked up per investigation |
| `deadline` | 60 | Wall-clock seconds before returning partial results |
| `workers` | 8 | Concurrent lookups |
| `offline` | false | Cache and local lists only (also `--offline`, `IGLITE_OFFLINE=1`) |
| `trust.<source>` | per source | 0–1 weight of that source's verdicts |
| `ttl.<source>` | per source | Seconds a cached answer stays fresh |

Environment: `IGLITE_DB` (default `~/.iglite/iglite.db`), `IGLITE_API_TOKEN`
(required to serve on a non-localhost interface), and the API keys above.

## Docker

```bash
docker build -t iglite .
docker run -p 8765:8765 -e IGLITE_API_TOKEN=change-me -v iglite:/data iglite
```

## Develop

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/pytest            # 39 offline tests, ~3 s
.venv/bin/ruff check src tests
```

## Credits

Created and maintained by **Ashvin Auti**. The approach (multi-source
correlation, evidence-based verdicts, contradiction detection, STIX export) is
inspired by [IntelGraph](https://github.com/Berkayy123-h/intelgraph) by
Berkay Altıntaş. IntelGraph Lite is an independent codebase. MIT licensed.
