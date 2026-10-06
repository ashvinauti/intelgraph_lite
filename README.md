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

# Trace the network path to a target and check every hop
iglite trace example.com

# Monitor this machine's live connections (alerts on flagged IPs)
iglite watch                     # live, every 30 s
iglite watch --once              # one snapshot table
iglite serve --watch             # dashboard + monitoring together
```

## Live network monitoring

`iglite watch` checks which remote addresses this computer is talking to,
which program owns each connection and, on Windows, which domain name it
resolved from. New public IPs are looked up through your sources, and an alert
fires when one comes back suspicious or malicious.

* **No driver, no admin rights, almost no CPU.** It reads the operating
  system's connection table (`netstat`/`tasklist`/`ipconfig /displaydns` on
  Windows, `/proc` on Linux, `lsof` on macOS) instead of capturing packets.
* **Bounded.** At most 25 new IPs are looked up per snapshot, and each IP is
  rechecked at most hourly. Answers are cached.
* **Private addresses never leave the machine.** Only public remote IPs are
  sent to the online sources. Use `--offline` or keyless/local lists if you
  don't want your traffic metadata sent anywhere.
* **One alert per indicator per day**, plus a new alert if a suspicious IP
  escalates to malicious. Alerts are stored, shown in the dashboard and
  printed by `iglite watch`.
* It sees connections *at the moment of each snapshot*. A connection that
  opens and closes between snapshots is missed. Lower `--interval` (minimum 5 s)
  for more coverage. On Windows, the DNS cache still reveals recently
  contacted domains.

Run it as a normal user. On Linux, root is needed to see other users'
processes. Only monitor machines and networks you're responsible for.

## Traceroute

`iglite trace <ip|domain|url>` (or the **Routes** tab, or **Trace** on any live
connection) runs the operating system's own `tracert` (Windows) or
`traceroute`/`tracepath` (Linux/macOS) and streams the hops as they answer.
Every responding router is then checked against your sources, and RDAP
names the network that owns it. The path is saved in the graph as
`this computer → hop 1 → hop 2 → … → target`, so it shows up in the graph's
Path layout next to the programs that talk to the same addresses.

On Linux, install `traceroute` if it is missing (`sudo apt install traceroute`).
Windows and macOS include one.

## Dashboard

`iglite serve` opens an interactive dashboard:

* **Overview**: totals by verdict, a live network-activity chart (connections and flagged over time), recent alerts, and a box for investigating pasted indicators or reports.
* **Live network**: live connections with process, remote address, domain and verdict. Start/stop monitoring, scan now, filter and sort.
* **Routes**: run a traceroute and watch the hops appear live, each colored by verdict and labeled with its owner, plus a round-trip-time chart. Recent traces can be replayed.
* **Graph**: two layouts. **Path** arranges nodes in columns by hop distance from a root, like traceroute (this computer → programs → IPs → domains, plus traced router paths). **Force** is a physics layout. Drag, zoom, pan, double-click to expand, filter by verdict, and pick any node as the root.
* **Indicators**: a searchable, sortable list with STIX export.
* **Details panel**: why an indicator got its score, its connections and attributes, and a button to investigate again.

Keyboard: `1`–`5` switch tabs, `/` focuses search, `Esc` closes details. New alerts pop up as notifications. Polling pauses while the browser tab is
hidden, so an idle dashboard costs nothing.

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
.venv/bin/pytest            # 54 offline tests, ~3 s
.venv/bin/ruff check src tests
```

## Credits

Created and maintained by **Ashvin Auti**. The approach (multi-source
correlation, evidence-based verdicts, contradiction detection, STIX export) is
inspired by [IntelGraph](https://github.com/Berkayy123-h/intelgraph) by
Berkay Altıntaş. IntelGraph Lite is an independent codebase. MIT licensed.
