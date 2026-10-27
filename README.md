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

# Or monitor every device on the network from the router/firewall (see Gateway mode)
iglite serve --host 0.0.0.0 --syslog 5514 --netflow 2055

# MITRE ATT&CK techniques behind what you've seen
iglite attack                    # matrix by tactic
iglite attack navigator -o layer.json

# Cases, response and notifications
iglite case list
iglite block 203.0.113.66 --case 1
iglite path host:10.42.0.52 http://cdn-update.example/setup.bin
iglite notify --test

# Show it to someone: a simulated network with a minute of incidents, nothing to set up
iglite demo
```

## Demo for other teams

`iglite demo` runs the real dashboard and the real pipeline on a **simulated home
network**: eight devices browsing, DHCP names, DNS lookups, and a minute of
scripted incidents. It needs no setup: no keys, no router, no admin rights, no
internet. The intelligence is invented, every "internet" address is in the
documentation ranges (TEST-NET) and every name ends in `.example`. It runs on a
throwaway database, so your own `~/.iglite` is never touched.

```bash
iglite demo                         # opens http://127.0.0.1:8765/#network
iglite demo --speed 2               # incidents play twice as fast
iglite demo --host 0.0.0.0          # let others on your network watch (prints an API token)
```

**One file to share.** `python scripts/build-pyz.py` builds `dist/iglite.pyz`
(about 200 KB). Each CI run also uploads it as the **iglite-pyz** artifact. Anyone with
Python 3.11+ on Windows, macOS or Linux runs it with nothing to install:

```bash
python iglite.pyz demo              # Windows: py iglite.pyz demo
python iglite.pyz --help            # it is the full tool, not just the demo
```

With Docker: `docker run --rm -p 8765:8765 iglite iglite demo --host 0.0.0.0 --no-browser`.

**What happens, and what to point at** (times at `--speed 1`):

| When | What happens | What to show |
|------|--------------|--------------|
| start | A threat brief is ingested and investigated | ATT&CK tab: techniques from the report |
| ~3 s | The iPhone loads a shared CDN whose address one feed listed long ago | It is *not* flagged: the entry is stale and the name is known-good |
| ~6 s | The Kids-iPad opens a phishing link | Device turns red; alert; T1566.002 |
| ~12 s | The Smart-Plug beacons to a C2 server on port 4444; the IDS fires | Alert; T1071 *observed* and T1571 |
| ~20 s | The Work-Laptop downloads a dropper | Alert; T1105; click it for the graph |
| ~28 s | The LG TV joins a crypto-mining pool | Alert; T1496 |
| ~36 s | An internet scanner reaches the NAS on SSH | *Suspicious* only: worth a look, not an alert |
| any time | The C2 and dropper alerts have filed themselves into case #1, opened from the threat brief | Cases tab: timeline, ATT&CK, **Block** the C2 IP, **Quarantine** the Smart-Plug, **Copy report** |
| any time | File the phishing alert into a new case | Recent alerts › **Add to case** |
| any time | How did the laptop get the malware? | Work-Laptop › **Find path to…** the dropper URL |

Good stops along the way: click a device in the **Network** tab to see its
connections and lookups; open an alert and read *why* it scored that way; mark
something a false positive and see it counted against the source that reported it; export STIX or an
ATT&CK Navigator layer. If `ANTHROPIC_API_KEY` is set, the **Analyst** tab works too
(`pip install anthropic` for the one-file build).

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

## Gateway mode: the whole network from your router or firewall

Instead of watching one computer, IntelGraph Lite can watch every device behind
your home router or company firewall: phones, TVs, IoT gadgets and servers
that can't run software of their own. It doesn't sit in the traffic path and it
doesn't capture packets. It reads what the gateway already records:

| Input | Flag | Works with |
|-------|------|------------|
| Firewall / router **syslog** (UDP) | `--syslog 5514` | OpenWrt, UFW and iptables/nftables `LOG`, pfSense/OPNsense `filterlog`, FortiGate, Sophos, SonicWall, Check Point and other `key=value` logs, Cisco ASA, Juniper SRX, MikroTik, Palo Alto `TRAFFIC` |
| DNS logs (in the same syslog, or a file) | `--syslog` / `--tail` | dnsmasq, **Pi-hole**, Unbound: which device looked up which domain |
| **NetFlow v5/v9, IPFIX** (UDP) | `--netflow 2055` | Most business routers and firewalls, MikroTik, OpenWrt with `softflowd` |
| The NAT table, when running **on** a Linux/OpenWrt gateway | `--conntrack` | `/proc/net/nf_conntrack` or `conntrack -L` |
| **SSH into the router**, nothing installed on it | `--ssh root@192.168.1.1` | OpenWrt, DD-WRT, Asuswrt-Merlin, Ubiquiti EdgeRouter/UniFi gateways and other Linux routers (conntrack); pfSense/OPNsense (`pfctl -ss`) |
| **Web proxy** logs | `--tail FILE` | Squid `access.log` (native format): which device visited which site |
| Log files | `--tail FILE` | **Zeek** `conn.log`/`dns.log` (TSV or JSON), **Suricata** `eve.json` (flows, DNS, and alerts with their ATT&CK IDs), or any file the formats above are written to |
| Device names | `--leases FILE`, `[devices]` | dnsmasq/OpenWrt and ISC DHCP leases; DHCP `DHCPACK` syslog lines are picked up automatically |

Each flow becomes *(LAN device, remote address, port)*. The public side is
looked up through your sources exactly as in host mode. The Live network tab
then lists **devices** instead of programs, alerts say which device it was
("pixel-7 (192.168.1.23) · port 443"), and you can mute a device just like a
program (`iglite suppress device 192.168.1.40`). Domains that devices looked
up in DNS are checked too, so a C2 domain can alert before any connection is
made.

* **Inside vs. outside.** By default every private address is "inside". If
  your company uses public address space internally, list it with
  `--lan 203.0.113.0/24` (or `lan_networks` in `iglite.toml`).
* **Blocked traffic is ignored.** A blocked internet scan is the firewall doing
  its job, not an incident. `--include-blocked` checks it anyway.
* **Trusted senders only.** The UDP listeners accept packets from private
  addresses only. Pin them to your gateway with `gateway_senders = ["192.168.1.1"]`.
* **Bounded cost.** At most `watch_max_new` (default 25) new IPs or domains
  are looked up per snapshot, each one at most hourly, and results are
  cached. On a busy network, rely on free local feeds (`[blocklists]`) and keep
  rate-limited APIs such as VirusTotal for on-demand lookups.
* **Rolling window.** Flows stay in the live table for `gateway_window`
  seconds (default 300) after they were last seen.

### The Network tab

In gateway mode the dashboard's **Network** tab shows the network rather than
one computer:

* **Devices.** One card per device: its name (from DHCP, or one you give it),
  IP address, how many connections, servers and sites, and whether anything it
  touched is flagged. Flagged devices come first. Click a card to see the
  device's alerts, MITRE ATT&CK techniques, connections and recent DNS lookups.
  From there you can rename it, mute it, show it in the graph or ask the AI
  analyst about it.
* **Live DNS lookups.** Every lookup on the network as it happens, with the
  device that made it and the domain's verdict. Filter it to flagged lookups or
  pause it.
* **Totals.** Devices, devices active now, flagged devices, open alerts and
  lookups per minute.

Names you give devices are kept across restarts and win over DHCP names.

### Ubuntu laptop or PC as the gateway (one command)

No spare router? Any Ubuntu machine with an ethernet port and a Wi-Fi card that
supports access-point mode (`iw list` lists `* AP`) can be the gateway. It
shares its wired connection to your router as a Wi-Fi hotspot, and IntelGraph
Lite watches everything that goes through it:

```
your router ──ethernet──► Ubuntu machine (hotspot + IntelGraph Lite) ──Wi-Fi──► your devices
```

```bash
git clone https://github.com/ashvinauti/intelgraph_lite.git && cd intelgraph_lite
sudo scripts/gateway-hotspot.sh --ssid HomeSecure --password 'a-strong-password'
```

The script:
1. Creates the hotspot.
2. Turns on DNS and DHCP logging.
3. Lets hotspot traffic past Docker's firewall rules, if Docker is installed.
4. Installs IntelGraph Lite as the `iglite-gateway` service, which starts on boot.
5. Keeps the machine awake with the lid closed.

At the end it prints the dashboard address and API token. Use `--dry-run` to
see every step first, and `--uninstall` to undo it.

**No changes on any device.** Give the hotspot the same Wi-Fi name and
password as your router, then turn off the router's own Wi-Fi. Every device
then joins the hotspot by itself.

A laptop hotspot suits about 5 to 15 devices in nearby rooms. For a whole
house, use a router you can SSH into (below) or an access point.

### Connect over SSH (no router configuration)

If your router lets you log in over SSH, IntelGraph Lite can read it directly.
You don't need syslog or NetFlow, and nothing is installed on the router:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/router            # once: make a key for the router
# add ~/.ssh/router.pub to the router (OpenWrt: System → Administration → SSH-Keys)
ssh -i ~/.ssh/router root@192.168.1.1 exit        # once: log in by hand to trust its host key
iglite serve --ssh root@192.168.1.1 --ssh-key ~/.ssh/router
```

Each scan reads the router's connection table and DHCP leases. Its system log
(DNS lookups, firewall entries) streams in over the same login. On OpenWrt,
switch on DNS query logging so lookups reach the log:
`uci set dhcp.@dnsmasq[0].logqueries=1; uci commit dhcp; /etc/init.d/dnsmasq restart`.

* **Read-only.** It only runs fixed `cat`/`grep`/`conntrack -L`/`pfctl -ss`
  and `logread -f`/`tail -F` commands. It changes nothing on the router.
* **Key login only.** SSH runs in `BatchMode`, so it never asks for or stores
  a password. On Windows 10/11, the built-in OpenSSH client works.
* **Same network.** Keep the router's SSH port closed to the internet. To
  monitor from elsewhere, connect to your home network over a VPN
  (WireGuard, Tailscale) first.
* Login failures appear on the Live network tab and in `iglite watch --once`
  (for example "Permission denied (publickey)").

Settings: `gateway_ssh = "root@192.168.1.1"`, `gateway_ssh_port`,
`gateway_ssh_key`, `gateway_ssh_logs = false` to read only the connection table.

### Web proxy

If your devices go through a web proxy (Squid, or a proxy server at work),
tail its access log: `--tail /var/log/squid/access.log`. Each request gives
the device, the site's name and the server address it reached. IntelGraph
Lite checks those exactly like DNS and connection data. To make IntelGraph
Lite's *own* lookups go out through a proxy, set `HTTPS_PROXY` (for example
`HTTPS_PROXY=http://proxy.corp:3128`).

### Home network

**Option A: a small always-on box (Raspberry Pi, NAS, old laptop).** Run
IntelGraph Lite there and point the router at it.

```bash
export IGLITE_API_TOKEN=pick-a-long-random-token   # required to listen on the network
iglite serve --host 0.0.0.0 --syslog 5514 --netflow 2055
```

Then, on the router:

* **OpenWrt.** For flows: `opkg install softflowd`, then
  `softflowd -i br-lan -n 192.168.1.10:2055 -v 9`. For DNS and device names,
  forward the system log to the box:
  `uci set dhcp.@dnsmasq[0].logqueries=1; uci set system.@system[0].log_ip=192.168.1.10; uci set system.@system[0].log_port=5514; uci set system.@system[0].log_proto=udp; uci commit; /etc/init.d/dnsmasq restart; /etc/init.d/log restart`.
* **pfSense / OPNsense.** Send firewall logs to the box via remote syslog
  (`192.168.1.10:5514`), and turn on logging for your LAN *pass* rule so
  allowed connections are logged too.
* **MikroTik.** `/ip traffic-flow set enabled=yes` and
  `/ip traffic-flow target add dst-address=192.168.1.10 port=2055 version=9`.
* **ISP router with no logging?** Use **Pi-hole** as the network's DNS
  server. Every device's lookups then reach IntelGraph Lite:
  `iglite serve --host 0.0.0.0 --tail /var/log/pihole/pihole.log --leases /etc/pihole/dhcp.leases`.

**Option B: on the router itself.** This works on OpenWrt 23.05 or newer with
spare RAM and USB storage. Python 3.11 is the only requirement.

```bash
opkg update && opkg install python3 python3-sqlite3 conntrack
uci set dhcp.@dnsmasq[0].logqueries=1; uci set system.@system[0].log_ip=127.0.0.1
uci set system.@system[0].log_port=5514; uci set system.@system[0].log_proto=udp; uci commit
/etc/init.d/dnsmasq restart; /etc/init.d/log restart
iglite --db /mnt/usb/iglite.db serve --host 0.0.0.0 --conntrack --syslog 127.0.0.1:5514 --leases /tmp/dhcp.leases
```

Most consumer routers have too little memory and flash for this, so Option A
is the usual choice.

### Company network

Put IntelGraph Lite on a small VM or server in the management network:

* **Next-generation firewall syslog.** Example for FortiGate:
  `config log syslogd setting` → `set status enable`, `set server 10.0.0.10`,
  `set port 5514`. On Palo Alto, use a syslog server profile and a
  log-forwarding profile for traffic logs. On Cisco ASA, use
  `logging host inside 10.0.0.10 udp/5514` and `logging trap informational`.
  Sophos, SonicWall and Check Point `key=value` logs work too.
* **NetFlow/IPFIX** from core routers: `--netflow 2055`.
* **Zeek/Suricata on a SPAN or TAP port** (for example Security Onion):
  `--tail /nsm/zeek/logs/current/conn.log --tail /nsm/zeek/logs/current/dns.log --tail /var/log/suricata/eve.json`.
  Suricata alerts carry ATT&CK technique IDs, which appear as *observed*
  techniques.
* Pin the exporters (`gateway_senders`) and list internal ranges (`lan_networks`).
* Monitoring other people's traffic is regulated in many countries. Follow
  your organisation's policy and tell users where the law requires it.

### Closing the loop: feed your firewall a blocklist

IntelGraph Lite publishes plain-text feeds that the gateway pulls and enforces
(when it runs *on* the gateway it can also block directly, see
[Respond: block and quarantine](#respond-block-and-quarantine)):

```
GET /api/blocklist/ip.txt       # malicious IPs
GET /api/blocklist/domain.txt   # malicious domains (Pi-hole / AdGuard / DNS filter)
GET /api/blocklist/url.txt      # malicious URLs (web proxy)
    ?suspicious=1  ?min_score=80  ?token=...   # firewalls can't send headers, so ?token= works here
```

Use these with pfSense/OPNsense *URL Table* aliases, FortiGate *External
Threat Feeds*, Palo Alto *External Dynamic Lists*, or Pi-hole *adlists*.
`iglite blocklist ip -o ips.txt` writes the same list to a file. False
positives you marked, suppressed indicators, private addresses and IPs on
shared CDN/cloud infrastructure are left out; anything you blocked by hand is
always in. Blocking one Cloudflare
IP would break thousands of unrelated sites. IntelGraph Lite serves plain
HTTP, so put it behind a TLS reverse proxy (Caddy, nginx) if the firewall
pulls across an untrusted network.

## MITRE ATT&CK

Every indicator can be linked to the
[ATT&CK](https://attack.mitre.org/) techniques behind it. The **ATT&CK** tab
shows a matrix of the techniques seen, by tactic, colored by verdict. Click a
technique to see its indicators. Each link records its *basis*, so a fact is
never confused with a guess:

| Basis | Where it comes from |
|-------|---------------------|
| **reported** | A threat feed mapped it: OTX pulses list ATT&CK IDs. |
| **observed** | Your IDS saw it: Suricata alert metadata (gateway mode). |
| **inferred** | Guessed from a feed tag (`c2` → T1071, `phishing` → T1566, `malware_download` → T1105, `tor` → T1090.003, ...) or from live traffic to a flagged host (port 443 → T1071.001 Web Protocols, 53 → T1071.004 DNS, an unusual port → T1571 Non-Standard Port). |
| **report** | A report you ingested names the technique ID (`T1566.001`). |
| **associated** | A tag names ATT&CK malware or a group (`emotet` → S0367, `apt28` → G0007). That software's known techniques are *associated*, and are shown only when you ask (`--associated`, or the checkbox). |

```bash
iglite attack                           # matrix of techniques seen, by tactic
iglite attack T1071.001                 # one technique and its indicators
iglite attack --indicator 45.155.205.20 # techniques for one indicator
iglite attack navigator -o layer.json   # open in the ATT&CK Navigator
iglite attack update                    # refresh the catalogue from MITRE
```

* **Offline.** A compact copy of Enterprise ATT&CK (v20: tactics, techniques,
  malware and groups) ships with the package, about 70 KB. `iglite attack update`
  downloads the latest release to `~/.iglite/attack.json.gz`. The download is
  about 55 MB and needs about 600 MB of memory to convert, so on a router or
  small board, run it on a PC and copy the file across.
* **Exports.** STIX bundles include `attack-pattern` objects with MITRE's own
  STIX IDs, linked by `indicates` relationships, so OpenCTI and MISP merge them
  with the ATT&CK data they already have. The Navigator layer opens in
  [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
* **AI agents.** The analyst can query the matrix (`attack_techniques`). The
  triage agent sees each alert's techniques and their basis.

ATT&CK® is a registered trademark of The MITRE Corporation. The bundled data
is © MITRE and used under the
[ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## Cases: from alerts to an incident

A **case** groups everything about one incident: its alerts, the devices and
indicators involved, the ATT&CK techniques they map to, your notes, and a
timeline of what happened and what was done (blocks, status changes).

* Open one from an alert (**Add to case** in Recent alerts), from any node's
  details panel, a device in the Network tab, or **New case** in the Cases tab.
* New alerts **file themselves** into an open case that already holds the same
  indicator or device (switch off with `auto_case = false`). One infected
  laptop stays one case, not twenty alerts.
* Set the status (open, investigating, closed) and severity, write a summary,
  add notes, and **Copy report** to paste the whole case as Markdown into a
  ticket, email or chat.

```bash
iglite case new "Smart plug beaconing" --alert 12 --severity high
iglite case add 1 --indicator 203.0.113.66
iglite case note 1 "Unplugged; owner informed"
iglite case status 1 closed
iglite case report 1 -o case-1.md
iglite case list
```

## Respond: block and quarantine

**Block** an IP, domain or URL, or **Quarantine** a device, from its details
panel, a case, or the Network tab. Every block:

1. goes into the [blocklist feeds](#closing-the-loop-feed-your-firewall-a-blocklist)
   your firewall or DNS filter pulls, even if its score is low;
2. is written into the timeline of every case that holds it;
3. is **enforced right away** when IntelGraph Lite runs on the gateway:
   * `--enforce nftables`: blocked IPs are dropped, both ways, in an nftables
     table of its own (`inet iglite`), and a quarantined device can reach the
     gateway (DHCP, DNS, this dashboard) but nothing beyond it. Existing
     connections are cut too. The table is rebuilt from the database on every
     change and at startup, so it always matches the dashboard.
   * `--block-hosts FILE`: blocked domains are written as a dnsmasq hosts file
     and dnsmasq reloads it, so the gateway's DNS stops answering for them
     (exact names, not subdomains).

Domains are never turned into IP blocks, because one IP can serve thousands of
sites. **Unblock** and **Release** undo it the same way. The Ubuntu hotspot
script sets both options up.

```bash
sudo iglite block 203.0.113.66 --note "C2 server" --case 1 --enforce nftables
sudo iglite block 10.42.0.61 --device --enforce nftables      # quarantine
sudo iglite block 10.42.0.61 --device --undo --enforce nftables
iglite block                                                  # list
```

## Alert notifications

New alerts can go to Slack, Microsoft Teams, email or any webhook. The
destinations are secrets, so they go in `.env`:

```bash
IGLITE_NOTIFY_SLACK=https://hooks.slack.com/services/...     # Slack incoming webhook
IGLITE_NOTIFY_TEAMS=https://...                              # Teams: Workflows › "Post to a channel when a webhook request is received"
IGLITE_NOTIFY_WEBHOOK=https://...                            # anything: the alert as JSON
IGLITE_NOTIFY_EMAIL=you@example.com,soc@example.com          # plus the SMTP settings:
IGLITE_SMTP_HOST=smtp.example.com
IGLITE_SMTP_PORT=587                                         # 587 STARTTLS, 465 TLS
IGLITE_SMTP_USER=...
IGLITE_SMTP_PASSWORD=...
IGLITE_DASHBOARD_URL=http://10.42.0.1:8765                   # optional: a link in each message
```

Only malicious alerts are sent by default (`notify_min_verdict = "suspicious"`
for more), at most `notify_per_hour = 30`. Each message names the device, what
it did, the ATT&CK techniques and the case it was filed in. Check the setup
with `iglite notify --test` or **Send test** in the Cases tab. Offline mode
and the demo never send anything.

## Reducing false positives

Most false alerts come from old evidence, shared infrastructure, noisy feeds,
or things only you know about (your VPN, your lab). IntelGraph Lite handles
each one, and every adjustment appears in the indicator's "why this score"
list.

| Cause | What IntelGraph Lite does |
|-------|---------------------------|
| **Stale evidence**: an IP flagged years ago, since reassigned | Bad evidence carries the date the source last saw it, and its weight halves every 180 days (`evidence_half_life_days`), down to 10%. The reason says e.g. *"last seen 2 years ago, weight 6%"*. |
| **Shared infrastructure**: one Cloudflare/Google/Akamai IP serves thousands of sites | IP reputation on known CDN and big-platform networks counts at half weight (`shared_infra` list in `iglite.toml`). |
| **Noisy signals** | VirusTotal: 1 engine = ignored, 2–4 = suspicious, 5+ = malicious. Shodan/InternetDB `vpn`, `proxy` and `honeypot` tags are recorded but aren't evidence. OTX's own "whitelisted" and "reported false positive" data counts *against* a flag. |
| **Weak single-source hits** | Shown in the Live network table but not alerted. Alerts need a score of at least 60 (`alert_min_score`). |
| **Things only you know** | **Mark false positive** or **Confirm malicious** from an alert, the details panel, or `iglite fp` / `iglite confirm`. Your mark overrides the verdict, resolves its alerts, and stops it spreading suspicion to related indicators. `iglite unmark` undoes it. |
| **Programs you trust** | **Mute** a program in the Live network table, or "Never alert" on an indicator (`iglite suppress process Teams.exe`). It's still scored and shown, just never alerted. |
| **A feed that's usually wrong** | Your marks are tallied per source (`iglite feedback`, and the dashboard's Sources card). A source whose flags you mostly mark as false positives is called out, so you can lower its `trust`. |

```bash
iglite fp 203.0.113.66 --note "office VPN gateway"
iglite confirm evil.example
iglite suppress process "VPNClient.exe" --note "company VPN"
iglite suppress list
iglite feedback          # your marks + false-positive rate per source
```

## AI false-positive triage

A second agent investigates alerts for you. When live monitoring raises an
alert, the triage agent works through the usual causes of false positives,
then gives a verdict: **likely false positive**, **likely real**, or
**uncertain**, with a confidence, short reasons, and a suggested action. The
causes it checks:

* how old and how independent the evidence is
* shared CDN/cloud infrastructure
* which program made the connection, and that program's alert history
* **your own past decisions** on the same network, domain or owner
* each source's false-positive rate

It **only suggests**: its tools are read-only, and nothing is marked until you
click *Apply* in the dashboard.

* **Automatic** for new alerts (`IGLITE_AI_TRIAGE=auto`), capped at 20 runs
  an hour (`ai_triage_per_hour`). Or `manual`, or `off`.
* **On demand**: the **AI check** button on any alert, **Investigate with AI**
  in an indicator's details panel, or the CLI:

```bash
iglite alerts               # recent alerts with their AI verdicts
iglite triage 12            # triage alert #12 now
iglite triage --open        # triage every open alert
iglite triage --indicator 203.0.113.66
```

### Claude or a fully local model

Both AI agents (analyst and triage) run on either backend. Choose in `.env`:

| | Claude (default) | Local model via Ollama |
|---|---|---|
| Set | `ANTHROPIC_API_KEY` (and optionally `ANTHROPIC_BASE_URL`) | `IGLITE_AI_PROVIDER=ollama`, `IGLITE_AI_MODEL=qwen2.5:7b` |
| Install | `pip install .[ai]` | [Ollama](https://ollama.com), then `ollama pull qwen2.5:7b` |
| Privacy | Questions and alert data go to the API | **Nothing leaves your computer** |
| Quality / speed | Strongest reasoning | Smaller models make more mistakes; slower without a GPU |

Any Ollama model that supports tool calling works (`qwen2.5`, `llama3.1`,
`mistral-nemo`, …); larger models triage better. The dashboard and
`iglite triage` show which model and endpoint are in use.

## AI analyst

An optional agent (Claude, or a local model; see above) that investigates for you. Ask in plain
language and it uses IntelGraph Lite's own tools: looking up indicators,
walking the graph, reading live connections and alerts, and running
traceroutes. It then answers with the evidence.

```bash
python -m pip install .[ai]          # adds the anthropic SDK (the only extra dependency)
# put ANTHROPIC_API_KEY=... in your .env (get a key at console.anthropic.com)

iglite ask "Is anything on my network talking to something malicious?"
iglite ask "Triage this report" -f report.txt
iglite chat                          # back-and-forth conversation
```

Or use the **Analyst** tab in the dashboard. Indicators in its answers are
clickable, and every indicator's details panel has an **Ask analyst** button.

* **Grounded:** scores and verdicts come from the evidence engine. The model
  explains and correlates; it doesn't invent findings.
* **Bounded:** at most 10 model turns per question (`ai_max_steps`), and every
  tool runs under the engine's own budget and deadline.
* **Injection-aware:** text from feeds and web pages is treated as data, never
  as instructions.
* **Configurable:** `ai_model` (default `claude-opus-5-5`) and `ai_effort`
  (`low` … `max`, default `high`) in `iglite.toml`, or `--model` / `--effort` on
  the command line. Lower effort is cheaper and faster.
* **Privacy:** the question and whatever its tools read (indicators, your
  connection list, evidence) are sent to Anthropic's API, or to your gateway if
  you set one (below). Nothing is sent until you ask a question.

### Using an Anthropic-compatible gateway

To route the analyst through a third-party gateway or reseller that speaks
the Anthropic Messages API, set these in `.env`:

```ini
ANTHROPIC_API_KEY=your-gateway-key
ANTHROPIC_BASE_URL=https://the-gateway-host
IGLITE_AI_MODEL=the-model-name-the-gateway-expects
```

With a gateway, the analyst sends a plain, standard request: no beta endpoint
and no server-side refusal fallback, since gateways may not support them. The
dashboard shows which endpoint is in use. A gateway sees everything the
analyst sends, so use one you trust. Anthropic's own model IDs use hyphens
(`claude-opus-4-8`, `claude-opus-5-5`); a gateway may use its own names.

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
* **Live network**: live connections with the process (or, in gateway mode, the LAN device), remote address, domain and verdict. Start/stop monitoring, scan now, filter and sort.
* **Network** (gateway mode): every device on the network as a card, a detail panel per device, and a live feed of DNS lookups.
* **Routes**: run a traceroute and watch the hops appear live, each colored by verdict and labeled with its owner, plus a round-trip-time chart. Recent traces can be replayed.
* **Cases**: incidents with their alerts, devices, indicators, ATT&CK techniques, notes and timeline (see [Cases](#cases-from-alerts-to-an-incident)).
* **Graph**: two layouts. **Path** arranges nodes in columns by hop distance from a root, like traceroute (this computer → programs → IPs → domains, plus traced router paths). **Force** is a physics layout. Click a node to see what points at it (orange) and what it points at (blue). **Find path to…** shows the shortest chain linking two nodes, e.g. *Work-Laptop → queried → cdn-update.example ← hosted_on ← the dropper URL*, without going through hubs like shared tags or the gateway. Hide techniques, tags, malware or reports when they clutter the view. Drag, zoom, pan, double-click to expand, filter by verdict, and pick any node as the root.
* **ATT&CK**: the MITRE ATT&CK matrix of techniques seen, by tactic, with the indicators and basis behind each one, and a Navigator layer export.
* **Indicators**: a searchable, sortable list with STIX export.
* **Analyst**: chat with the optional AI analyst (see below).
* **Details panel**: why an indicator got its score, its incoming and outgoing connections, attributes, the cases it is in, and buttons to investigate again, block or quarantine, add it to a case, or find a path to another node.

Keyboard: `1`–`9` switch tabs, `/` focuses search, `Esc` closes details. New alerts pop up as notifications. Polling pauses while the browser tab is
hidden, so an idle dashboard costs nothing.

Example output:

```
MALICIOUS   91  ip:45.155.205.20
           +2.16  urlhaus      hosted 4 malware URL(s), 2 online
           +2.10  feodo        listed in feodo
           +0.72  internetdb   tagged scanner
```

## Sources

| Source | Kind | Key (environment variable) | What it adds |
|--------|------|------------|--------------|
| `dns` | OSINT | none | A/AAAA records (domain → IP pivots) |
| `rdap` | OSINT | none | Registrar, domain age (new domains are suspicious), network owner |
| `crtsh` | OSINT | none | Subdomains from certificate transparency logs |
| `internetdb` | OSINT | none | Open ports, hostnames, CVEs, tags (c2, tor, scanner, …) from Shodan InternetDB |
| `shodan` | OSINT | `SHODAN_API_KEY` | Full Shodan host data: owner, ASN, country, ports, CVEs, tags |
| `otx` | CTI | `OTX_API_KEY` | AlienVault OTX pulses, malware families |
| `virustotal` | CTI | `VIRUSTOTAL_API_KEY` (or `VT_API_KEY`) | Engine detections (rate-limited to the free tier) |
| `urlhaus` | CTI | `ABUSECH_AUTH_KEY` | Malware distribution URLs and payloads |
| *your lists* | feed | none | Any text blocklist/allowlist, local file or URL |

### Adding your API keys

Copy [`.env.example`](.env.example) to `.env` in the folder you run `iglite`
from (or to `~/.iglite/.env` so it works from anywhere) and fill in your keys:

```ini
SHODAN_API_KEY=your-shodan-key
VIRUSTOTAL_API_KEY=your-virustotal-key
OTX_API_KEY=your-otx-key
```

Run `iglite sources` to confirm they show as `enabled`. The dashboard's
Overview tab shows the same thing. `.env` is git-ignored, so keys can't be
committed by accident. Keys are sent only to their own service; they are never
written to the database, logs or error messages. Real environment variables
override `.env`.

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
| `watch_max_new` | 25 | New IPs/domains looked up per live snapshot |
| `gateway_syslog`, `gateway_netflow` | off | `"[host:]port"` to receive syslog / NetFlow on (gateway mode) |
| `gateway_conntrack` | false | Read the NAT table when running on the gateway |
| `gateway_ssh`, `gateway_ssh_port`, `gateway_ssh_key` | off, 22, agent | Read the router over SSH (`user@host`, key login) |
| `gateway_ssh_logs` | true | Also follow the router's log over SSH |
| `gateway_files`, `gateway_leases` | `[]` | Log files to tail; DHCP lease files for device names |
| `gateway_senders` | private IPs | Exporters allowed to send syslog/NetFlow |
| `lan_networks` | private ranges | What counts as inside the network |
| `gateway_include_blocked` | false | Also check flows the firewall blocked |
| `gateway_window` | 300 | Seconds a flow stays in the live table |
| `[devices]` | none | `"192.168.1.40" = "Office printer"` friendly names |

Environment: `IGLITE_DB` (default `~/.iglite/iglite.db`), `IGLITE_API_TOKEN`
(required to serve on a non-localhost interface), and the API keys above.

## Docker

```bash
docker build -t iglite .
docker run -p 8765:8765 -e IGLITE_API_TOKEN=change-me -v iglite:/data iglite

# gateway mode: receive syslog and NetFlow from the router/firewall
docker run -p 8765:8765 -p 5514:5514/udp -p 2055:2055/udp -e IGLITE_API_TOKEN=change-me -v iglite:/data \
  iglite iglite serve --host 0.0.0.0 --syslog 5514 --netflow 2055
```

## Develop

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/pytest            # 163 offline tests, ~10 s
.venv/bin/ruff check src tests
```

## Credits

Created and maintained by **Ashvin Auti**. The approach (multi-source
correlation, evidence-based verdicts, contradiction detection, STIX export) is
inspired by [IntelGraph](https://github.com/Berkayy123-h/intelgraph) by
Berkay Altıntaş. IntelGraph Lite is an independent codebase. MIT licensed.
