# Changelog

## 0.2.0

### Behaviour analysis (new)
- Every device (or program, on a single computer) gets a **baseline** after
  `behaviour_learn_days` (7): the servers, sites and ports it uses, whether
  anything connects in, the hours it is active and how busy a normal hour is.
- Detectors: **beaconing** (regular check-ins to one server, counted from new
  connections including ones already closing), **generated-looking domains**
  (DGA), **new inbound** connections, **new ports** (risky ports such as 4444,
  3333, 22, 3389 are high), **new destinations** for devices with few habits,
  **bursts** of new destinations, **unusual hours** and **traffic spikes**.
  Beaconing and generated domains count from day one; the rest need a baseline.
- Common services never count. Each finding is stored once per device, kind
  and target, counted (not repeated) for a day; **This is normal** teaches it
  never to raise that one again.
- Beaconing, generated domains and risky new ports add `behaviour` evidence to
  the target's score, so an unknown C2 server can turn suspicious with no feed
  knowing it.
- New findings go into the timeline of open cases about the device and to
  notifications (`behaviour_notify = "high"`).
- Behaviour tab, a Behaviour section in the details panel,
  `/api/behaviour`, `iglite behaviour [list|devices|mark]`.
- The demo seeds a week of normal life and adds two incidents only behaviour
  analysis catches: a doorbell checking in with an unknown server and a
  printer looking up generated domains.

### Since 0.1.0
- **Live graph**: new devices, servers and sites appear as they connect; active
  links animate.
- **Connection database**: every connection and DNS lookup, one row per
  endpoint per day, searchable in Live network › History, CSV export,
  `iglite connections`; 90-day retention.
- **Hide common services** (Google, Apple, Microsoft, CDNs...) from the graph,
  with a built-in catalogue, the Tranco popular-domain list
  (`iglite common update`) and a list of popular-but-abused services that are
  always shown.
- **Cases**: incidents grouping alerts, devices and indicators, with notes,
  timeline and a Markdown report; alerts file themselves into the right case.
- **Block / Quarantine** from the dashboard, enforced with nftables and a
  dnsmasq hosts file on the gateway, and always in the blocklist feeds.
- **Graph**: click a node for its incoming and outgoing connections, arrowed
  edges, **Find path to…** between two nodes, and filters for noisy node kinds.
- **Alert notifications** to Slack, Teams, email or a webhook.
- **Demo** (`iglite demo`) and a one-file build (`iglite.pyz`) for sharing.
- Gateway mode: Network tab, router over SSH (OpenWrt, ASUS, pfSense), the
  one-command Ubuntu hotspot gateway, older routers' `ip_conntrack` table.
- Database schema 8 (upgraded in place from earlier versions).
