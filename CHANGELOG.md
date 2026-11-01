# Changelog

## 0.2.3

- The graph and its live updates apply the same device rule as the device
  list: addresses older versions recorded by mistake (the gateway's own,
  link-local, neighbours outside `lan_networks`) no longer hang off the
  gateway. Asked for by name, such a node is still shown.

## 0.2.2

Found on a real hotspot gateway: the device list held the gateway's own
addresses and upstream neighbours, not just hotspot clients.

- **Multicast is not the internet.** Python's `ipaddress` calls `224.0.0.251`
  (mDNS), `239.255.255.250` (SSDP) and `ff02::fb` "global", so every device
  announcing itself on the local network looked like one talking to the
  internet. Multicast is now never a public address.
- **The gateway isn't a device.** When reading the connection table on the
  gateway itself, its own addresses (uplink, hotspot, Docker/VM bridges) are
  excluded, as are link-local, loopback and unspecified addresses.
- The hotspot script passes `--lan 10.42.0.0/24`, so only hotspot clients
  count as devices.
- Addresses older versions recorded by mistake drop out of the device list,
  the Behaviour tab and `iglite devices`; the connection history is kept.

## 0.2.1

- **Active devices only, by default.** The Network tab and the graph show the
  devices with traffic in the last 5 minutes (`device_active_secs`); **Today**
  and **All devices** bring back the quiet and the offline ones. In the live
  graph a device that goes quiet leaves, with whatever only it connected to.
- **Device inventory**: every device ever active, with first and last activity,
  total connections and lookups (filled from the connection log on upgrade).
  `iglite devices [--today|--all]`, `/api/devices?state=active|today|all`.
- **Traffic per device**: a 24-hour strip on each device card and a per-hour
  chart in its details; a "connections this hour" total.
- A device's DNS lookups are grouped by site with a count.
- Database schema 9.

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
