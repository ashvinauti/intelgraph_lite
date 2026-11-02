# Installing IntelGraph Lite

Three ways to run it:

| Setup | What it watches | Section |
|-------|-----------------|---------|
| **Ubuntu gateway** (recommended) | Every device on your network: the Ubuntu machine shares its wired internet as a Wi-Fi hotspot and checks everything that goes through it | [1](#1-ubuntu-gateway-fresh-system) |
| **Windows PC with Mobile hotspot** | Every device on the PC's Wi-Fi hotspot (only those) | [2](#2-windows-mobile-hotspot) |
| **Windows, macOS or Linux PC** | That one computer's own connections, or the demo | [2b](#2b-windows-macos-or-linux-one-computer) |
| **Your own router** (OpenWrt, ASUS, pfSense) | Every device, read from the router over SSH | README, "Connect over SSH" |

Then [find and add your keys](#3-keys-and-tokens), and keep it [up to date](#4-updating).

---

## 1. Ubuntu gateway (fresh system)

```
internet ─ your router ─ ethernet ─► Ubuntu machine (hotspot + IntelGraph Lite) ─ Wi-Fi ─► your devices
```

### What you need

- **Ubuntu 24.04 or newer** (Python 3.11+ is required; 22.04 ships 3.10 and won't work).
  Desktop or server, with NetworkManager (Ubuntu Desktop has it).
- **A wired internet connection** (ethernet to your router), so the Wi-Fi card is free to be the hotspot.
- **A Wi-Fi card that can be an access point.** Check:
  ```bash
  sudo apt install -y iw
  iw list | grep -A10 "Supported interface modes" | grep -w AP && echo "AP mode: OK"
  ```
- About 1 GB of free disk space (the database grows by roughly 1 MB a day on a home network).

### Install

Run these as your normal user, **one line at a time**. Only lines that start with `sudo` need it.
Never run `git` with `sudo`: it leaves files your user can't update later.

```bash
# 1. Tools
sudo apt update && sudo apt install -y git

# 2. Get the code (into your home folder)
cd ~
git clone https://github.com/ashvinauti/intelgraph_lite.git
cd intelgraph_lite

# 3. Try the setup without changing anything: it prints every step
sudo scripts/gateway-hotspot.sh --dry-run --ssid "HomeSecure" --password "choose-a-strong-password"

# 4. Run it for real
sudo scripts/gateway-hotspot.sh --ssid "HomeSecure" --password "choose-a-strong-password"
```

If `git clone` asks for a username and password, the repository is private: sign in with
your GitHub username and a [personal access token](https://github.com/settings/tokens) as the
password (a token with "repo" read access).

The script:
- creates the Wi-Fi hotspot `HomeSecure` sharing the wired connection;
- makes the hotspot's DNS log every lookup and device name;
- installs IntelGraph Lite in `/opt/iglite` (with the AI analyst) and runs it as the
  `iglite-gateway` service, started on boot;
- only counts hotspot clients (`10.42.0.0/24`) as devices, and enforces **Block** /
  **Quarantine** with nftables;
- keeps the machine awake with the lid closed (`--no-keep-awake` to skip).

Options: `--wifi wlp2s0 --wan enp1s0f1` if it picks the wrong network cards (see
`nmcli device status`), `--band a` for 5 GHz, `--token ...` to choose the dashboard token yourself.

At the end it prints the dashboard addresses and the **API token**: save them.

### Finish

```bash
# 5. Download the popular-sites list and Google/CloudFront address ranges (hides routine traffic)
sudo /opt/iglite/venv/bin/iglite common update

# 6. Add your threat-intel keys (section 3), then restart
sudo nano /etc/iglite/.env
sudo systemctl restart iglite-gateway

# 7. Check
systemctl status iglite-gateway --no-pager | head -5      # active (running)
/opt/iglite/venv/bin/iglite --version
```

### Use it

Connect your phones, laptops and TV to the `HomeSecure` Wi-Fi. Then open the dashboard:

| From | Address |
|------|---------|
| the Ubuntu machine itself | `http://127.0.0.1:8765` |
| a device on the hotspot | `http://10.42.0.1:8765` |
| a computer on your home network | `http://<the Ubuntu machine's address>:8765` (shown at the end of setup; `ip -4 addr` shows it too) |

Enter the API token when it asks. **Tip:** give the hotspot the same name and password as
your router's Wi-Fi and switch the router's Wi-Fi off: every device moves over by itself.

Behaviour analysis learns each device's habits for 7 days before it flags changes;
beaconing and generated-looking domains are flagged from day one.

---

## 2. Windows Mobile hotspot

```
internet ─ your router ─ ethernet ─► Windows PC (Mobile hotspot + IntelGraph Lite) ─ Wi-Fi ─► your devices
```

Windows' **Mobile hotspot** shares the PC's internet over Wi-Fi; its devices get
`192.168.137.x` addresses. IntelGraph Lite watches **only those devices**: it captures the
hotspot adapter alone (with Wireshark's `tshark`), keeps just the first packet of each new
connection plus DNS and DHCP, and counts only `192.168.137.0/24` as devices. The PC's own
browsing doesn't go through that adapter, so it isn't watched.

### What you need

- **Windows 10 or 11** with Wi-Fi, and the internet on **Ethernet** (or a second Wi-Fi adapter).
- **Python 3.11+**: the installer gets Python 3.12 with `winget` if it's missing.
- **Wireshark** with the **Npcap** driver: the installer gets Wireshark with `winget`;
  Npcap must be installed by hand once from [npcap.com](https://npcap.com/#download) (default
  options; leave *"Restrict Npcap driver's access to Administrators only"* unticked).

### Install

1. **Turn the hotspot on:** Settings › Network & internet › **Mobile hotspot** ›
   *Share my internet connection from:* **Ethernet** › set a network name and password ›
   **On**. (Optional: *Power saving* off, so it stays on when no device is connected.)
2. **Get the code:** on GitHub **Code › Download ZIP** and unzip it, or
   `git clone https://github.com/ashvinauti/intelgraph_lite.git`.
3. **Run the installer** in **PowerShell as Administrator** (Start › type PowerShell ›
   right-click › *Run as administrator*), inside that folder:
   ```powershell
   cd "C:\Users\you\Downloads\intelgraph_lite"
   powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
   ```
   It finds or installs Python and Wireshark, finds the hotspot adapter, installs
   IntelGraph Lite in `%LOCALAPPDATA%\IntelGraphLite`, makes your **dashboard token**,
   **asks for your API keys** (Enter skips one; see [section 3](#3-keys-and-tokens) for where
   to get them), downloads the popular-site list, opens the dashboard port to local
   networks in Windows Firewall, and starts IntelGraph Lite hidden, now and at every log-on.
   At the end it prints the addresses and the token, and puts an **IntelGraph Lite**
   shortcut on the desktop.

### Use it

| From | Address |
|------|---------|
| this PC | `http://127.0.0.1:8765` (desktop shortcut) |
| a device on the hotspot | `http://192.168.137.1:8765` |
| a computer on your home network | `http://<this PC's address>:8765` (printed at the end) |

Connect phones and laptops to the hotspot's Wi-Fi; they appear under **Network** within a
scan. Settings and keys live in `%USERPROFILE%\.iglite\.env`, the database and the log
(`service.log`) next to it.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -Keys        # change API keys
powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -SkipKeys    # install without asking
powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -Uninstall   # remove (keeps your data)
```

**Differences from the Ubuntu gateway:** **Block** and **Quarantine** go into the
blocklist feeds and case timelines but aren't enforced on the PC (Windows' hotspot has no
firewall hook for shared traffic). Windows turns the hotspot off after a while with no
devices unless *Power saving* is off; IntelGraph Lite picks the capture back up when it's on
again. Wi-Fi hotspot devices only: Ethernet devices behind the PC aren't seen.

## 2b. Windows, macOS or Linux (one computer)

1. Install **Python 3.11 or newer** from [python.org](https://www.python.org/downloads/).
   On Windows, tick **"Add python.exe to PATH"** in the installer.
2. Get the code: `git clone https://github.com/ashvinauti/intelgraph_lite.git`, or on GitHub
   **Code › Download ZIP** and unzip it.
3. In a terminal (PowerShell on Windows) inside that folder:
   ```bash
   pip install ".[ai]"        # or just: pip install .   (without the AI analyst)
   iglite --version
   ```
   If `iglite` isn't found (Windows: "not recognized"), use `python -m iglite` instead, or add
   the Scripts folder pip names in its warning to your PATH:
   ```powershell
   $dir = "<the folder from pip's WARNING line>"
   $user = [Environment]::GetEnvironmentVariable("Path", "User")
   [Environment]::SetEnvironmentVariable("Path", "$user;$dir", "User")
   # then open a new PowerShell window
   ```
4. Run it:
   ```bash
   iglite demo                 # a simulated network, nothing to set up
   iglite serve --watch        # watch this computer's connections: http://127.0.0.1:8765
   iglite investigate 8.8.8.8  # look something up
   ```

**One file to share:** `python scripts/build-pyz.py` builds `dist/iglite.pyz`; anyone with
Python 3.11+ runs `python iglite.pyz demo`.

---

## 3. Keys and tokens

There are two different kinds.

### The dashboard's API token (yours, protects the dashboard)

| Setup | Where it is |
|-------|-------------|
| Ubuntu gateway | `sudo grep IGLITE_API_TOKEN /etc/iglite/.env` (also printed at the end of setup) |
| Windows Mobile hotspot | Printed at the end of the installer; also `IGLITE_API_TOKEN=` in `%USERPROFILE%\.iglite\.env` (open it with `notepad $env:USERPROFILE\.iglite\.env`) |
| One computer (any system) | Only needed to open the dashboard from another machine (`iglite serve --host 0.0.0.0`): put `IGLITE_API_TOKEN=...` in your `.env` (below) |

To change it, make a new one with `openssl rand -hex 16` (or any long random text), put it
in the file, and restart (`sudo systemctl restart iglite-gateway`). The browser asks for it
once per session.

### Threat-intelligence API keys (from each service, all optional)

Without any keys IntelGraph Lite still works: DNS, RDAP, certificate logs, Shodan InternetDB
and the free blocklists need none. Each key switches on one more source.

| Source | Sign up / find the key | Line in `.env` | Free tier |
|--------|------------------------|----------------|-----------|
| **AlienVault OTX** | Create an account at [otx.alienvault.com](https://otx.alienvault.com), then click your username › **Settings**: the key is under **OTX Key** | `OTX_API_KEY=` | free |
| **VirusTotal** | Sign up at [virustotal.com](https://www.virustotal.com), then click your profile picture (top right) › **API key** | `VIRUSTOTAL_API_KEY=` | free: 4 lookups a minute, 500 a day |
| **Shodan** | Sign up at [account.shodan.io](https://account.shodan.io): the **API Key** is on your account page | `SHODAN_API_KEY=` | free account has limited lookups; the one-off membership gives more |
| **abuse.ch** (URLhaus) | Log in at [auth.abuse.ch](https://auth.abuse.ch) with an existing account (for example Google or GitHub), then generate an **Auth-Key** on your profile page | `ABUSECH_AUTH_KEY=` | free |
| **Anthropic** (AI analyst and AI triage) | [console.anthropic.com](https://console.anthropic.com) › **API Keys** › **Create Key** (paid by usage) | `ANTHROPIC_API_KEY=` | pay as you go |

Sites change their menus from time to time; if a step has moved, look for "API key" in
your account or profile settings.

**Where the keys go**

| Setup | File |
|-------|------|
| Ubuntu gateway | `/etc/iglite/.env`: `sudo nano /etc/iglite/.env`, add the lines, save (Ctrl+O, Enter, Ctrl+X), then `sudo systemctl restart iglite-gateway` |
| Windows | `%USERPROFILE%\.iglite\.env` (e.g. `C:\Users\you\.iglite\.env`): the hotspot installer asks for the keys and writes this file (re-run it with `-Keys` to change them), or edit it with `notepad $env:USERPROFILE\.iglite\.env` and then restart it with `Stop-ScheduledTask "IntelGraph Lite"; Start-ScheduledTask "IntelGraph Lite"` |
| macOS / Linux | `~/.iglite/.env` or `.env` in the folder you run from |

Example:

```ini
OTX_API_KEY=0123abcd...
VIRUSTOTAL_API_KEY=89ef...
SHODAN_API_KEY=Ab12...
ABUSECH_AUTH_KEY=4567...
ANTHROPIC_API_KEY=sk-ant-...
```

Check: `iglite sources` (gateway: `sudo /opt/iglite/venv/bin/iglite --db /var/lib/iglite/iglite.db sources`)
lists each source as `enabled`; so does the dashboard's Overview › Sources card.

Keep keys private: never paste them into chats, screenshots or tickets. If one leaks,
revoke it on the service's site and make a new one. `.env` files are git-ignored, so
they can't be committed by accident.

Optional extras in the same file: `IGLITE_NOTIFY_SLACK`, `IGLITE_NOTIFY_TEAMS`,
`IGLITE_NOTIFY_EMAIL` + `IGLITE_SMTP_*` for alert notifications (README, "Alert
notifications"), and `ANTHROPIC_BASE_URL` for an Anthropic-compatible gateway.

---

## 4. Updating

Ubuntu gateway:

```bash
cd ~/intelgraph_lite && git pull
sudo /opt/iglite/venv/bin/pip install --force-reinstall --no-deps .
sudo systemctl restart iglite-gateway
/opt/iglite/venv/bin/iglite --version
```

The database upgrades itself on start; nothing is lost. Reload the dashboard with
**Ctrl+Shift+R**. Run `sudo /opt/iglite/venv/bin/iglite common update` again now and then
(monthly) to refresh the popular-sites list and address ranges.

Windows hotspot: get the new code (`git pull` or a new ZIP), then run the installer again
(`-SkipKeys` keeps your keys); it updates IntelGraph Lite in place and restarts it.

Windows / one computer: get the new code (`git pull` or a new ZIP), then `pip install .` again.

## 5. Uninstalling the gateway

```bash
sudo ~/intelgraph_lite/scripts/gateway-hotspot.sh --uninstall
```

It removes the hotspot, the service and its settings, and keeps `/opt/iglite` (the
program), `/etc/iglite` (your token and keys) and `/var/lib/iglite` (the database). Delete
those by hand if you want them gone.

## 6. Troubleshooting

| Problem | Fix |
|---------|-----|
| `git pull`: "insufficient permission for adding an object" | Something ran git with sudo. `sudo chown -R "$USER":"$USER" ~/intelgraph_lite`, then pull again |
| Setup stops: "nmcli ... NetworkManager ... update was installed" | `sudo systemctl restart NetworkManager`, then run the script again |
| Setup stops: "does not support access-point mode" | The Wi-Fi card can't be a hotspot; use a USB Wi-Fi adapter that supports AP mode |
| Dashboard won't load | `systemctl status iglite-gateway` and `sudo journalctl -u iglite-gateway -n 40`; a setting typed twice in `/etc/iglite/iglite.toml` stops the service |
| Devices don't appear | Are they on the hotspot Wi-Fi (address `10.42.0.x`)? Check `sudo tail -f /var/log/hotspot-dns.log` while one browses |
| `iglite` not found on Windows | `python -m iglite ...`, or add the Scripts folder to PATH (section 2b) |
| Windows installer: "The Mobile hotspot is off" | Turn it on (section 2, step 1), then run the installer again |
| Windows installer: "Npcap capture driver is missing" | Install Npcap from npcap.com with default options, then run the installer again |
| Windows: no devices appear | Open `%USERPROFILE%\.iglite\service.log`: "capture ... ended" means the hotspot went off or Npcap is restricted to administrators |
| Windows: "running scripts is disabled" | Start it as shown: `powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1` |
| Sources show "no key" | Key line missing or misspelled in `.env`, or the service wasn't restarted |
