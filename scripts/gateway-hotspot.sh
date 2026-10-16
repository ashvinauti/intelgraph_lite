#!/usr/bin/env bash
# Turn an Ubuntu laptop/PC into a monitored internet gateway for your home network.
#
#   internet ─ your router ─ethernet─► this machine (Wi-Fi hotspot + IntelGraph Lite) ─Wi-Fi─► your devices
#
# What it does (all reversible with --uninstall):
#   1. creates a NetworkManager Wi-Fi hotspot that shares this machine's wired connection
#   2. makes the hotspot's DNS/DHCP server (dnsmasq) log lookups and device names
#   3. lets hotspot traffic through Docker's firewall rules, if Docker is installed
#   4. installs IntelGraph Lite in /opt/iglite and runs it as a service, started on boot,
#      watching the hotspot's connection table and DNS log (gateway mode)
#   5. keeps the machine awake with the lid closed (skip with --no-keep-awake)
#
# Usage:
#   sudo scripts/gateway-hotspot.sh --ssid HomeSecure --password 'at-least-8-chars'
#   sudo scripts/gateway-hotspot.sh --ssid HomeSecure --password '...' --wifi wlp2s0 --wan enp1s0f1
#   sudo scripts/gateway-hotspot.sh --dry-run ...     # print what it would do
#   sudo scripts/gateway-hotspot.sh --uninstall
#
# Tip: give the hotspot the same name and password as your router's Wi-Fi, then switch the
# router's Wi-Fi off: every device moves to the hotspot without changing anything on it.

set -euo pipefail

CON=iglite-hotspot
SSID="" PASSWORD="" WIFI="" WAN="" BAND=bg TOKEN="" DRY=0 UNINSTALL=0 KEEP_AWAKE=1 SERVICE=1
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX=/opt/iglite ETC=/etc/iglite DATA=/var/lib/iglite DNSLOG=/var/log/hotspot-dns.log

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
run() { if [ "$DRY" = 1 ]; then printf '    %s\n' "$*"; else "$@"; fi; }
write() { # write FILE MODE  (content on stdin)
  if [ "$DRY" = 1 ]; then printf '    write %s:\n' "$1"; sed 's/^/      | /'; else install -D -m "$2" /dev/stdin "$1"; fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ssid) SSID="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --wifi) WIFI="$2"; shift 2 ;;
    --wan) WAN="$2"; shift 2 ;;
    --band) BAND="$2"; shift 2 ;;            # bg = 2.4 GHz (widest support), a = 5 GHz
    --token) TOKEN="$2"; shift 2 ;;
    --no-keep-awake) KEEP_AWAKE=0; shift ;;
    --no-service) SERVICE=0; shift ;;
    --dry-run) DRY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then echo "run with sudo" >&2; exit 1; fi

if [ "$UNINSTALL" = 1 ]; then
  say "Removing the hotspot, the service and their settings"
  run systemctl disable --now iglite-gateway.service || true
  run rm -f /etc/systemd/system/iglite-gateway.service
  run nmcli connection delete "$CON" || true
  run rm -f /etc/NetworkManager/dnsmasq-shared.d/iglite.conf /etc/NetworkManager/dispatcher.d/90-iglite-hotspot \
    /etc/logrotate.d/iglite-hotspot /etc/systemd/logind.conf.d/iglite-gateway.conf
  run systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target || true
  run systemctl daemon-reload
  echo "Kept: $PREFIX (the program), $ETC (your token and keys), $DATA (the database). Delete them by hand if you like."
  exit 0
fi

[ -n "$SSID" ] || { echo "--ssid is required" >&2; usage 1; }
[ "${#PASSWORD}" -ge 8 ] || { echo "--password must be at least 8 characters" >&2; exit 1; }

# -- interfaces ---------------------------------------------------------------------------
if [ -z "$WIFI" ]; then
  WIFI="$(nmcli -t -f DEVICE,TYPE device status 2>/dev/null | awk -F: '$2=="wifi"{print $1; exit}' || true)"
fi
if [ -z "$WAN" ]; then
  WAN="$(ip route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
fi
[ -n "$WIFI" ] || { echo "no Wi-Fi interface found; pass --wifi" >&2; exit 1; }
[ -n "$WAN" ] || { echo "no internet connection found; plug in the ethernet cable or pass --wan" >&2; exit 1; }
[ "$WIFI" != "$WAN" ] || { echo "the hotspot needs the internet to come from another interface (ethernet), not $WIFI" >&2; exit 1; }
if [ "$DRY" = 0 ] && command -v iw >/dev/null && ! iw list 2>/dev/null | grep -q '^[[:space:]]*\* AP$'; then
  echo "this Wi-Fi card does not support access-point (hotspot) mode" >&2; exit 1
fi
say "Hotspot on $WIFI, internet from $WAN"

# -- 1. Wi-Fi on, DNS/DHCP logging ----------------------------------------------------------
run rfkill unblock wifi || true
run nmcli radio wifi on
say "Logging DNS lookups and DHCP device names to $DNSLOG"
write /etc/NetworkManager/dnsmasq-shared.d/iglite.conf 0644 <<EOF
# IntelGraph Lite: log every lookup and lease from the hotspot (read by iglite --tail)
log-queries
log-dhcp
log-facility=$DNSLOG
EOF
write /etc/logrotate.d/iglite-hotspot 0644 <<EOF
$DNSLOG {
  daily
  rotate 7
  compress
  missingok
  notifempty
  copytruncate
}
EOF

# -- 2. the hotspot -------------------------------------------------------------------------
say "Creating the Wi-Fi hotspot \"$SSID\""
run nmcli connection delete "$CON" >/dev/null 2>&1 || true
run nmcli connection add type wifi ifname "$WIFI" con-name "$CON" autoconnect yes ssid "$SSID"
run nmcli connection modify "$CON" 802-11-wireless.mode ap 802-11-wireless.band "$BAND" \
  ipv4.method shared ipv6.method ignore wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PASSWORD" \
  connection.autoconnect-priority 100

# -- 3. Docker's firewall drops forwarded traffic: let the hotspot through ------------------
write "$ETC/hotspot-forward.sh" 0755 <<EOF
#!/bin/sh
# Allow hotspot <-> internet forwarding past Docker's DROP policy (no-op without Docker).
command -v iptables >/dev/null || exit 0
command -v docker >/dev/null || iptables -nL DOCKER-USER >/dev/null 2>&1 || exit 0
iptables -nL DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER
iptables -C DOCKER-USER -i $WIFI -o $WAN -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i $WIFI -o $WAN -j ACCEPT
iptables -C DOCKER-USER -i $WAN -o $WIFI -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \\
  || iptables -I DOCKER-USER -i $WAN -o $WIFI -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
EOF
write /etc/NetworkManager/dispatcher.d/90-iglite-hotspot 0755 <<EOF
#!/bin/sh
[ "\$1" = "$WIFI" ] && [ "\$2" = "up" ] && exec $ETC/hotspot-forward.sh
exit 0
EOF

# -- 4. IntelGraph Lite as a service ---------------------------------------------------------
if [ "$SERVICE" = 1 ]; then
  say "Installing IntelGraph Lite from $REPO into $PREFIX"
  run apt-get install -y -q python3-venv conntrack
  [ -x "$PREFIX/venv/bin/python" ] || run python3 -m venv "$PREFIX/venv"
  run "$PREFIX/venv/bin/pip" install -q --upgrade "$REPO"
  run mkdir -p "$DATA"
  if [ "$DRY" = 1 ] || [ ! -f "$ETC/.env" ]; then
    [ -n "$TOKEN" ] || TOKEN="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
    write "$ETC/.env" 0600 <<EOF
# IntelGraph Lite gateway service. Add API keys here (see .env.example), then:
#   sudo systemctl restart iglite-gateway
IGLITE_API_TOKEN=$TOKEN
EOF
  else
    TOKEN="$(sed -n 's/^IGLITE_API_TOKEN=//p' "$ETC/.env" | head -1)"
  fi
  if [ ! -f "$ETC/iglite.toml" ] && [ -f "$REPO/iglite.example.toml" ]; then
    run install -m 0644 "$REPO/iglite.example.toml" "$ETC/iglite.toml"
  fi
  write /etc/systemd/system/iglite-gateway.service 0644 <<EOF
[Unit]
Description=IntelGraph Lite network monitoring (Wi-Fi hotspot gateway)
After=network-online.target NetworkManager.service docker.service
Wants=network-online.target

[Service]
WorkingDirectory=$ETC
EnvironmentFile=$ETC/.env
ExecStartPre=-$ETC/hotspot-forward.sh
ExecStart=$PREFIX/venv/bin/iglite --db $DATA/iglite.db serve --host 0.0.0.0 --conntrack --tail $DNSLOG \\
  --leases /var/lib/NetworkManager/dnsmasq-$WIFI.leases
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
fi

# -- 5. stay awake ---------------------------------------------------------------------------
if [ "$KEEP_AWAKE" = 1 ]; then
  say "Keeping the machine awake with the lid closed"
  write /etc/systemd/logind.conf.d/iglite-gateway.conf 0644 <<EOF
[Login]
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
EOF
  run systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
fi

# -- start --------------------------------------------------------------------------------------
say "Starting"
run systemctl daemon-reload
run nmcli connection up "$CON"
run "$ETC/hotspot-forward.sh"
[ "$SERVICE" = 0 ] || run systemctl enable --now iglite-gateway.service
[ "$KEEP_AWAKE" = 0 ] || run systemctl kill -s HUP systemd-logind || true

LAN_IP="$(ip -4 -o addr show "$WAN" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
LAN_IP="${LAN_IP:-THIS-MACHINE-IP}"
cat <<EOF

Done. Connect a phone to the Wi-Fi "$SSID" and browse a little, then open the dashboard:
  on this machine:         http://127.0.0.1:8765/#network
  from your other network: http://$LAN_IP:8765/#network
  from the hotspot:        http://10.42.0.1:8765/#network
  API token:               ${TOKEN:-(see $ETC/.env)}

Check:   systemctl status iglite-gateway      sudo tail -f $DNSLOG
Logs:    journalctl -u iglite-gateway -f
Undo:    sudo $0 --uninstall
EOF
