"""Response actions: block an indicator or quarantine a device, and undo it.

A block is recorded in the database first, so it always reaches the blocklist feeds
(``/api/blocklist/*.txt``) that a router, firewall or DNS filter can pull. When
IntelGraph Lite runs on the gateway itself it can also enforce blocks right away:

* ``enforce = "nftables"``: blocked IPs and quarantined devices go into an
  nftables table of their own (``inet iglite``), dropped in the forward and
  output paths. The whole table is rewritten from the database on every change,
  so it is always exactly what the dashboard shows. A quarantined device can
  still reach the gateway itself (DHCP, DNS, this dashboard), nothing beyond.
* ``block_hosts = "/path/blocked.hosts"``: blocked domains are written as
  ``0.0.0.0 name`` lines and dnsmasq is told to reload them (SIGHUP), so the
  gateway's DNS stops answering for them. Exact names only, not subdomains.

Domains are never turned into IP blocks: one IP can serve thousands of sites.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from . import cases
from .extract import classify
from .model import Kind
from .store import Store

TABLE = "iglite"


def parse_target(value: str, device: bool = False) -> tuple[str, str]:
    """('indicator', key) or ('device', lan ip) from what a person typed."""
    value = (value or "").strip()
    if device or value.startswith("host:"):
        ip = value.removeprefix("host:")
        try:
            if ipaddress.ip_address(ip).version != 4:
                raise ValueError
        except ValueError:
            raise ValueError(f"a device is quarantined by its IPv4 LAN address, not {ip!r}")
        return "device", ip
    kind, _, rest = value.partition(":")
    ind = classify(rest if kind in ("ip", "domain", "url") else value)
    if ind is None or ind.kind not in (Kind.IP, Kind.DOMAIN, Kind.URL):
        raise ValueError(f"only IPs, domains and URLs can be blocked, not {value!r}")
    return "indicator", ind.key


def block(
    engine: Any, value: str, *, device: bool = False, note: str = "", case_id: int | None = None
) -> dict[str, Any]:
    kind, target = parse_target(value, device)
    store: Store = engine.store
    if case_id is not None:
        cases._require(store, case_id)
    added = store.add_block(kind, target, note, case_id)
    what = f"Device {target} quarantined" if kind == "device" else f"Blocked {target}"
    if added:
        for cid in {
            case_id,
            *store.cases_with_indicator(target if kind == "indicator" else f"host:{target}"),
        } - {None}:
            store.add_case_event(cid, "block", what + (f": {note}" if note else ""))
    status = enforcer(engine.config).apply(store)
    return {"kind": kind, "value": target, "added": added, "enforcement": status}


def unblock(engine: Any, value: str, *, device: bool = False) -> dict[str, Any]:
    kind, target = parse_target(value, device)
    store: Store = engine.store
    row = store.remove_block(kind, target)
    if row is None:
        raise KeyError(f"{target} is not blocked")
    what = f"Device {target} released from quarantine" if kind == "device" else f"Unblocked {target}"
    for cid in {
        row["case_id"],
        *store.cases_with_indicator(target if kind == "indicator" else f"host:{target}"),
    } - {None}:
        store.add_case_event(cid, "block", what)
    status = enforcer(engine.config).apply(store)
    return {"kind": kind, "value": target, "enforcement": status}


def blocked_keys(store: Store) -> set[str]:
    """Indicator keys and ``host:<ip>`` device keys currently blocked."""
    return {b["value"] if b["kind"] == "indicator" else f"host:{b['value']}" for b in store.blocks()}


# -- enforcement --------------------------------------------------------------------------


class Enforcer:
    """Pushes the blocks table to the local firewall / DNS. The base class does nothing."""

    name = "none"

    def __init__(self, cfg: Any) -> None:
        self.cfg = cfg

    def apply(self, store: Store) -> dict[str, Any]:
        return {"enforcer": self.name, "ok": True, "detail": "blocklist feeds only (no firewall connected)"}


def _split(store: Store) -> tuple[list[str], list[str], list[str], list[str]]:
    v4, v6, devices, domains = [], [], [], []
    for b in store.blocks():
        kind, _, value = b["value"].partition(":")
        if b["kind"] == "device":
            devices.append(b["value"])
        elif kind == "ip":
            (v6 if ":" in value else v4).append(value)
        elif kind == "domain":
            domains.append(value)
        elif kind == "url":
            host = classify(value.split("/")[2]) if value.count("/") >= 2 else None
            if host is not None and host.kind is Kind.DOMAIN:
                domains.append(host.value)
    return sorted(set(v4)), sorted(set(v6)), sorted(set(devices)), sorted(set(domains))


def nft_script(v4: list[str], v6: list[str], devices: list[str]) -> str:
    """The whole ``inet iglite`` table: created, emptied and refilled in one atomic load."""

    def elements(values: list[str]) -> str:
        return f"elements = {{ {', '.join(values)} }}; " if values else ""

    return "\n".join(
        [
            f"table inet {TABLE}",  # so the delete below never fails
            f"delete table inet {TABLE}",
            f"table inet {TABLE} {{",
            f"  set block4 {{ type ipv4_addr; {elements(v4)}}}",
            f"  set block6 {{ type ipv6_addr; {elements(v6)}}}",
            f"  set quarantine4 {{ type ipv4_addr; {elements(devices)}}}",
            "  chain forward {",
            "    type filter hook forward priority -5; policy accept;",
            "    ip daddr @block4 counter drop",
            "    ip saddr @block4 counter drop",
            "    ip6 daddr @block6 counter drop",
            "    ip6 saddr @block6 counter drop",
            "    ip saddr @quarantine4 counter drop",
            "    ip daddr @quarantine4 counter drop",
            "  }",
            "  chain output {",
            "    type filter hook output priority -5; policy accept;",
            "    ip daddr @block4 counter drop",
            "    ip6 daddr @block6 counter drop",
            "  }",
            "}",
            "",
        ]
    )


def _reload_dnsmasq() -> int:
    """SIGHUP every dnsmasq started by NetworkManager (the hotspot's), so it rereads hosts files."""
    sent = 0
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            cmd = (proc / "cmdline").read_bytes().replace(b"\0", b" ")
        except OSError:
            continue
        if (
            cmd.startswith((b"dnsmasq", b"/usr/sbin/dnsmasq", b"/usr/bin/dnsmasq"))
            and b"NetworkManager" in cmd
        ):
            try:
                os.kill(int(proc.name), signal.SIGHUP)
                sent += 1
            except OSError:
                pass
    return sent


class LocalEnforcer(Enforcer):
    """nftables for IPs and devices, a dnsmasq hosts file for domains (either may be off)."""

    def __init__(self, cfg: Any, *, run: Any = subprocess.run, reload_dns: Any = _reload_dnsmasq) -> None:
        super().__init__(cfg)
        self.nft = (cfg.enforce or "").lower() == "nftables"
        self.hosts = cfg.block_hosts
        self.name = "+".join(n for n, on in (("nftables", self.nft), ("dnsmasq", bool(self.hosts))) if on)
        self._run, self._reload = run, reload_dns

    def apply(self, store: Store) -> dict[str, Any]:
        v4, v6, devices, domains = _split(store)
        notes, ok = [], True
        if self.nft:
            nft = shutil.which("nft") or "/usr/sbin/nft"
            try:
                res = self._run(
                    [nft, "-f", "-"],
                    input=nft_script(v4, v6, devices),
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                if res.returncode != 0:
                    ok = False
                    notes.append(f"nftables failed: {(res.stderr or '').strip()[:300] or res.returncode}")
                else:
                    notes.append(
                        f"nftables: {len(v4) + len(v6)} IPs blocked, {len(devices)} devices quarantined"
                    )
            except (OSError, subprocess.SubprocessError) as exc:
                ok = False
                notes.append(f"nftables unavailable: {exc}")
        if self.hosts:
            try:
                path = Path(self.hosts)
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                tmp.write_text(
                    "# IntelGraph Lite: blocked domains (managed file, edits are overwritten)\n"
                    + "".join(f"0.0.0.0 {d}\n:: {d}\n" for d in domains),
                    encoding="utf-8",
                )
                tmp.replace(path)
                reloaded = self._reload()
                notes.append(
                    f"DNS: {len(domains)} domains blocked"
                    + ("" if reloaded else " (dnsmasq not found to reload)")
                )
            except OSError as exc:
                ok = False
                notes.append(f"DNS block file failed: {exc}")
        return {"enforcer": self.name, "ok": ok, "detail": "; ".join(notes), "at": time.time()}


def enforcer(cfg: Any) -> Enforcer:
    if (cfg.enforce or "").lower() == "nftables" or cfg.block_hosts:
        return LocalEnforcer(cfg)
    return Enforcer(cfg)
