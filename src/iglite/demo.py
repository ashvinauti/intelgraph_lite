"""Demo mode: a simulated home network, live in the dashboard, with nothing to set up.

``iglite demo`` starts the real dashboard and the real pipeline (gateway collector,
watcher, engine, scoring, ATT&CK mapping, alerts) on a throwaway database, fed by a
simulated network instead of a router:

* eight devices browse ordinary sites, with DHCP names and DNS lookups;
* scripted incidents unfold over the first minute: a smart plug beaconing to a
  command-and-control server, a tablet opening a phishing page, a TV mining
  cryptocurrency, a laptop downloading malware, an internet scanner reaching the NAS,
  and a shared-CDN address that a stale feed entry would wrongly flag.

Threat intelligence comes from local demo sources with invented data. Every
"internet" address is in the documentation ranges (TEST-NET-1/2/3) and every name
is under ``.example``, so no real host or company is named. No network access, no
API keys, no admin rights; the user's own database is never touched.
"""

from __future__ import annotations

import random
import secrets
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config as config_mod
from .engine import Engine
from .extract import classify, treat_as_public
from .gateway import DnsEvent, Flow, GatewayCollector, Lease
from .model import Evidence, Finding, Indicator, Kind, Relation, Verdict
from .netwatch import GATEWAY, NetWatch
from .sources.base import Context, Source

# Documentation ranges play the internet; the LAN is a laptop hotspot's 10.42.0.0/24.
DEMO_INTERNET = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]

DEVICES = {
    "10.42.0.11": "Parent-iPhone",
    "10.42.0.23": "Kids-iPad",
    "10.42.0.31": "LG-webOS-TV",
    "10.42.0.40": "Office-Printer",
    "10.42.0.52": "Work-Laptop",
    "10.42.0.61": "Smart-Plug",
    "10.42.0.70": "Family-NAS",
    "10.42.0.88": "Ring-Doorbell",
}

# Ordinary traffic: which sites each device uses (name -> address, port).
SITES = {
    "news-site.example": ("198.51.100.10", 443),
    "video-stream.example": ("198.51.100.11", 443),
    "photos-cloud.example": ("198.51.100.12", 443),
    "music.example": ("198.51.100.13", 443),
    "maps.example": ("198.51.100.14", 443),
    "video-call.example": ("198.51.100.15", 443),
    "updates.vendor.example": ("198.51.100.16", 443),
    "gaming.example": ("198.51.100.17", 443),
    "printer-cloud.example": ("198.51.100.18", 443),
    "doorbell-cloud.example": ("198.51.100.19", 443),
    "smart-home-hub.example": ("198.51.100.20", 8883),
    "static-cdn.example": ("198.51.100.200", 443),
}
HABITS = {
    "10.42.0.11": [
        "news-site.example",
        "maps.example",
        "music.example",
        "photos-cloud.example",
        "static-cdn.example",
    ],
    "10.42.0.23": ["video-stream.example", "gaming.example", "video-stream.example"],
    "10.42.0.31": ["video-stream.example", "updates.vendor.example"],
    "10.42.0.40": ["printer-cloud.example"],
    "10.42.0.52": ["video-call.example", "news-site.example", "updates.vendor.example"],
    "10.42.0.61": ["smart-home-hub.example"],
    "10.42.0.70": ["updates.vendor.example", "photos-cloud.example"],
    "10.42.0.88": ["doorbell-cloud.example"],
}

C2_IP, PHISH, MINER, DROPPER, SCANNER, CDN_IP = (
    "203.0.113.66",
    "account-verify-login.example",
    "pool.coin-mine.example",
    "cdn-update.example",
    "192.0.2.50",
    "198.51.100.200",
)
DROPPER_URL = f"http://{DROPPER}/setup.bin"
STALE = time.time() - 2 * 365 * 86400  # a two-year-old sighting


# What the demo intelligence sources "know": key -> per source (verdict, detail, confidence,
# last seen, tags, ATT&CK ids, attributes).
@dataclass(frozen=True)
class Intel:
    verdict: Verdict | None = None
    detail: str = ""
    confidence: float = 0.9
    last_seen: float | None = None
    tags: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    attrs: tuple[tuple[str, Any], ...] = ()


M, S, B = Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN
INTEL: dict[str, dict[str, Intel]] = {
    "community-feed": {
        f"ip:{C2_IP}": Intel(
            M,
            "in 3 community reports: Emotet botnet command server",
            0.8,
            None,
            ("c2", "emotet"),
            ("T1071.001", "T1573"),
        ),
        f"domain:{PHISH}": Intel(
            M, "phishing kit imitating a webmail sign-in page", 0.8, None, ("phishing",), ("T1566.002",)
        ),
        f"domain:{MINER}": Intel(
            M, "cryptocurrency mining pool used by IoT malware", 0.7, None, ("cryptomining",)
        ),
        f"domain:{DROPPER}": Intel(
            M, "serves droppers in an invoice-themed campaign", 0.7, None, ("malware_download",)
        ),
        f"ip:{SCANNER}": Intel(
            S, "mass SSH scanner seen by 41 sensors", 0.8, None, ("scanner", "bruteforce")
        ),
        # The false-positive trap: one old report about an address on a shared CDN.
        f"ip:{CDN_IP}": Intel(M, "listed once in an old phishing report", 0.6, STALE),
    },
    "malware-db": {
        f"ip:{C2_IP}": Intel(M, "Emotet C2 (online)", 0.9, None, ("c2",)),
        f"domain:{PHISH}": Intel(M, "credential phishing URL (online)", 0.9),
        f"domain:{MINER}": Intel(M, "Monero mining pool contacted by malware samples", 0.8),
        f"domain:{DROPPER}": Intel(M, "hosted 3 malware URLs, 2 online", 0.9, None, ("agent tesla",)),
        f"url:{DROPPER_URL}": Intel(
            M,
            "malware_download: Agent Tesla dropper (online)",
            0.9,
            None,
            ("malware_download", "agent tesla"),
        ),
        f"ip:{SCANNER}": Intel(S, "brute-force source on port 22", 0.6),
    },
    "known-good": {
        f"domain:{name}": Intel(B, "on the known-good list", 0.9)
        for name in (
            "updates.vendor.example",
            "printer-cloud.example",
            "video-call.example",
            "static-cdn.example",
        )
    },
    "rdap": {
        f"ip:{CDN_IP}": Intel(attrs=(("net_name", "SHARED-CDN-DEMO"),)),
        f"ip:{C2_IP}": Intel(attrs=(("net_name", "BULLETPROOF-HOSTING-DEMO"),)),
    },
}

SOURCE_INFO = {
    "community-feed": (0.6, "Demo community threat feed: reports, tags and ATT&CK IDs (invented data)"),
    "malware-db": (0.8, "Demo malware database: C2, phishing and malware URLs (invented data)"),
    "known-good": (0.9, "Demo allowlist of known-good services"),
    "rdap": (0.3, "Demo network-owner records"),
}

REPORT = f"""Threat brief (demo): IoT botnet and phishing campaign targeting home networks

Infected smart plugs beacon to {C2_IP} over a non-standard port (T1571) using an
encrypted channel (T1573). The same operators run {PHISH} to harvest webmail
passwords (T1566.002) and push an Agent Tesla dropper from hxxp://cdn-update[.]example/setup.bin
(T1105). Compromised TVs are enrolled into {MINER} for Monero mining (T1496).
"""


class DemoIntel(Source):
    """A local, offline source answering from the INTEL table above."""

    kinds = frozenset({Kind.IP, Kind.DOMAIN, Kind.URL})
    remote = False

    def __init__(self, name: str) -> None:
        self.name = name  # type: ignore[misc]
        self.trust, self.description = SOURCE_INFO[name]  # type: ignore[misc]
        self.table = INTEL[name]

    def lookup(self, ind: Indicator, ctx: Context) -> Finding | None:
        intel = self.table.get(ind.key)
        if intel is None:
            return Finding()
        finding = Finding(attributes=dict(intel.attrs))
        if intel.verdict is not None:
            finding.evidence.append(
                Evidence(self.name, intel.verdict, intel.detail, intel.confidence, None, intel.last_seen)
            )
        for tag in intel.tags:
            finding.relations.append(Relation(ind, "tagged", Indicator(Kind.TAG, tag), pivot=False))
        for tid in intel.attack:
            finding.relations.append(
                Relation(ind, "uses_technique", Indicator(Kind.TECHNIQUE, tid), pivot=False)
            )
        return finding


class DemoNetwork:
    """Plays the simulated network into a GatewayCollector: background browsing plus scripted incidents."""

    def __init__(self, gateway: GatewayCollector, *, speed: float = 1.0, seed: int = 7) -> None:
        self.gw = gateway
        self.speed = max(0.1, speed)
        self.rng = random.Random(seed)  # noqa: S311 - simulated traffic, not security
        self.t0 = time.monotonic()
        self.fired: set[str] = set()
        self._stop = threading.Event()

    # -- what happens -----------------------------------------------------------------

    def visit(self, device: str, name: str, port: int | None = None) -> None:
        ip, default_port = SITES.get(name, ("", 443))
        self.gw.add(DnsEvent(device, name))
        if ip:
            self.gw.add(DnsEvent(None, name, (ip,)))
            self.gw.add(Flow(device, ip, self.rng.randint(49152, 65000), port or default_port, "tcp", "pass"))

    def background(self) -> None:
        for device in self.rng.sample(sorted(DEVICES), 3):
            self.visit(device, self.rng.choice(HABITS[device]))

    def incidents(self, elapsed: float) -> None:
        def once(key: str, at: float) -> bool:
            if elapsed >= at and key not in self.fired:
                self.fired.add(key)
                return True
            return False

        if once("phishing", 6):  # the tablet opens a phishing link from a chat message
            self.gw.add(DnsEvent("10.42.0.23", PHISH))
            self.gw.add(DnsEvent(None, PHISH, ("198.51.100.23",)))
            self.gw.add(Flow("10.42.0.23", "198.51.100.23", 51022, 443, "tcp", "pass"))
        if once("c2", 12):  # the smart plug starts beaconing; the IDS recognises it
            self.gw.add(
                Flow("10.42.0.61", C2_IP, 50123, 4444, "tcp", "", "ET MALWARE Emotet CnC Beacon", ("T1071",))
            )
        if elapsed >= 12 and int(elapsed) % 20 == 0:  # ...and keeps beaconing
            self.gw.add(Flow("10.42.0.61", C2_IP, self.rng.randint(49152, 65000), 4444, "tcp", "pass"))
        if once("dropper", 20):  # the laptop follows an invoice link
            self.gw.add(DnsEvent("10.42.0.52", DROPPER))
            self.gw.add(DnsEvent(None, DROPPER, ("203.0.113.10",)))
            self.gw.add(Flow("10.42.0.52", "203.0.113.10", 52011, 80, "tcp", "pass"))
        if once("miner", 28):  # the TV joins a mining pool
            self.gw.add(DnsEvent("10.42.0.31", MINER))
            self.gw.add(DnsEvent(None, MINER, ("198.51.100.77",)))
            self.gw.add(Flow("10.42.0.31", "198.51.100.77", 53001, 3333, "tcp", "pass"))
        if once("scanner", 36):  # an internet scanner reaches the NAS's forwarded SSH port
            self.gw.add(Flow(SCANNER, "10.42.0.70", 40022, 22, "tcp", "pass"))
        if once("cdn", 3):  # the false-positive trap: ordinary CDN traffic
            self.visit("10.42.0.11", "static-cdn.example")

    def step(self) -> None:
        self.incidents((time.monotonic() - self.t0) * self.speed)
        self.background()

    # -- running ------------------------------------------------------------------------

    def start(self) -> None:
        for ip, name in DEVICES.items():
            self.gw.add(Lease(ip, name))
        threading.Thread(target=self._loop, name="iglite-demo-network", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.step()
            self._stop.wait(1.5 / self.speed)


def build(
    db: str | None = None, *, speed: float = 1.0, interval: float = 5.0
) -> tuple[Engine, NetWatch, DemoNetwork]:
    """A demo engine and watcher on a throwaway database, wired to the simulated network."""
    treat_as_public(DEMO_INTERNET)
    cfg = config_mod.load()  # AI keys from the environment / .env still apply; intel keys are unused
    cfg.db = db or str(Path(tempfile.mkdtemp(prefix="iglite-demo-")) / "demo.db")
    cfg.offline = True
    cfg.ai_triage = "manual" if cfg.ai_triage == "auto" else cfg.ai_triage
    cfg.lan_networks = ["10.42.0.0/24"]
    engine = Engine(cfg, sources=[DemoIntel(name) for name in INTEL])
    engine.demo = True
    engine.ingest(REPORT, "Threat brief: IoT botnet and phishing (demo)")
    report = [i for i in (classify(DROPPER_URL), classify(C2_IP)) if i is not None]
    engine.investigate(report, depth=1)
    gw = GatewayCollector(cfg)
    gw.started = True  # no listeners: the simulation feeds it directly
    gw.extra_inputs = ["simulated home network (demo)"]
    watch = NetWatch(engine, interval=interval, collector=gw.collect, origin=GATEWAY, gateway=gw)
    engine._netwatch = watch
    return engine, watch, DemoNetwork(gw, speed=speed)


def run(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    open_browser: bool = True,
    speed: float = 1.0,
    db: str | None = None,
) -> None:
    from .api import make_server

    engine, watch, network = build(db, speed=speed)
    local = host in ("127.0.0.1", "localhost", "::1")
    if not local and not engine.config.api_token:
        engine.config.api_token = secrets.token_urlsafe(12)
    network.start()
    watch.start()
    server = make_server(engine, host, port)
    url = f"http://{'127.0.0.1' if local else host}:{port}/#network"
    print(
        "IntelGraph Lite demo: a simulated home network with 8 devices (invented data, nothing leaves this machine)"
    )
    print(f"  Dashboard: {url}")
    if engine.config.api_token and not local:
        print(
            f"  API token: {engine.config.api_token}   (others on your network open http://<this machine's IP>:{port})"
        )
    print("  Incidents unfold over the first minute; press Ctrl+C to stop. The demo database is thrown away.")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        network.stop()
        watch.stop()
        server.server_close()
        engine.store.close()
