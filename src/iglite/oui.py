"""Who made that device? Manufacturers from hardware (MAC) addresses, offline.

The first 3 bytes of a MAC address (the OUI) belong to a manufacturer. The
list is read from the first of these that exists:

* ``~/.iglite/manuf.txt`` - written by ``iglite oui update`` (Wireshark's list,
  or the IEEE registry as a fallback)
* Wireshark's ``manuf`` file (Windows: Program Files\\Wireshark; Linux:
  /usr/share/wireshark)
* Linux system copies of the IEEE list (``ieee-data``, ``hwdata``)

Phones and laptops often use a random "private" address on Wi-Fi; those have
no manufacturer and are reported as such.
"""

from __future__ import annotations

import csv
import io
import os
import re
import socket
import threading
import urllib.request
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

DEFAULT_FILE = "~/.iglite/manuf.txt"
SOURCES = (
    "https://www.wireshark.org/download/automated/data/manuf",
    "https://standards-oui.ieee.org/oui/oui.csv",
)


def system_files() -> list[Path]:
    files = []
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        if base := os.environ.get(env):
            files.append(Path(base) / "Wireshark" / "manuf")
    files += [
        Path(p)
        for p in (
            "/usr/share/wireshark/manuf",
            "/usr/share/ieee-data/oui.txt",
            "/var/lib/ieee-data/oui.txt",
            "/usr/share/hwdata/oui.txt",
            "/usr/share/misc/oui.txt",
        )
    ]
    return files


_HEX = re.compile(r"[^0-9A-Fa-f]")


def parse(text: str) -> dict[str, str]:
    """Prefix (6, 7 or 9 hex digits, upper case) -> vendor, from manuf, oui.txt or oui.csv text."""
    out: dict[str, str] = {}
    lines = text.splitlines()
    if lines and lines[0].startswith("Registry,Assignment"):  # IEEE oui.csv (MA-L / MA-M / MA-S)
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6,9}", row[1] or ""):
                out[row[1].upper()] = row[2].strip()
        return out
    for line in lines:
        if not line or line.startswith("#"):
            continue
        m = re.match(r"\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
        if m:  # IEEE oui.txt
            out[_HEX.sub("", m.group(1)).upper()] = m.group(2).strip()
            continue
        parts = line.split("\t")  # Wireshark manuf: prefix[/bits] <tab> short <tab> long
        if len(parts) >= 2:
            prefix, _, bits = parts[0].strip().partition("/")
            digits = _HEX.sub("", prefix).upper()
            length = int(bits) // 4 if bits.isdigit() else 6
            if len(digits) >= length >= 6:
                out[digits[:length]] = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
    return out


class Vendors:
    def __init__(self, path: str | Path | None = None, extra: Iterable[Path] | None = None) -> None:
        self.path = Path(path or DEFAULT_FILE).expanduser()
        self.extra = list(extra) if extra is not None else system_files()
        self._table: dict[str, str] | None = None
        self.source: str | None = None
        self._lock = threading.Lock()

    def table(self) -> dict[str, str]:
        with self._lock:
            if self._table is None:
                self._table = {}
                for candidate in [self.path, *self.extra]:
                    try:
                        table = parse(candidate.read_text(encoding="utf-8", errors="replace"))
                    except OSError:
                        continue
                    if table:
                        self._table, self.source = table, str(candidate)
                        break
            return self._table

    def reload(self) -> None:
        with self._lock:
            self._table = None

    def lookup(self, mac: str | None) -> str | None:
        if not mac:
            return None
        digits = _HEX.sub("", mac).upper()
        if len(digits) != 12 or int(digits[:2], 16) & 2:  # locally administered: random, no maker
            return None
        table = self.table()
        for length in (9, 7, 6):
            if digits[:length] in table:
                return table[digits[:length]]
        return None


def update(dest: str | Path = DEFAULT_FILE, fetch: Callable[[str], str] | None = None) -> dict[str, object]:
    """Download the vendor list. Returns where it came from and how many prefixes it has."""

    def http(url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "iglite (vendor list update)"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https sources
            return resp.read(64 * 1024 * 1024).decode("utf-8", "replace")

    fetch = fetch or http
    errors = []
    for url in SOURCES:
        try:
            text = fetch(url)
        except Exception as exc:  # try the next source
            errors.append(f"{url}: {exc}")
            continue
        table = parse(text)
        if len(table) < 1000:  # an error page, not the list
            errors.append(f"{url}: only {len(table)} entries")
            continue
        path = Path(dest).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(f"{k}\t{v}\n" for k, v in sorted(table.items())) if url.endswith(".csv") else text,
            encoding="utf-8",
        )
        return {"source": url, "entries": len(table), "path": str(path)}
    raise RuntimeError("couldn't download the vendor list: " + "; ".join(errors))


# -- naming ---------------------------------------------------------------------------------

_TYPES = (  # (type, words in the vendor or host name)
    (
        "router",
        (
            "router",
            "gateway",
            "tp-link",
            "tplink",
            "netgear",
            "ubiquiti",
            "mikrotik",
            "linksys",
            "d-link",
            "zyxel",
            "arris",
            "technicolor",
            "sagemcom",
            "fritz",
            "avm",
            "huawei device",
            "openwrt",
            "eero",
        ),
    ),
    (
        "printer",
        ("printer", "epson", "brother", "canon", "lexmark", "kyocera", "ricoh", "xerox", "hp inc", "hewlett"),
    ),
    (
        "phone",
        (
            "iphone",
            "android",
            "galaxy",
            "pixel",
            "oneplus",
            "xiaomi",
            "redmi",
            "oppo",
            "vivo",
            "motorola",
            "huawei",
            "phone",
        ),
    ),
    ("tablet", ("ipad", "tablet", "kindle")),
    (
        "tv / media",
        (
            "tv",
            "roku",
            "chromecast",
            "fire-tv",
            "firetv",
            "appletv",
            "apple-tv",
            "sonos",
            "lg electronics",
            "vizio",
            "tcl",
            "hisense",
            "nvidia shield",
            "plex",
        ),
    ),
    ("smart speaker", ("echo", "alexa", "homepod", "google-home", "nest")),
    ("camera", ("camera", "cam-", "hikvision", "dahua", "wyze", "arlo", "ring", "reolink", "axis comm")),
    ("game console", ("xbox", "playstation", "nintendo", "sony interactive")),
    ("single-board computer", ("raspberry", "espressif", "arduino")),
    (
        "computer",
        (
            "desktop",
            "laptop",
            "macbook",
            "imac",
            "-pc",
            "dell",
            "lenovo",
            "intel corporate",
            "asustek",
            "micro-star",
            "acer",
            "microsoft",
            "framework",
            "liteon",
            "azurewave",
        ),
    ),
)


def guess_type(vendor: str | None, hostname: str | None, randomized: bool, router: bool = False) -> str:
    if router:
        return "router"
    text = f"{vendor or ''} {hostname or ''}".lower()
    for kind, words in _TYPES:
        if any(w in text for w in words):
            return kind
    if text.strip() in ("apple", "apple, inc.", "apple inc."):
        return "Apple device"
    if randomized:
        return "phone or laptop (private address)"
    return "unknown"


def hostnames(
    ips: Iterable[str], timeout: float = 2.0, resolver: Callable[[str], str] | None = None
) -> dict[str, str]:
    """Reverse-DNS names (routers usually know their DHCP clients'), within ``timeout`` seconds overall."""
    resolve = resolver or (lambda ip: socket.gethostbyaddr(ip)[0])
    ips = list(dict.fromkeys(ips))[:64]
    out: dict[str, str] = {}
    if not ips:
        return out
    pool = ThreadPoolExecutor(max_workers=min(16, len(ips)))
    futures = {pool.submit(resolve, ip): ip for ip in ips}
    done, _ = wait(futures, timeout=timeout)
    for fut in done:
        try:
            name = fut.result()
        except Exception:  # noqa: BLE001, S112 - an unnamed device just stays unnamed
            continue
        if name and name != futures[fut]:
            out[futures[fut]] = name.rstrip(".")
    pool.shutdown(wait=False, cancel_futures=True)
    return out
