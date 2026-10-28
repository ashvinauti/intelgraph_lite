"""Common services: tell routine traffic (Google, Apple, Microsoft, Netflix, CDNs...) apart.

On a real network most of the graph is devices talking to the same few dozen big
services. They are rarely what an investigation is about, so the dashboard hides
them by default and shows what is left: the unusual, the unknown and the flagged.

A domain counts as **common** when it (or a parent domain) is

1. in the built-in catalogue (``data/common_services.json``: service -> domains), or
2. in your own ``common_domains`` (config), or
3. in the Tranco list of the internet's most popular domains, if you downloaded it
   (``iglite common update``; Tranco is a research ranking built from several
   providers over 30 days, so it is hard to game: https://tranco-list.eu).

and none of these say otherwise:

* it is under a domain in the catalogue's **abused** list: popular services that
  attackers use to host or deliver malware and phishing (file sharing, paste sites,
  URL shorteners, dynamic DNS, tunnels, user-content hosting such as
  ``*.blogspot.com`` or ``raw.githubusercontent.com``). Those always stay visible,
  however popular they are;
* it is in your ``common_ignore``.

An IP counts as common when it belongs to a CDN-only operator (Akamai, Cloudflare,
Fastly, Apple, Meta...; not Google, Microsoft or Amazon, whose clouds rent servers
to anyone) or when every domain seen resolving to it is common.

Whatever this module says, the dashboard never hides anything flagged malicious or
suspicious, blocked, or held in a case: popularity is not proof of innocence.
"""

from __future__ import annotations

import csv
import io
import json
import time
import urllib.request
import zipfile
from collections.abc import Iterable
from importlib import resources
from pathlib import Path
from typing import Any

from . import __version__

TRANCO_API = "https://tranco-list.eu/api/lists/date/latest"
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_FILE = Path("~/.iglite/tranco.txt").expanduser()
DEFAULT_TOP = 10_000  # the long tail of the top million holds plenty of junk and some malware


def _load_catalogue() -> dict[str, Any]:
    raw = resources.files("iglite").joinpath("data/common_services.json").read_text(encoding="utf-8")
    return json.loads(raw)


class Common:
    """Classifies domains and IPs as common services. Cheap: a few set lookups per name."""

    def __init__(
        self,
        extra: Iterable[str] = (),
        ignore: Iterable[str] = (),
        top: Iterable[str] = (),
        catalogue: dict[str, Any] | None = None,
        extra_label: str = "Your common services",
    ) -> None:
        cat = catalogue or _load_catalogue()
        self.service: dict[str, str] = {}
        for name, domains in cat["services"].items():
            for d in domains:
                self.service[d.lower()] = name
        for d in extra:
            self.service.setdefault(d.lower().strip("."), extra_label)
        self.abused = {d.lower() for d in cat.get("abused", [])}
        self.ignore = {d.lower().strip(".") for d in ignore}
        self.top = {d.lower() for d in top}
        self.operators = [o.lower() for o in cat.get("operators", [])]

    @staticmethod
    def _parents(name: str) -> list[str]:
        """``a.b.example.com`` -> [a.b.example.com, b.example.com, example.com, com]."""
        labels = name.lower().strip(".").split(".")
        return [".".join(labels[i:]) for i in range(len(labels))]

    def abused_by(self, name: str) -> str | None:
        return next((p for p in self._parents(name) if p in self.abused), None)

    def domain(self, name: str) -> str | None:
        """The service a domain belongs to ("Google", "Popular site"), or None if it isn't common."""
        parents = self._parents(name)
        if any(p in self.ignore or p in self.abused for p in parents):
            return None
        for p in parents:
            if p in self.service:
                return self.service[p]
        for p in parents[:-1]:  # never a bare TLD
            if p in self.top:
                return "Popular site"
        return None

    def operator(self, attrs: dict[str, Any]) -> str | None:
        """A CDN-only network owner, from the IP's RDAP/Shodan attributes."""
        owners = " | ".join(
            str(attrs.get(k) or "")
            for k in ("shodan.org", "shodan.isp", "rdap.net_name", "rdap.net_handle", "net_name")
        ).lower()
        return next((o.title() for o in self.operators if o in owners), None)

    def classify(self, store: Any, nodes: list[dict[str, Any]]) -> dict[str, str]:
        """key -> service label, for the common ones among ``nodes`` (domains, URLs and IPs)."""
        out: dict[str, str] = {}
        ips = []
        for n in nodes:
            kind, value = n["kind"], n["value"]
            if kind == "domain":
                if label := self.domain(value):
                    out[n["key"]] = label
            elif kind == "url":
                host = value.split("/")[2] if value.count("/") >= 2 else ""
                host = host.rsplit("@", 1)[-1].split(":")[0]
                if host and (label := self.domain(host)):
                    out[n["key"]] = label
            elif kind == "ip":
                if label := self.operator(n.get("attrs") or {}):
                    out[n["key"]] = label
                else:
                    ips.append(n["key"])
        # An IP is common when every name seen resolving to it is common.
        for key in ips:
            names = [
                e["src"].split(":", 1)[1]
                for e in store.edges_of(key)
                if e["rel"] == "resolves_to" and e["dst"] == key
            ]
            labels = [self.domain(n) for n in names]
            if labels and all(labels):
                out[key] = labels[0] if len(set(labels)) == 1 else "Common services"
        return out


# -- Tranco top list -------------------------------------------------------------------------


def _get(url: str, timeout: float = 60.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"iglite/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        return resp.read()


def parse_tranco(data: bytes, top: int) -> list[str]:
    """``rank,domain`` CSV (or a zip holding one) -> the first ``top`` domains."""
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            data = zf.read(zf.namelist()[0])
    out = []
    for row in csv.reader(io.StringIO(data.decode("utf-8", "replace"))):
        if len(row) >= 2 and row[0].strip().isdigit() and "." in row[1]:
            out.append(row[1].strip().lower())
            if len(out) >= top:
                break
    return out


def download_tranco(top: int = DEFAULT_TOP, get: Any = _get) -> tuple[list[str], str]:
    """The latest Tranco list's top ``top`` domains, and its id. Tries the API, then the zip."""
    try:
        meta = json.loads(get(TRANCO_API, 30.0))
        list_id = str(meta["list_id"])
        domains = parse_tranco(get(f"https://tranco-list.eu/download/{list_id}/{top}"), top)
        if domains:
            return domains, list_id
    except (OSError, ValueError, KeyError):
        pass
    return parse_tranco(get(TRANCO_ZIP, 180.0), top), "top-1m"


def save_tranco(domains: list[str], list_id: str, path: Path = TRANCO_FILE) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d", time.gmtime())
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        f"# Tranco list {list_id}, top {len(domains)}, downloaded {stamp}\n" + "\n".join(domains) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)
    return path


def read_top(path: Path = TRANCO_FILE) -> tuple[list[str], str | None]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], None
    header = lines[0][2:] if lines and lines[0].startswith("#") else None
    return [x for x in lines if x and not x.startswith("#")], header


def from_config(cfg: Any) -> Common:
    top, _ = read_top(Path(cfg.common_top_file).expanduser()) if cfg.common_top_file else ([], None)
    return Common(cfg.common_domains, cfg.common_ignore, top)


# -- graph filtering ---------------------------------------------------------------------------

FLAGGED = ("malicious", "suspicious")


def protected(store: Any, nodes: list[dict[str, Any]]) -> set[str]:
    """Keys that are never hidden: flagged, blocked, or held in a case."""
    from .respond import blocked_keys

    keys = [n["key"] for n in nodes]
    keep = {n["key"] for n in nodes if n.get("verdict") in FLAGGED}
    keep |= blocked_keys(store) & set(keys)
    keep |= store.keys_in_cases(keys)
    return keep


def filter_graph(
    common: Common, store: Any, graph: dict[str, Any], keep: Iterable[str] = (), limit: int | None = None
) -> dict[str, Any]:
    """Drop common-service nodes from a neighbourhood, and whatever is only reachable through them.

    A common node stays when it is protected, asked for in ``keep``, the root, or
    directly linked to a flagged node (so a malicious URL on a popular host keeps its
    path back to the device that fetched it).
    """
    nodes, edges, root = graph["nodes"], graph["edges"], graph.get("root")
    labels = common.classify(store, nodes)
    safe = protected(store, nodes) | set(keep) | {root}
    flagged = {n["key"] for n in nodes if n.get("verdict") in FLAGGED}
    for e in edges:  # bridges to something flagged
        if e["src"] in flagged:
            safe.add(e["dst"])
        if e["dst"] in flagged:
            safe.add(e["src"])
    hidden = {k for k in labels if k not in safe}
    kept = [n for n in nodes if n["key"] not in hidden]
    kept_edges = [e for e in edges if e["src"] not in hidden and e["dst"] not in hidden]
    # Keep only what is still connected to the root (or to anything asked for).
    adj: dict[str, list[str]] = {}
    for e in kept_edges:
        adj.setdefault(e["src"], []).append(e["dst"])
        adj.setdefault(e["dst"], []).append(e["src"])
    seen = {k for k in ({root} | set(keep)) if k}
    stack = list(seen)
    while stack:
        for nxt in adj.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    kept = [n for n in kept if n["key"] in seen]
    if limit is not None:
        kept = kept[:limit]  # nodes arrive nearest first
    present = {n["key"] for n in kept}
    services: dict[str, int] = {}
    for k in hidden:
        services[labels[k]] = services.get(labels[k], 0) + 1
    return {
        **graph,
        "nodes": kept,
        "edges": [e for e in kept_edges if e["src"] in present and e["dst"] in present],
        "hidden": {
            "common": len(hidden),
            "unreachable": sum(1 for n in nodes if n["key"] not in hidden and n["key"] not in seen),
            "services": dict(sorted(services.items(), key=lambda kv: -kv[1])),
            "keys": {k: labels[k] for k in sorted(hidden)[:1000]},
        },
    }
