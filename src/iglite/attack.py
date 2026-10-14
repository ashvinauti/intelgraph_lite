"""MITRE ATT&CK: the technique catalogue, and mapping what we see onto techniques.

Techniques reach the graph four ways, and each one keeps its basis so the
dashboard can tell a reported technique from a guess:

* ``uses_technique``     - a threat feed reported it (OTX pulses list ATT&CK IDs),
                           or a local IDS signature carries it (Suricata metadata).
* ``mentions``           - a report you ingested names the technique ID.
* ``suggests_technique`` - inferred from a feed tag (``c2`` -> T1071, ``phishing``
                           -> T1566, ...) or from live traffic to a flagged host
                           (port 443 -> T1071.001, an odd port -> T1571).
* ``associated_with``    - a tag names ATT&CK malware or a threat group; that
                           software's known techniques are *associated*, not observed.

The catalogue is a compact copy of MITRE's Enterprise ATT&CK STIX bundle
(tactics, techniques, malware and groups with their techniques), shipped as
``data/attack.json.gz``. ``iglite attack update`` downloads the latest release
to ``~/.iglite/attack.json.gz``, which then takes precedence. No lookups are
made at runtime.

ATT&CK® is a registered trademark of The MITRE Corporation, used under its
terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
"""

from __future__ import annotations

import gzip
import json
import re
import threading
from collections.abc import Iterable
from importlib import resources
from pathlib import Path
from typing import Any

from .model import Indicator, Kind, Relation

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"
    "enterprise-attack.json"
)
USER_COPY = Path("~/.iglite/attack.json.gz")
NOTICE = (
    "MITRE ATT&CK, (c) The MITRE Corporation. Reproduced and distributed with the permission of "
    "The MITRE Corporation: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
)

TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
KINDS = frozenset({Kind.TECHNIQUE, Kind.SOFTWARE, Kind.GROUP})

# Relation name -> basis shown to the user, strongest first.
BASIS = {
    "uses_technique": "reported",
    "exhibits": "observed",
    "suggests_technique": "inferred",
    "mentions": "report",
    "associated_with": "associated",
}

# Feed tags that name a behaviour rather than a family. Kept short and
# conservative: a tag only maps when the technique is the tag's plain meaning.
TAG_TECHNIQUES: dict[str, str] = {
    "c2": "T1071",
    "cc": "T1071",
    "c&c": "T1071",
    "botnetcc": "T1071",
    "botnet_cc": "T1071",
    "command-and-control": "T1071",
    "phishing": "T1566",
    "phish": "T1566",
    "malware_download": "T1105",
    "payload_delivery": "T1105",
    "dropper": "T1105",
    "tor": "T1090.003",
    "dga": "T1568.002",
    "ransomware": "T1486",
    "cryptomining": "T1496",
    "coinminer": "T1496",
    "miner": "T1496",
    "scanner": "T1595",
    "scanning": "T1595",
    "bruteforce": "T1110",
    "brute-force": "T1110",
    "ssh-bruteforce": "T1110",
    "keylogger": "T1056.001",
    "stealer": "T1555",
    "infostealer": "T1555",
}

# Application-layer C2 sub-technique by destination port; other ports suggest T1571.
PORT_TECHNIQUES = {
    80: "T1071.001",
    443: "T1071.001",
    8080: "T1071.001",
    8443: "T1071.001",
    53: "T1071.004",
    853: "T1071.004",
    25: "T1071.003",
    465: "T1071.003",
    587: "T1071.003",
    993: "T1071.003",
    995: "T1071.003",
    21: "T1071.002",
    990: "T1071.002",
}
COMMON_PORTS = frozenset({22, 123, 3389, 5222, 5228, *PORT_TECHNIQUES})


# -- the catalogue ----------------------------------------------------------------


def build(bundle: dict[str, Any]) -> dict[str, Any]:
    """Compact catalogue from MITRE's enterprise-attack STIX 2.1 bundle."""

    def ext_id(obj: dict[str, Any]) -> str | None:
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    def live(obj: dict[str, Any]) -> bool:
        return not obj.get("revoked") and not obj.get("x_mitre_deprecated")

    objects = [o for o in bundle.get("objects") or [] if live(o)]
    by_stix = {o["id"]: o for o in objects}
    version = next((str(o.get("x_mitre_version")) for o in objects if o["type"] == "x-mitre-collection"), "?")
    matrix = next((o for o in objects if o["type"] == "x-mitre-matrix"), None)
    tactic_objs = [by_stix[r] for r in (matrix or {}).get("tactic_refs", []) if r in by_stix] or [
        o for o in objects if o["type"] == "x-mitre-tactic"
    ]
    tactics = [[ext_id(t), t["x_mitre_shortname"], t["name"]] for t in tactic_objs]

    techniques: dict[str, list[Any]] = {}
    pattern_ids: dict[str, str] = {}
    for o in objects:
        if o["type"] != "attack-pattern" or not (tid := ext_id(o)):
            continue
        phases = [
            p["phase_name"]
            for p in o.get("kill_chain_phases") or []
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[tid] = [o["name"], phases, o["id"]]
        pattern_ids[o["id"]] = tid

    uses: dict[str, set[str]] = {}
    for o in objects:
        if (
            o["type"] == "relationship"
            and o.get("relationship_type") == "uses"
            and o.get("target_ref") in pattern_ids
        ):
            uses.setdefault(o["source_ref"], set()).add(pattern_ids[o["target_ref"]])

    software: dict[str, list[Any]] = {}
    groups: dict[str, list[Any]] = {}
    for o in objects:
        if o["type"] not in ("malware", "tool", "intrusion-set") or not (oid := ext_id(o)):
            continue
        aliases = {o["name"], *(o.get("x_mitre_aliases") or []), *(o.get("aliases") or [])}
        entry = [o["name"], sorted({a.strip() for a in aliases if a.strip()}), sorted(uses.get(o["id"], ()))]
        if o["type"] == "intrusion-set":
            groups[oid] = entry
        else:
            software[oid] = [*entry, o["type"]]
    return {
        "version": version,
        "notice": NOTICE,
        "tactics": tactics,
        "techniques": techniques,
        "software": software,
        "groups": groups,
    }


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


class Catalogue:
    # Aliases too generic to identify malware from a feed tag.
    _AMBIGUOUS = frozenset({"agent", "backdoor", "trojan", "loader", "rat", "stealer", "dropper", "miner"})

    def __init__(self, data: dict[str, Any]) -> None:
        self.version: str = data.get("version", "?")
        self.tactics: list[dict[str, str]] = [
            {"id": t[0], "short": t[1], "name": t[2]} for t in data.get("tactics", [])
        ]
        self._tactic_order = {t["short"]: i for i, t in enumerate(self.tactics)}
        self._techniques: dict[str, list[Any]] = data.get("techniques", {})
        self._software: dict[str, list[Any]] = data.get("software", {})
        self._groups: dict[str, list[Any]] = data.get("groups", {})
        # Tag -> ("software" | "group", id). Malware and groups only: tool names
        # ("ftp", "tor", "net") are ordinary words in feeds.
        self._aliases: dict[str, tuple[str, str]] = {}
        for gid, (_, aliases, _) in self._groups.items():
            for a in aliases:
                if len(_norm(a)) >= 4 and _norm(a) not in self._AMBIGUOUS:
                    self._aliases.setdefault(_norm(a), ("group", gid))
        for sid, (_, aliases, _, stype) in self._software.items():
            if stype != "malware":
                continue
            for a in aliases:
                if len(_norm(a)) >= 4 and _norm(a) not in self._AMBIGUOUS:
                    self._aliases.setdefault(_norm(a), ("software", sid))

    def __len__(self) -> int:
        return len(self._techniques)

    def technique(self, tid: str) -> dict[str, Any] | None:
        tid = tid.upper()
        entry = self._techniques.get(tid)
        if entry is None:
            return None
        name, tactics, stix_id = entry
        parent = tid.split(".")[0]
        full = name if parent == tid else f"{self._techniques.get(parent, [parent])[0]}: {name}"
        return {
            "id": tid,
            "name": full,
            "tactics": sorted(tactics, key=lambda t: self._tactic_order.get(t, 99)),
            "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/"),
            "stix_id": stix_id,
        }

    def entity(self, kind: str, eid: str) -> dict[str, Any] | None:
        table = self._software if kind == "software" else self._groups if kind == "group" else {}
        entry = table.get(eid.upper())
        if entry is None:
            return None
        path = "software" if kind == "software" else "groups"
        return {
            "id": eid.upper(),
            "name": entry[0],
            "aliases": entry[1],
            "techniques": entry[2],
            "url": f"https://attack.mitre.org/{path}/{eid.upper()}",
        }

    def match_tag(self, tag: str) -> Indicator | None:
        """ATT&CK malware or group a feed tag names (e.g. 'emotet', 'apt28'), if any."""
        hit = self._aliases.get(_norm(tag))
        if hit is None:
            return None
        return Indicator(Kind.SOFTWARE if hit[0] == "software" else Kind.GROUP, hit[1])

    def attrs(self, ind: Indicator) -> dict[str, Any]:
        """Display attributes stored on a technique / software / group node."""
        if ind.kind is Kind.TECHNIQUE and (t := self.technique(ind.value)):
            return {"attack.name": t["name"], "attack.tactics": t["tactics"]}
        if ind.kind in (Kind.SOFTWARE, Kind.GROUP) and (e := self.entity(ind.kind.value, ind.value)):
            return {"attack.name": e["name"]}
        return {}


_lock = threading.Lock()
_cached: Catalogue | None = None


def load_data(path: str | Path | None = None) -> dict[str, Any]:
    candidates = [Path(path)] if path else [USER_COPY.expanduser()]
    for p in candidates:
        try:
            with gzip.open(p, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            continue
    with resources.files("iglite").joinpath("data/attack.json.gz").open("rb") as raw:
        return json.loads(gzip.decompress(raw.read()))


def catalogue() -> Catalogue:
    global _cached
    with _lock:
        if _cached is None:
            _cached = Catalogue(load_data())
        return _cached


def save(data: dict[str, Any], path: str | Path = USER_COPY) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(target, "wt", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"), sort_keys=True)
    global _cached
    with _lock:
        _cached = None
    return target


# -- mapping observations to techniques ---------------------------------------------


def technique_node(tid: str) -> Indicator | None:
    tid = tid.strip().upper()
    return Indicator(Kind.TECHNIQUE, tid) if TECHNIQUE_ID.match(tid) else None


def from_tag(ind: Indicator, tag: str) -> list[Relation]:
    """Relations implied by one feed tag on ``ind``: a behaviour, or named malware/group."""
    out = []
    if (tid := TAG_TECHNIQUES.get(tag.strip().lower())) is not None:
        out.append(Relation(ind, "suggests_technique", Indicator(Kind.TECHNIQUE, tid), pivot=False))
    if (entity := catalogue().match_tag(tag)) is not None:
        out.append(Relation(ind, "associated_with", entity, pivot=False))
    return out


def from_connection(port: int | None) -> str:
    """Technique suggested by outbound traffic to a flagged host on ``port``."""
    if port in PORT_TECHNIQUES:
        return PORT_TECHNIQUES[port]
    return "T1071" if port in COMMON_PORTS or not port else "T1571"


# -- the matrix ------------------------------------------------------------------------

_RANK = {"malicious": 4, "suspicious": 3, "unknown": 2, "benign": 1}


def summary(store: Any, *, associated: bool = False) -> dict[str, Any]:
    """Techniques seen across the knowledge base, grouped by tactic in matrix order."""
    cat = catalogue()
    links = _links(store, associated)
    nodes = {n["key"]: n for n in store.nodes({src for src, _, _ in links})}
    per_tech: dict[str, dict[str, Any]] = {}
    for src, tid, basis in links:
        t = per_tech.setdefault(tid, {"indicators": {}, "basis": set()})
        t["basis"].add(basis)
        t["indicators"].setdefault(src, basis)
    tactics = [{**t, "techniques": []} for t in cat.tactics]
    index = {t["short"]: t for t in tactics}
    unknown = []
    for tid, t in per_tech.items():
        info = cat.technique(tid)
        verdicts: dict[str, int] = {}
        for key in t["indicators"]:
            v = (nodes.get(key) or {}).get("verdict") or "unknown"
            verdicts[v] = verdicts.get(v, 0) + 1
        row = {
            "id": tid,
            "name": info["name"] if info else tid,
            "url": info["url"] if info else None,
            "count": len(t["indicators"]),
            "verdicts": verdicts,
            "top_verdict": max(verdicts, key=lambda v: _RANK.get(v, 0)) if verdicts else "unknown",
            "basis": sorted(t["basis"], key=list(BASIS.values()).index),
        }
        if not info:
            unknown.append(row)
        for tactic in (info or {}).get("tactics", []):
            if tactic in index:
                index[tactic]["techniques"].append(row)
    for t in tactics:
        t["techniques"].sort(key=lambda r: (-_RANK.get(r["top_verdict"], 0), -r["count"], r["id"]))
    return {
        "version": cat.version,
        "tactics": tactics,
        "unknown_ids": unknown,
        "techniques": len(per_tech),
        "indicators": len({src for src, _, _ in links}),
    }


def detail(store: Any, tid: str, *, associated: bool = True) -> dict[str, Any]:
    """One technique: catalogue entry and every indicator linked to it, with the basis."""
    tid = tid.upper()
    info = catalogue().technique(tid) or {"id": tid, "name": tid, "tactics": [], "url": None}
    rows: dict[str, dict[str, Any]] = {}
    for src, t, basis in _links(store, associated):
        if t == tid:
            rows.setdefault(src, {"key": src, "basis": []})["basis"].append(basis)
    nodes = {n["key"]: n for n in store.nodes(rows)}
    for key, row in rows.items():
        node = nodes.get(key) or {}
        row.update(verdict=node.get("verdict"), score=node.get("score"), kind=key.split(":", 1)[0])
    ordered = sorted(rows.values(), key=lambda r: (-_RANK.get(r["verdict"] or "", 0), -(r["score"] or 0)))
    return {**info, "indicators": ordered}


def techniques_of(store: Any, key: str, *, associated: bool = True) -> list[dict[str, Any]]:
    """Techniques linked to one indicator, with the basis and, if associated, the malware/group."""
    cat = catalogue()
    out: dict[str, dict[str, Any]] = {}
    for e in store.edges_of(key):
        if e["src"] != key:
            continue
        kind, _, value = e["dst"].partition(":")
        if kind == Kind.TECHNIQUE.value and e["rel"] in BASIS:
            out.setdefault(value, {"basis": [], "via": []})["basis"].append(BASIS[e["rel"]])
        elif associated and kind in ("software", "group") and (ent := cat.entity(kind, value)):
            for tid in ent["techniques"]:
                row = out.setdefault(tid, {"basis": [], "via": []})
                row["basis"].append("associated")
                row["via"].append(ent["name"])
    result = []
    for tid, row in out.items():
        info = cat.technique(tid) or {"id": tid, "name": tid, "tactics": [], "url": None}
        result.append(
            {**info, "basis": sorted(set(row["basis"]), key=list(BASIS.values()).index), "via": row["via"]}
        )
    order = list(BASIS.values())
    result.sort(key=lambda r: (order.index(r["basis"][0]), r["id"]))
    return result


def navigator_layer(store: Any, *, associated: bool = False, name: str = "IntelGraph Lite") -> dict[str, Any]:
    """An ATT&CK Navigator layer (https://mitre-attack.github.io/attack-navigator/)."""
    s = summary(store, associated=associated)
    seen: dict[str, dict[str, Any]] = {}
    for tactic in s["tactics"]:
        for t in tactic["techniques"]:
            seen[t["id"]] = t
    top = max((t["count"] for t in seen.values()), default=1)
    return {
        "name": name,
        "versions": {"attack": s["version"].split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques linked to indicators in IntelGraph Lite. " + NOTICE,
        "techniques": [
            {
                "techniqueID": tid,
                "score": t["count"],
                "comment": f"{t['count']} indicator(s); basis: {', '.join(t['basis'])}; "
                + ", ".join(f"{v} {k}" for k, v in sorted(t["verdicts"].items())),
                "enabled": True,
            }
            for tid, t in sorted(seen.items())
        ],
        "gradient": {"colors": ["#fff3b0", "#e4572e"], "minValue": 0, "maxValue": top},
        "hideDisabled": False,
    }


def _links(store: Any, associated: bool) -> list[tuple[str, str, str]]:
    """(indicator key, technique id, basis) for every technique link in the store."""
    out = []
    for e in store.edges_to_kind(Kind.TECHNIQUE.value):
        if (basis := BASIS.get(e["rel"])) is not None:
            out.append((e["src"], e["dst"].partition(":")[2], basis))
    if associated:
        cat = catalogue()
        for kind in ("software", "group"):
            for e in store.edges_to_kind(kind):
                if e["rel"] == "associated_with" and (ent := cat.entity(kind, e["dst"].partition(":")[2])):
                    out += [(e["src"], tid, "associated") for tid in ent["techniques"]]
    return out


def ids_in(values: Iterable[Any]) -> list[str]:
    """Valid technique IDs from a feed's list (strings or {"id": ...} objects)."""
    out = []
    for v in values or []:
        raw = v.get("id") if isinstance(v, dict) else v
        if isinstance(raw, str) and TECHNIQUE_ID.match(raw.strip().upper()):
            out.append(raw.strip().upper())
    return list(dict.fromkeys(out))
