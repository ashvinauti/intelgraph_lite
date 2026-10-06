"""Exports: JSON graph, CSV, and STIX 2.1 (hand-built, no stix2 dependency).

STIX object ids are UUIDv5 of the indicator key, so re-exporting produces the
same ids and downstream platforms (MISP, OpenCTI) update instead of duplicate.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .model import Indicator, Kind
from .store import Store

_NS = uuid.UUID("5f0d6f1e-6b8e-4b51-9c1e-6c1a1e0c4a11")
_IDENTITY = f"identity--{uuid.uuid5(_NS, 'iglite')}"


def to_json(store: Store, verdicts: set[str] | None = None) -> str:
    nodes = [n for n in _all_nodes(store) if not verdicts or n["verdict"] in verdicts]
    keys = {n["key"] for n in nodes}
    edges = [e for k in keys for e in store.edges_of(k) if e["src"] == k and e["dst"] in keys]
    return json.dumps({"nodes": nodes, "edges": edges}, indent=2, default=str)


def to_csv(store: Store, verdicts: set[str] | None = None) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["kind", "value", "verdict", "score", "first_seen", "last_seen"])
    for n in _all_nodes(store):
        if not verdicts or n["verdict"] in verdicts:
            w.writerow(
                [
                    n["kind"],
                    n["value"],
                    n["verdict"] or "",
                    n["score"] if n["score"] is not None else "",
                    _iso(n["first_seen"]),
                    _iso(n["last_seen"]),
                ]
            )
    return buf.getvalue()


def to_stix(store: Store, verdicts: set[str] | None = None) -> str:
    verdicts = verdicts or {"malicious", "suspicious"}
    now = _iso(datetime.now(UTC).timestamp())
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": _IDENTITY,
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "IntelGraph Lite",
            "identity_class": "system",
        }
    ]
    sdo_ids: dict[str, str] = {}
    for n in _all_nodes(store):
        if n["verdict"] not in verdicts:
            continue
        ind = Indicator(Kind(n["kind"]), n["value"])
        reasons = "; ".join(f"{e.source}: {e.detail}" for e in store.evidence(n["key"]))
        common = {
            "spec_version": "2.1",
            "created": _iso(n["first_seen"]),
            "modified": _iso(n["last_seen"]),
            "created_by_ref": _IDENTITY,
            "confidence": int(n["score"] or 0),
            "labels": [n["verdict"]],
        }
        if ind.kind is Kind.CVE:
            sdo = {
                "type": "vulnerability",
                "id": _sid("vulnerability", ind),
                "name": ind.value,
                "external_references": [{"source_name": "cve", "external_id": ind.value}],
                **common,
            }
        elif (pattern := _pattern(ind)) is not None:
            sdo = {
                "type": "indicator",
                "id": _sid("indicator", ind),
                "name": ind.value,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": _iso(n["first_seen"]),
                "indicator_types": [
                    "malicious-activity" if n["verdict"] == "malicious" else "anomalous-activity"
                ],
                "description": reasons[:2000] or f"{n['verdict']} (score {n['score']})",
                **common,
            }
        else:
            continue
        objects.append(sdo)
        sdo_ids[n["key"]] = sdo["id"]

    for key, sid in sdo_ids.items():
        for e in store.edges_of(key):
            if e["src"] == key and e["dst"] in sdo_ids:
                rid = uuid.uuid5(_NS, f"{e['src']}|{e['rel']}|{e['dst']}")
                objects.append(
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{rid}",
                        "created": now,
                        "modified": now,
                        "created_by_ref": _IDENTITY,
                        "relationship_type": "related-to",
                        "description": e["rel"],
                        "source_ref": sid,
                        "target_ref": sdo_ids[e["dst"]],
                    }
                )
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return json.dumps(bundle, indent=2)


def _pattern(ind: Indicator) -> str | None:
    v = ind.value.replace("\\", "\\\\").replace("'", "\\'")
    if ind.kind is Kind.IP:
        return f"[{'ipv6-addr' if ':' in v else 'ipv4-addr'}:value = '{v}']"
    if ind.kind is Kind.DOMAIN:
        return f"[domain-name:value = '{v}']"
    if ind.kind is Kind.URL:
        return f"[url:value = '{v}']"
    if ind.kind is Kind.EMAIL:
        return f"[email-addr:value = '{v}']"
    if ind.kind is Kind.HASH:
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(v)]
        return f"[file:hashes.'{algo}' = '{v}']"
    return None


def _sid(kind: str, ind: Indicator) -> str:
    return f"{kind}--{uuid.uuid5(_NS, ind.key)}"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(ts % 1 * 1000):03d}Z"


def _all_nodes(store: Store, page: int = 1000):
    offset = 0
    while batch := store.search(limit=page, offset=offset):
        yield from batch
        offset += page


FORMATS = {"json": to_json, "csv": to_csv, "stix": to_stix}
__all__ = ["FORMATS", "to_csv", "to_json", "to_stix"]
