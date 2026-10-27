"""Cases: group related alerts and indicators into one incident and keep a timeline.

A case holds alerts (the live-monitoring hits), indicators (anything in the graph:
IPs, domains, devices...) and a timeline of what happened and what was done:
notes, status changes, blocks. New alerts join an open case automatically when
the case already holds the same indicator or the same device, so one incident
stays one case instead of a pile of separate alerts.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from . import attack
from .store import Store

STATUSES = ("open", "investigating", "closed")
SEVERITIES = ("low", "medium", "high", "critical")
AUTO_ATTACH_WINDOW = 7 * 86400  # an open case untouched for longer doesn't pull in new alerts


def severity_for(verdict: str) -> str:
    return "high" if verdict == "malicious" else "medium"


def _alert_title(alert: dict[str, Any]) -> str:
    ctx = alert.get("context") or {}
    who = ctx.get("device_name") or ctx.get("device") or ctx.get("process")
    what = alert["key"].split(":", 1)[1]
    return f"{alert['verdict'].capitalize()} {what}" + (f" on {who}" if who else "")


def create(
    store: Store,
    title: str,
    *,
    severity: str = "medium",
    summary: str = "",
    alerts: list[int] = (),  # type: ignore[assignment]
    indicators: list[str] = (),  # type: ignore[assignment]
) -> int:
    """A new case, optionally seeded with alerts and indicators. An empty title is made from the first alert."""
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    rows = [a for a in (store.alert(i) for i in alerts) if a is not None]
    if len(rows) != len(list(alerts)):
        raise KeyError("no such alert")
    title = (title or "").strip() or (_alert_title(rows[0]) if rows else "")
    if not title:
        raise ValueError("a case needs a title")
    case_id = store.add_case(title[:200], severity, summary)
    store.add_case_event(case_id, "created", f"Case opened: {title[:200]}")
    for a in rows:
        attach_alert(store, case_id, a["id"])
    for key in indicators:
        add_indicator(store, case_id, key)
    return case_id


def _require(store: Store, case_id: int) -> dict[str, Any]:
    case = store.case(case_id)
    if case is None:
        raise KeyError(f"no case {case_id}")
    return case


def attach_alert(store: Store, case_id: int, alert_id: int, *, auto: bool = False) -> None:
    _require(store, case_id)
    alert = store.alert(alert_id)
    if alert is None:
        raise KeyError(f"no alert {alert_id}")
    if alert.get("case_id") == case_id:
        return
    store.set_alert_case(alert_id, case_id)
    store.add_case_indicator(case_id, alert["key"])
    device = (alert.get("context") or {}).get("device")
    if device:
        store.add_case_indicator(case_id, f"host:{device}")
    how = "Joined automatically: " if auto else "Alert added: "
    store.add_case_event(case_id, "alert", how + _alert_title(alert) + f" (score {alert['score']})")


def detach_alert(store: Store, case_id: int, alert_id: int) -> None:
    alert = store.alert(alert_id)
    if alert is None or alert.get("case_id") != case_id:
        raise KeyError(f"alert {alert_id} is not in case {case_id}")
    store.set_alert_case(alert_id, None)
    store.add_case_event(case_id, "alert", f"Alert removed: {_alert_title(alert)}")


def add_indicator(store: Store, case_id: int, key: str) -> None:
    _require(store, case_id)
    if store.node(key) is None:
        raise KeyError(f"{key} is not in the graph")
    if store.add_case_indicator(case_id, key):
        store.add_case_event(case_id, "indicator", f"Indicator added: {key}")


def remove_indicator(store: Store, case_id: int, key: str) -> None:
    if store.remove_case_indicator(case_id, key):
        store.add_case_event(case_id, "indicator", f"Indicator removed: {key}")


def note(store: Store, case_id: int, text: str) -> None:
    _require(store, case_id)
    text = (text or "").strip()
    if not text:
        raise ValueError("empty note")
    store.add_case_event(case_id, "note", text[:4000])


def update(store: Store, case_id: int, **fields: Any) -> dict[str, Any]:
    case = _require(store, case_id)
    if "status" in fields and fields["status"] not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    if "severity" in fields and fields["severity"] not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    if "title" in fields and not str(fields["title"]).strip():
        raise ValueError("a case needs a title")
    changed = {
        k: v for k, v in fields.items() if k in ("title", "status", "severity", "summary") and case[k] != v
    }
    if not changed:
        return case
    store.update_case(case_id, **changed)
    for k in ("status", "severity", "title"):
        if k in changed:
            store.add_case_event(case_id, k, f"{k.capitalize()}: {case[k]} → {changed[k]}")
    return store.case(case_id) or case


def auto_attach(store: Store, alert_id: int) -> int | None:
    """File a new alert into an open case that already holds its indicator or device."""
    alert = store.alert(alert_id)
    if alert is None or alert.get("case_id"):
        return None
    keys = [alert["key"]]
    if device := (alert.get("context") or {}).get("device"):
        keys.append(f"host:{device}")
    recent = time.time() - AUTO_ATTACH_WINDOW
    candidates = {cid for k in keys for cid in store.cases_with_indicator(k)}
    for case in sorted(filter(None, map(store.case, candidates)), key=lambda c: -c["updated"]):
        if case["status"] != "closed" and case["updated"] >= recent:
            attach_alert(store, case["id"], alert_id, auto=True)
            return case["id"]
    return None


def detail(store: Store, case_id: int) -> dict[str, Any]:
    """Everything the case view shows: the case, its alerts, indicators, devices, techniques and timeline."""
    case = _require(store, case_id)
    alerts = store.case_alerts(case_id)
    keys = store.case_indicators(case_id)
    nodes = {n["key"]: n for n in store.nodes(keys)}
    indicators = [
        {
            "key": k,
            "kind": k.split(":", 1)[0],
            "value": k.split(":", 1)[1],
            "verdict": (nodes.get(k) or {}).get("verdict"),
            "score": (nodes.get(k) or {}).get("score"),
            "name": ((nodes.get(k) or {}).get("attrs") or {}).get("name"),
        }
        for k in keys
    ]
    techniques: dict[str, dict[str, Any]] = {}
    for k in keys:
        if not k.startswith("host:"):
            for t in attack.techniques_of(store, k, associated=False):
                techniques.setdefault(t["id"], {"id": t["id"], "name": t["name"], "tactics": t["tactics"]})
    for a in alerts:
        for tid in (a.get("context") or {}).get("attack") or []:
            if tid not in techniques and (t := attack.catalogue().technique(tid)):
                techniques[tid] = {"id": tid, "name": t["name"], "tactics": t["tactics"]}
    blocked = {(b["kind"], b["value"]) for b in store.blocks()}
    for ind in indicators:
        ind["blocked"] = (
            ("device", ind["value"]) in blocked
            if ind["kind"] == "host"
            else ("indicator", ind["key"]) in blocked
        )
    timeline = [{"at": e["at"], "kind": e["kind"], "text": e["text"]} for e in store.case_events(case_id)]
    return {
        **case,
        "alerts": alerts,
        "indicators": indicators,
        "devices": [i for i in indicators if i["kind"] == "host"],
        "techniques": sorted(techniques.values(), key=lambda t: t["id"]),
        "timeline": timeline,
    }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def report(store: Store, case_id: int) -> str:
    """The case as Markdown, to paste into a ticket, email or chat."""
    d = detail(store, case_id)
    out = [
        f"# Case {d['id']}: {d['title']}",
        "",
        f"**Status:** {d['status']} · **Severity:** {d['severity']} · "
        f"**Opened:** {_iso(d['created'])} · **Updated:** {_iso(d['updated'])}",
        "",
    ]
    if d["summary"]:
        out += [d["summary"], ""]
    if d["devices"]:
        out += ["## Devices", ""]
        out += [
            f"- {i['name'] or i['value']} ({i['value']})" + (" — quarantined" if i["blocked"] else "")
            for i in d["devices"]
        ]
        out.append("")
    others = [i for i in d["indicators"] if i["kind"] != "host"]
    if others:
        out += ["## Indicators", "", "| Indicator | Verdict | Score | Blocked |", "|---|---|---|---|"]
        out += [
            f"| `{i['key']}` | {i['verdict'] or '-'} | {i['score'] if i['score'] is not None else '-'} | {'yes' if i['blocked'] else ''} |"
            for i in others
        ]
        out.append("")
    if d["techniques"]:
        out += ["## MITRE ATT&CK", ""]
        out += [f"- {t['id']} {t['name']} ({', '.join(t['tactics'])})" for t in d["techniques"]]
        out.append("")
    if d["alerts"]:
        out += ["## Alerts", ""]
        out += [
            f"- {_iso(a['at'])}: {_alert_title(a)} (score {a['score']}, {a['status']})" for a in d["alerts"]
        ]
        out.append("")
    out += ["## Timeline", ""]
    out += [f"- {_iso(e['at'])} [{e['kind']}] {e['text']}" for e in d["timeline"]]
    return "\n".join(out) + "\n"
