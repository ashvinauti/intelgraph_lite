"""JSON API and dashboard on the standard-library HTTP server.

Endpoints
    GET  /                          dashboard (single static page)
    GET  /api/health
    GET  /api/stats
    GET  /api/sources
    GET  /api/indicators?verdict=&kind=&q=&limit=&offset=
    GET  /api/indicator?key=        node, assessment, evidence, edges
    GET  /api/graph?key=&depth=&limit=
    GET  /api/export/{json,csv,stix}
    GET  /api/attack?associated=0   MITRE ATT&CK matrix of techniques seen
    GET  /api/attack/technique?id=  one technique and its indicators
    GET  /api/attack/navigator      ATT&CK Navigator layer
    GET  /api/devices               gateway mode: one summary per LAN device
    GET  /api/device?ip=            one device: connections, DNS lookups, alerts, techniques
    POST /api/device/name           {"ip": "...", "name": "..."} name a device (empty name clears)
    GET  /api/lookups?since=        live feed of DNS lookups across the network
    GET  /api/blocklist/{ip,domain,url}.txt?suspicious=0&min_score=0
                                    plain-text feed for a firewall / DNS filter to pull
    GET  /api/path?from=&to=&all=0  shortest chain of edges linking two nodes
    GET  /api/cases?status=         cases (incidents); POST to create one
                                    {"title", "severity", "summary", "alerts": [ids], "indicators": [keys]}
    GET  /api/case?id=              one case: alerts, indicators, devices, techniques, timeline
    POST /api/case/update           {"id", "title"?, "status"?, "severity"?, "summary"?}
    POST /api/case/note             {"id", "text"}
    POST /api/case/alert            {"id", "alert", "remove"?}   file / unfile an alert
    POST /api/case/indicator        {"id", "key", "remove"?}
    GET  /api/case/report?id=       the case as Markdown
    GET  /api/blocks                blocked indicators and quarantined devices
    POST /api/block                 {"value", "device"?, "note"?, "case_id"?}; /api/unblock {"value", "device"?}
    GET  /api/notify                notification channels and recent deliveries; POST /api/notify/test
    POST /api/extract      {"text": "..."}
    POST /api/investigate  {"indicators": [...], "text": "...", "depth": 1, "budget": 50}

Binds to 127.0.0.1 by default. Set IGLITE_API_TOKEN to require
``Authorization: Bearer <token>`` on every /api request. Blocklist feeds also
accept ``?token=``, because firewalls that pull URL lists can't send headers.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__, attack, cases, export, respond
from .engine import Engine
from .extract import classify, extract
from .model import KINDS
from .sources import describe

MAX_BODY = 1024 * 1024
MAX_SEEDS = 200


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


def make_handler(engine: Engine) -> type[BaseHTTPRequestHandler]:
    page = resources.files("iglite").joinpath("web/index.html").read_bytes()
    token = engine.config.api_token

    class Handler(BaseHTTPRequestHandler):
        server_version = f"iglite/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:  # quieter default logging
            pass

        # -- plumbing ------------------------------------------------------

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: Any, status: int = 200) -> None:
            self._send(status, json.dumps(data, default=str).encode(), "application/json")

        def _authorised(self, q: dict[str, str], path: str) -> bool:
            if not token:
                return True
            given = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if not given and path.startswith("/api/blocklist/"):
                given = q.get("token", "")
            return hmac.compare_digest(given.encode(), token.encode())

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid JSON")
            if not isinstance(data, dict):
                raise ApiError(HTTPStatus.BAD_REQUEST, "expected a JSON object")
            return data

        def _dispatch(self, method: str) -> None:
            url = urlsplit(self.path)
            q = {k: v[-1] for k, v in parse_qs(url.query).items()}
            if method == "GET" and url.path in ("/", "/index.html"):
                self._send(200, page, "text/html; charset=utf-8")
                return
            if url.path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
                return
            if not url.path.startswith("/api/"):
                self._json({"error": "not found"}, 404)
                return
            if not self._authorised(q, url.path):
                self._json({"error": "unauthorised"}, 401)
                return
            route = ROUTES.get((method, url.path))
            if route is None and method == "GET" and url.path.startswith("/api/export/"):
                route, q["format"] = _export, url.path.rsplit("/", 1)[1]
            if route is None and method == "GET" and url.path.startswith("/api/blocklist/"):
                route, q["kind"] = _blocklist, url.path.rsplit("/", 1)[1].removesuffix(".txt")
            if route is None:
                self._json({"error": "not found"}, 404)
                return
            try:
                result = route(engine, q, self._body() if method == "POST" else {})
            except ApiError as exc:
                self._json({"error": str(exc)}, exc.status)
                return
            except Exception as exc:  # never leak a traceback to the client
                self._json({"error": f"internal error: {type(exc).__name__}"}, 500)
                return
            if isinstance(result, tuple):
                self._send(200, result[0].encode(), result[1])
            else:
                self._json(result)

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

    return Handler


# -- routes ----------------------------------------------------------------


def _int(q: dict[str, str], name: str, default: int, hi: int) -> int:
    try:
        return max(0, min(hi, int(q.get(name, default))))
    except ValueError:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"{name} must be an integer")


def _key(q: dict[str, str]) -> str:
    raw = q.get("key", "")
    if raw.split(":", 1)[0] in KINDS:
        return raw
    ind = classify(raw)
    if ind is None:
        raise ApiError(HTTPStatus.BAD_REQUEST, "key must be an indicator or kind:value")
    return ind.key


def _health(engine: Engine, q: dict, body: dict) -> Any:
    return {"status": "ok", "version": __version__, "demo": engine.demo}


def _stats(engine: Engine, q: dict, body: dict) -> Any:
    return engine.store.stats()


def _sources(engine: Engine, q: dict, body: dict) -> Any:
    stats = engine.store.source_feedback_stats()
    if engine.demo:  # the invented demo sources, not the real ones
        listed = [
            {
                "name": s.name,
                "status": "enabled",
                "kinds": sorted(k.value for k in s.kinds),
                "trust": s.trust,
                "description": s.description,
            }
            for s in engine.sources
        ]
        return [{**s, **stats.get(s["name"], {"false_positives": 0, "confirmed": 0})} for s in listed]
    return [
        {**s, **stats.get(s["name"], {"false_positives": 0, "confirmed": 0})} for s in describe(engine.config)
    ]


def _feedback_set(engine: Engine, q: dict, body: dict) -> Any:
    verdict = body.get("verdict")
    if verdict not in ("false_positive", "confirmed", "clear"):
        raise ApiError(HTTPStatus.BAD_REQUEST, "verdict must be false_positive, confirmed or clear")
    key = _key({"key": str(body.get("key", ""))})
    try:
        a = engine.set_feedback(key, None if verdict == "clear" else verdict, str(body.get("note") or ""))
    except KeyError:
        raise ApiError(HTTPStatus.NOT_FOUND, f"{key} not found")
    return {"key": key, "assessment": a.as_dict()}


def _feedback_list(engine: Engine, q: dict, body: dict) -> Any:
    return {"feedback": engine.store.all_feedback(), "sources": engine.store.source_feedback_stats()}


def _suppressions(engine: Engine, q: dict, body: dict) -> Any:
    return engine.store.suppressions()


def _suppression_add(engine: Engine, q: dict, body: dict) -> Any:
    kind, value = body.get("kind"), str(body.get("value") or "").strip()
    if kind not in ("indicator", "process", "device") or not value:
        raise ApiError(HTTPStatus.BAD_REQUEST, "kind must be indicator, process or device, with a value")
    if kind == "indicator":
        value = _key({"key": value})
    elif kind == "device":
        ind = classify(value)
        if ind is None or ind.kind.value != "ip":
            raise ApiError(HTTPStatus.BAD_REQUEST, "a device is its LAN IP address")
        value = ind.value
    return {
        "id": engine.store.add_suppression(
            kind, value.lower() if kind == "process" else value, str(body.get("note") or "")[:500]
        )
    }


def _suppression_delete(engine: Engine, q: dict, body: dict) -> Any:
    try:
        ok = engine.store.remove_suppression(int(body.get("id")))
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "id must be an integer")
    if not ok:
        raise ApiError(HTTPStatus.NOT_FOUND, "no such rule")
    return {"ok": True}


def _indicators(engine: Engine, q: dict, body: dict) -> Any:
    return engine.store.search(
        verdict=q.get("verdict") or None,
        kind=q.get("kind") or None,
        text=q.get("q") or None,
        limit=_int(q, "limit", 100, 1000),
        offset=_int(q, "offset", 0, 10**9),
    )


def _indicator(engine: Engine, q: dict, body: dict) -> Any:
    key = _key(q)
    node = engine.store.node(key)
    if node is None:
        raise ApiError(HTTPStatus.NOT_FOUND, f"{key} not found")
    edges = engine.store.edges_of(key)[:500]
    others = {e["dst"] if e["src"] == key else e["src"] for e in edges}
    return {
        "node": node,
        "assessment": engine.assess(key).as_dict(),
        "evidence": [asdict(e) for e in engine.store.evidence(key)],
        "edges": edges,
        # The other end of each edge, so the details panel can show verdicts and names.
        "neighbours": {
            n["key"]: {
                "kind": n["kind"],
                "verdict": n["verdict"],
                "score": n["score"],
                "name": (n["attrs"] or {}).get("name") or (n["attrs"] or {}).get("attack.name"),
            }
            for n in engine.store.nodes(others)
        },
        "attack": attack.techniques_of(engine.store, key),
        "attack_entry": _attack_entry(key),
        "blocked": key in respond.blocked_keys(engine.store),
        "cases": [
            {"id": c["id"], "title": c["title"], "status": c["status"]}
            for c in filter(None, map(engine.store.case, engine.store.cases_with_indicator(key)))
        ],
    }


def _attack_entry(key: str) -> dict[str, Any] | None:
    """Catalogue entry when the node itself is an ATT&CK technique, software or group."""
    kind, _, value = key.partition(":")
    if kind == "technique":
        return attack.catalogue().technique(value)
    if kind in ("software", "group"):
        return attack.catalogue().entity(kind, value)
    return None


def _flag(q: dict[str, str], name: str) -> bool:
    return q.get(name, "").lower() in ("1", "true", "yes", "on")


def _attack(engine: Engine, q: dict, body: dict) -> Any:
    return attack.summary(engine.store, associated=_flag(q, "associated"))


def _attack_technique(engine: Engine, q: dict, body: dict) -> Any:
    tech = attack.technique_node(q.get("id", ""))
    if tech is None:
        raise ApiError(HTTPStatus.BAD_REQUEST, "id must be a technique ID such as T1071.001")
    return attack.detail(engine.store, tech.value, associated=_flag(q, "associated") or "associated" not in q)


def _attack_navigator(engine: Engine, q: dict, body: dict) -> Any:
    return json.dumps(
        attack.navigator_layer(engine.store, associated=_flag(q, "associated"))
    ), "application/json"


def _graph(engine: Engine, q: dict, body: dict) -> Any:
    return engine.store.neighbourhood(_key(q), _int(q, "depth", 1, 3), _int(q, "limit", 150, 1000))


def _export(engine: Engine, q: dict, body: dict) -> Any:
    fmt = q.get("format", "")
    if fmt not in export.FORMATS:
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown export format")
    ctype = "text/csv" if fmt == "csv" else "application/json"
    return export.FORMATS[fmt](engine.store, None), ctype


def _blocklist(engine: Engine, q: dict, body: dict) -> Any:
    if q.get("kind") not in export.BLOCKLIST_KINDS:
        raise ApiError(HTTPStatus.NOT_FOUND, "blocklists: ip.txt, domain.txt, url.txt")
    text = export.blocklist(
        engine.store,
        q["kind"],
        suspicious=_flag(q, "suspicious"),
        min_score=_int(q, "min_score", 0, 100),
        shared_infra=engine.shared_infra,
        comments=_flag(q, "comments"),
    )
    return text, "text/plain; charset=utf-8"


def _device_ip(raw: Any) -> str:
    ind = classify(str(raw or ""))
    if ind is None or ind.kind.value != "ip":
        raise ApiError(HTTPStatus.BAD_REQUEST, "ip must be a device's IP address")
    return ind.value


def _devices(engine: Engine, q: dict, body: dict) -> Any:
    watch = engine.watcher()
    return {"status": watch.status(), "devices": watch.devices()}


def _device(engine: Engine, q: dict, body: dict) -> Any:
    return engine.watcher().device(_device_ip(q.get("ip")))


def _device_name(engine: Engine, q: dict, body: dict) -> Any:
    ip = _device_ip(body.get("ip"))
    name = " ".join(str(body.get("name") or "").split())[:60] or None
    engine.watcher().rename(ip, name)
    return {"ip": ip, "name": name}


def _lookups(engine: Engine, q: dict, body: dict) -> Any:
    try:
        since = float(q.get("since") or 0)
    except ValueError:
        raise ApiError(HTTPStatus.BAD_REQUEST, "since must be a number")
    return engine.watcher().lookup_feed(since, _int(q, "limit", 200, 1000))


def _watch_status(engine: Engine, q: dict, body: dict) -> Any:
    return engine.watcher().status()


def _watch_control(engine: Engine, q: dict, body: dict) -> Any:
    action = body.get("action")
    try:
        interval = float(body["interval"]) if body.get("interval") else None
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "interval must be a number")
    watch = engine.watcher(interval)
    if action == "start":
        watch.start()
    elif action == "stop":
        watch.stop()
    elif action == "scan":
        return {**watch.status(), "result": watch.scan()}
    else:
        raise ApiError(HTTPStatus.BAD_REQUEST, "action must be start, stop or scan")
    return watch.status()


def _connections(engine: Engine, q: dict, body: dict) -> Any:
    watch = engine.watcher()
    rules: dict[str, set[str]] = {}
    for rule in engine.store.suppressions():  # current rules, not those at scan time
        rules.setdefault(rule["kind"], set()).add(rule["value"])
    rows = [
        {**r, "suppressed": watch._suppressed(r["key"], r["process"], rules, r.get("device"))}
        for r in watch.rows[:1000]
    ]
    return {"status": watch.status(), "connections": rows}


def _alerts(engine: Engine, q: dict, body: dict) -> Any:
    alerts = engine.store.alerts(_int(q, "since", 0, 2**62), _int(q, "limit", 100, 1000))
    triage = engine.store.latest_triage(alert_ids=[a["id"] for a in alerts])
    return [{**a, "triage": triage.get(a["id"])} for a in alerts]


def _triage_status(engine: Engine, q: dict, body: dict) -> Any:
    return engine.triage_worker().status()


def _triage_submit(engine: Engine, q: dict, body: dict) -> Any:
    from .llm import AgentUnavailable

    alert_id, key = body.get("alert_id"), body.get("key")
    try:
        alert_id = int(alert_id) if alert_id is not None else None
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "alert_id must be an integer")
    if alert_id is None and not key:
        raise ApiError(HTTPStatus.BAD_REQUEST, "give alert_id or key")
    if alert_id is None:
        key = _key({"key": str(key)})
        if engine.store.node(key) is None:
            raise ApiError(HTTPStatus.NOT_FOUND, f"{key} not found")
    elif not any(a["id"] == alert_id for a in engine.store.alerts(limit=1000)):
        raise ApiError(HTTPStatus.NOT_FOUND, f"no alert #{alert_id}")
    try:
        engine.triage_worker().submit(alert_id=alert_id, key=key, trigger="manual")
    except AgentUnavailable as exc:
        raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
    return {"queued": True, "alert_id": alert_id, "key": key}


def _triage_latest(engine: Engine, q: dict, body: dict) -> Any:
    if q.get("alert_id"):
        return engine.store.latest_triage(alert_ids=[_int(q, "alert_id", 0, 2**62)]).get(
            _int(q, "alert_id", 0, 2**62)
        )
    key = _key(q)
    return engine.store.latest_triage(key=key).get(key)


def _history(engine: Engine, q: dict, body: dict) -> Any:
    return [
        {"at": at, "connections": c, "public": p, "flagged": f} for at, c, p, f in engine.watcher().history
    ]


def _trace_start(engine: Engine, q: dict, body: dict) -> Any:
    try:
        job = engine.tracer().start(str(body.get("target", "")), int(body.get("max_hops", 20)))
    except (TypeError, ValueError) as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc))
    except RuntimeError as exc:
        raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, str(exc))
    return engine.tracer().describe(job)


def _trace_get(engine: Engine, q: dict, body: dict) -> Any:
    tracer = engine.tracer()
    job = tracer.jobs.get(_int(q, "id", 0, 2**62))
    if job is None:
        raise ApiError(HTTPStatus.NOT_FOUND, "no such trace")
    return tracer.describe(job)


def _traces(engine: Engine, q: dict, body: dict) -> Any:
    tracer = engine.tracer()
    running = [tracer.describe(j) for j in sorted(tracer.jobs.values(), key=lambda j: -j.id)]
    return {"jobs": running, "saved": engine.store.routes(20)}


def _agent_status(engine: Engine, q: dict, body: dict) -> Any:
    return engine.agent_desk().status()


def _agent_ask(engine: Engine, q: dict, body: dict) -> Any:
    from .agent import AgentUnavailable

    desk = engine.agent_desk()
    session = str(body.get("session") or "default")[:64]
    try:
        job = desk.ask(str(body.get("question", "")), session)
    except ValueError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc))
    except AgentUnavailable as exc:
        raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
    except RuntimeError as exc:
        raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, str(exc))
    return desk.describe(job)


def _agent_get(engine: Engine, q: dict, body: dict) -> Any:
    desk = engine.agent_desk()
    job = desk.jobs.get(_int(q, "id", 0, 2**62))
    if job is None:
        raise ApiError(HTTPStatus.NOT_FOUND, "no such question")
    return desk.describe(job)


def _agent_reset(engine: Engine, q: dict, body: dict) -> Any:
    engine.agent_desk().reset(str(body.get("session") or "default")[:64])
    return {"ok": True}


def _extract(engine: Engine, q: dict, body: dict) -> Any:
    return [i.key for i in extract(str(body.get("text", ""))[:MAX_BODY])]


def _investigate(engine: Engine, q: dict, body: dict) -> Any:
    seeds = []
    for raw in body.get("indicators") or []:
        ind = classify(str(raw))
        if ind is None:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"not an indicator: {raw!r}")
        seeds.append(ind)
    if body.get("text"):
        seeds += extract(str(body["text"]))
    if not seeds:
        raise ApiError(HTTPStatus.BAD_REQUEST, "no indicators given")
    if len(seeds) > MAX_SEEDS:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"at most {MAX_SEEDS} indicators per request")
    cfg = engine.config
    try:
        depth = max(0, min(int(body.get("depth", cfg.depth)), 3))
        budget = max(1, min(int(body.get("budget", cfg.budget)), 500))
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "depth and budget must be integers")
    report = engine.investigate(seeds, depth=depth, budget=budget)
    return report.as_dict()


# -- cases ---------------------------------------------------------------------------------


def _case_id(raw: Any) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "id must be a case number")


def _case_call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except KeyError as exc:
        raise ApiError(HTTPStatus.NOT_FOUND, str(exc).strip("'\""))
    except ValueError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc))


def _cases(engine: Engine, q: dict, body: dict) -> Any:
    status = q.get("status") or None
    if status and status not in cases.STATUSES:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"status must be one of {', '.join(cases.STATUSES)}")
    return engine.store.cases(status)


def _case_create(engine: Engine, q: dict, body: dict) -> Any:
    alerts = [_case_id(a) for a in body.get("alerts") or []]
    keys = [_key({"key": str(k)}) for k in body.get("indicators") or []]
    case_id = _case_call(
        cases.create,
        engine.store,
        str(body.get("title") or ""),
        severity=str(body.get("severity") or "medium"),
        summary=str(body.get("summary") or "")[:4000],
        alerts=alerts,
        indicators=keys,
    )
    return cases.detail(engine.store, case_id)


def _case(engine: Engine, q: dict, body: dict) -> Any:
    return _case_call(cases.detail, engine.store, _case_id(q.get("id")))


def _case_update(engine: Engine, q: dict, body: dict) -> Any:
    case_id = _case_id(body.get("id"))
    fields = {k: str(body[k])[:4000] for k in ("title", "status", "severity", "summary") if k in body}
    _case_call(cases.update, engine.store, case_id, **fields)
    return cases.detail(engine.store, case_id)


def _case_note(engine: Engine, q: dict, body: dict) -> Any:
    case_id = _case_id(body.get("id"))
    _case_call(cases.note, engine.store, case_id, str(body.get("text") or ""))
    return cases.detail(engine.store, case_id)


def _case_alert(engine: Engine, q: dict, body: dict) -> Any:
    case_id, alert_id = _case_id(body.get("id")), _case_id(body.get("alert"))
    fn = cases.detach_alert if body.get("remove") else cases.attach_alert
    _case_call(fn, engine.store, case_id, alert_id)
    return cases.detail(engine.store, case_id)


def _case_indicator(engine: Engine, q: dict, body: dict) -> Any:
    case_id, key = _case_id(body.get("id")), _key({"key": str(body.get("key") or "")})
    fn = cases.remove_indicator if body.get("remove") else cases.add_indicator
    _case_call(fn, engine.store, case_id, key)
    return cases.detail(engine.store, case_id)


def _case_report(engine: Engine, q: dict, body: dict) -> Any:
    return _case_call(cases.report, engine.store, _case_id(q.get("id"))), "text/markdown; charset=utf-8"


# -- response ------------------------------------------------------------------------------


def _blocks(engine: Engine, q: dict, body: dict) -> Any:
    return {"blocks": engine.store.blocks(), "enforcer": respond.enforcer(engine.config).name}


def _block(engine: Engine, q: dict, body: dict) -> Any:
    case_id = _case_id(body["case_id"]) if body.get("case_id") not in (None, "") else None
    return _case_call(
        respond.block,
        engine,
        str(body.get("value") or ""),
        device=bool(body.get("device")),
        note=str(body.get("note") or "")[:500],
        case_id=case_id,
    )


def _unblock(engine: Engine, q: dict, body: dict) -> Any:
    return _case_call(respond.unblock, engine, str(body.get("value") or ""), device=bool(body.get("device")))


# -- graph path ------------------------------------------------------------------------------

# Hubs that connect everything to everything: never stepping stones unless asked for.
PATH_AVOID = ("tag:", "technique:", "software:", "group:", "asn:", "host:gateway", "host:this-computer")


def _path(engine: Engine, q: dict, body: dict) -> Any:
    src, dst = _key({"key": q.get("from", "")}), _key({"key": q.get("to", "")})
    for k in (src, dst):
        if engine.store.node(k) is None:
            raise ApiError(HTTPStatus.NOT_FOUND, f"{k} not found")
    found = engine.store.path(
        src, dst, max_hops=_int(q, "max_hops", 6, 8), avoid=() if _flag(q, "all") else PATH_AVOID
    )
    return {
        "from": src,
        "to": dst,
        "found": found is not None,
        **(found or {"nodes": [], "edges": [], "hops": None}),
    }


# -- notifications --------------------------------------------------------------------------


def _notify_status(engine: Engine, q: dict, body: dict) -> Any:
    return engine.notifier().status()


def _notify_test(engine: Engine, q: dict, body: dict) -> Any:
    try:
        return {"results": engine.notifier().test()}
    except RuntimeError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc))


ROUTES = {
    ("GET", "/api/health"): _health,
    ("GET", "/api/stats"): _stats,
    ("GET", "/api/sources"): _sources,
    ("GET", "/api/indicators"): _indicators,
    ("GET", "/api/indicator"): _indicator,
    ("GET", "/api/graph"): _graph,
    ("GET", "/api/attack"): _attack,
    ("GET", "/api/attack/technique"): _attack_technique,
    ("GET", "/api/attack/navigator"): _attack_navigator,
    ("POST", "/api/extract"): _extract,
    ("POST", "/api/investigate"): _investigate,
    ("GET", "/api/watch"): _watch_status,
    ("POST", "/api/watch"): _watch_control,
    ("GET", "/api/connections"): _connections,
    ("GET", "/api/devices"): _devices,
    ("GET", "/api/device"): _device,
    ("POST", "/api/device/name"): _device_name,
    ("GET", "/api/lookups"): _lookups,
    ("GET", "/api/alerts"): _alerts,
    ("GET", "/api/watch/history"): _history,
    ("POST", "/api/trace"): _trace_start,
    ("GET", "/api/trace"): _trace_get,
    ("GET", "/api/traces"): _traces,
    ("GET", "/api/triage/status"): _triage_status,
    ("POST", "/api/triage"): _triage_submit,
    ("GET", "/api/triage/latest"): _triage_latest,
    ("POST", "/api/feedback"): _feedback_set,
    ("GET", "/api/feedback"): _feedback_list,
    ("GET", "/api/suppressions"): _suppressions,
    ("POST", "/api/suppressions"): _suppression_add,
    ("POST", "/api/suppressions/delete"): _suppression_delete,
    ("GET", "/api/cases"): _cases,
    ("POST", "/api/cases"): _case_create,
    ("GET", "/api/case"): _case,
    ("POST", "/api/case/update"): _case_update,
    ("POST", "/api/case/note"): _case_note,
    ("POST", "/api/case/alert"): _case_alert,
    ("POST", "/api/case/indicator"): _case_indicator,
    ("GET", "/api/case/report"): _case_report,
    ("GET", "/api/blocks"): _blocks,
    ("POST", "/api/block"): _block,
    ("POST", "/api/unblock"): _unblock,
    ("GET", "/api/path"): _path,
    ("GET", "/api/notify"): _notify_status,
    ("POST", "/api/notify/test"): _notify_test,
    ("GET", "/api/agent/status"): _agent_status,
    ("POST", "/api/agent"): _agent_ask,
    ("GET", "/api/agent"): _agent_get,
    ("POST", "/api/agent/reset"): _agent_reset,
}


def make_server(engine: Engine, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(engine))
    server.daemon_threads = True
    return server


def serve(engine: Engine, host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in ("127.0.0.1", "localhost", "::1") and not engine.config.api_token:
        raise SystemExit("refusing to listen on a public interface without IGLITE_API_TOKEN set")
    server = make_server(engine, host, port)
    print(f"IntelGraph Lite on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    finally:
        server.server_close()
