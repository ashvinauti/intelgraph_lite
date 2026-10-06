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
    POST /api/extract      {"text": "..."}
    POST /api/investigate  {"indicators": [...], "text": "...", "depth": 1, "budget": 50}

Binds to 127.0.0.1 by default. Set IGLITE_API_TOKEN to require
``Authorization: Bearer <token>`` on every /api request.
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

from . import __version__, export
from .engine import Engine
from .extract import classify, extract
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

        def _authorised(self) -> bool:
            if not token:
                return True
            given = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
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
            if not self._authorised():
                self._json({"error": "unauthorised"}, 401)
                return
            route = ROUTES.get((method, url.path))
            if route is None and method == "GET" and url.path.startswith("/api/export/"):
                route, q["format"] = _export, url.path.rsplit("/", 1)[1]
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
    if raw.split(":", 1)[0] in {"ip", "domain", "url", "hash", "cve", "email", "asn", "org", "tag", "report"}:
        return raw
    ind = classify(raw)
    if ind is None:
        raise ApiError(HTTPStatus.BAD_REQUEST, "key must be an indicator or kind:value")
    return ind.key


def _health(engine: Engine, q: dict, body: dict) -> Any:
    return {"status": "ok", "version": __version__}


def _stats(engine: Engine, q: dict, body: dict) -> Any:
    return engine.store.stats()


def _sources(engine: Engine, q: dict, body: dict) -> Any:
    return describe(engine.config)


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
    return {
        "node": node,
        "assessment": engine.assess(key).as_dict(),
        "evidence": [asdict(e) for e in engine.store.evidence(key)],
        "edges": engine.store.edges_of(key)[:500],
    }


def _graph(engine: Engine, q: dict, body: dict) -> Any:
    return engine.store.neighbourhood(_key(q), _int(q, "depth", 1, 3), _int(q, "limit", 150, 1000))


def _export(engine: Engine, q: dict, body: dict) -> Any:
    fmt = q.get("format", "")
    if fmt not in export.FORMATS:
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown export format")
    ctype = "text/csv" if fmt == "csv" else "application/json"
    return export.FORMATS[fmt](engine.store, None), ctype


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


ROUTES = {
    ("GET", "/api/health"): _health,
    ("GET", "/api/stats"): _stats,
    ("GET", "/api/sources"): _sources,
    ("GET", "/api/indicators"): _indicators,
    ("GET", "/api/indicator"): _indicator,
    ("GET", "/api/graph"): _graph,
    ("POST", "/api/extract"): _extract,
    ("POST", "/api/investigate"): _investigate,
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
