"""Polite, cached HTTP client built on the standard library.

Every response (including 404s, which are useful negative answers) is cached
in SQLite for the source's TTL, so repeating an investigation costs no
network traffic. A per-host minimum interval keeps free API tiers happy.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode, urlsplit

from . import __version__
from .store import Store

# (method, url, headers, body) -> (status, body)
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]

USER_AGENT = f"iglite/{__version__} (+https://github.com/ashvinauti/intelgraph_lite)"
MAX_BODY = 8 * 1024 * 1024


class FetchError(Exception):
    pass


def urllib_transport(timeout: float) -> Transport:
    def send(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - http(s) only
                return resp.status, resp.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(MAX_BODY) if exc.fp else b""

    return send


class Fetcher:
    def __init__(
        self,
        store: Store,
        *,
        timeout: float = 10.0,
        offline: bool = False,
        transport: Transport | None = None,
        min_interval: dict[str, float] | None = None,
    ) -> None:
        self.store = store
        self.offline = offline
        self._send = transport or urllib_transport(timeout)
        self._min_interval = min_interval or {}
        self._host_locks: dict[str, threading.Lock] = {}
        self._last_call: dict[str, float] = {}
        self._guard = threading.Lock()
        self.network_calls = 0

    def _throttle(self, host: str) -> threading.Lock:
        with self._guard:
            return self._host_locks.setdefault(host, threading.Lock())

    def request(
        self,
        method: str,
        url: str,
        *,
        ttl: float,
        headers: dict[str, str] | None = None,
        form: dict[str, str] | None = None,
    ) -> tuple[int, bytes] | None:
        """Return ``(status, body)``, from cache when fresh; ``None`` if unavailable."""
        if not url.startswith(("https://", "http://")):
            raise FetchError(f"refusing non-HTTP URL: {url}")
        body = urlencode(form).encode() if form is not None else None
        # Credentials live in headers and are deliberately not part of the key.
        cache_key = method + " " + url
        if body:
            cache_key += " " + hashlib.sha256(body).hexdigest()
        cached = self.store.cache_get(cache_key, ttl)
        if cached is not None:
            return cached
        if self.offline:
            return None

        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
        hdrs.update(headers or {})
        if body is not None:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        host = urlsplit(url).hostname or ""
        interval = self._min_interval.get(host, 0.0)
        with self._throttle(host):
            wait = self._last_call.get(host, 0.0) + interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            try:
                status, payload = self._send(method, url, hdrs, body)
            except (OSError, ValueError) as exc:
                raise FetchError(f"{host}: {exc}") from exc
            finally:
                self._last_call[host] = time.monotonic()
                self.network_calls += 1

        if status == 429 or status >= 500:
            raise FetchError(f"{host}: HTTP {status}")  # transient: don't cache
        self.store.cache_put(cache_key, status, payload)
        return status, payload

    def json(self, url: str, *, ttl: float, **kw: Any) -> Any | None:
        """Decoded JSON for a 2xx response; ``None`` for 404/empty/unavailable."""
        result = self.request(kw.pop("method", "GET"), url, ttl=ttl, **kw)
        if result is None:
            return None
        status, body = result
        if status == 404 or not body.strip():
            return None
        if status >= 400:
            raise FetchError(f"{urlsplit(url).hostname}: HTTP {status}")
        try:
            return json.loads(body)
        except ValueError as exc:
            raise FetchError(f"{urlsplit(url).hostname}: invalid JSON") from exc

    def memo(self, key: str, ttl: float, compute: Callable[[], Any]) -> Any:
        """Cache the JSON-serialisable result of a non-HTTP lookup (e.g. DNS)."""
        cached = self.store.cache_get("memo " + key, ttl)
        if cached is not None:
            return json.loads(cached[1])
        if self.offline:
            return None
        value = compute()
        self.store.cache_put("memo " + key, 200, json.dumps(value).encode())
        return value
