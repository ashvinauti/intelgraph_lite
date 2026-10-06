from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from iglite.config import Config
from iglite.engine import Engine
from iglite.fetch import Fetcher
from iglite.store import Store


class FakeTransport:
    """Maps URL prefixes to canned (status, body) responses and counts calls."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, Callable[[str, bytes | None], tuple[int, bytes]]]] = []
        self.calls: list[str] = []

    def add(self, prefix: str, status: int = 200, body: object = None) -> None:
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.routes.append((prefix, lambda url, data: (status, payload)))

    def __call__(self, method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, bytes]:
        self.calls.append(url)
        for prefix, handler in self.routes:
            if url.startswith(prefix):
                return handler(url, body)
        return 404, b""


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def make_engine(tmp_path, transport):
    def factory(**cfg_kwargs) -> Engine:
        cfg_kwargs.setdefault("disabled", ["dns", "crtsh", "rdap", "internetdb"])  # offline by default
        cfg = Config(db=":memory:", **cfg_kwargs)
        store = Store(":memory:")
        fetcher = Fetcher(store, transport=transport)
        return Engine(cfg, store=store, fetcher=fetcher)

    return factory


@pytest.fixture
def lists(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("# test blocklist\n203.0.113.66\nevil.example\nhxxp://evil[.]example/payload.bin\n")
    good = tmp_path / "good.txt"
    good.write_text("cdn.example\n198.51.100.7\n")
    other = tmp_path / "other.txt"
    other.write_text("203.0.113.66\n")
    return {"bad": str(bad), "good": str(good), "other": str(other)}
