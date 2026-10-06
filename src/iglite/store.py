"""SQLite storage: the database *is* the graph.

Nodes, edges, evidence and the HTTP response cache live in one file. Graph
traversal is done with indexed recursive SQL queries, so memory use is
proportional to the answer, not to the size of the knowledge base.

All access goes through a single connection guarded by a lock. Lookups run in
worker threads but SQLite writes are short, so one writer is simpler and
fast enough.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .model import Evidence, Indicator, Relation, Verdict

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS nodes (
    key         TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    attrs       TEXT NOT NULL DEFAULT '{}',
    score       INTEGER,
    verdict     TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS nodes_verdict ON nodes(verdict, score DESC);
CREATE INDEX IF NOT EXISTS nodes_kind ON nodes(kind);

CREATE TABLE IF NOT EXISTS edges (
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    rel         TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    PRIMARY KEY (src, dst, rel)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst);

CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY,
    node        TEXT NOT NULL,
    source      TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    confidence  REAL NOT NULL,
    detail      TEXT NOT NULL,
    url         TEXT,
    observed_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_node ON evidence(node, source);

CREATE TABLE IF NOT EXISTS cache (
    key         TEXT PRIMARY KEY,
    status      INTEGER NOT NULL,
    body        BLOB NOT NULL,
    fetched_at  REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute("PRAGMA foreign_keys=OFF")
            self._db.executescript(_SCHEMA)
            row = self._db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
            if row is None:
                self._db.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            elif int(row["v"]) > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema v{row['v']} is newer than this release (v{SCHEMA_VERSION})"
                )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    def _query(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, tuple(args)).fetchall()

    # -- nodes -------------------------------------------------------------

    def upsert_node(self, ind: Indicator, attrs: dict[str, Any] | None = None) -> None:
        now = time.time()
        with self.transaction() as db:
            row = db.execute("SELECT attrs FROM nodes WHERE key=?", (ind.key,)).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO nodes (key, kind, value, attrs, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                    (ind.key, ind.kind.value, ind.value, json.dumps(attrs or {}), now, now),
                )
            else:
                merged = json.loads(row["attrs"])
                merged.update(attrs or {})
                db.execute(
                    "UPDATE nodes SET attrs=?, last_seen=? WHERE key=?",
                    (json.dumps(merged, sort_keys=True), now, ind.key),
                )

    def set_assessment(self, key: str, score: int, verdict: Verdict) -> None:
        with self._lock:
            self._db.execute("UPDATE nodes SET score=?, verdict=? WHERE key=?", (score, verdict.value, key))

    def node(self, key: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM nodes WHERE key=?", (key,))
        return _node_dict(rows[0]) if rows else None

    def nodes(self, keys: Iterable[str]) -> list[dict[str, Any]]:
        keys = list(keys)
        out: list[dict[str, Any]] = []
        for i in range(0, len(keys), 500):  # stay under SQLite's variable limit
            chunk = keys[i : i + 500]
            marks = ",".join("?" * len(chunk))
            out += [
                _node_dict(r)
                for r in self._query(f"SELECT * FROM nodes WHERE key IN ({marks})", chunk)  # noqa: S608 - placeholders only
            ]
        return out

    def search(
        self,
        *,
        verdict: str | None = None,
        kind: str | None = None,
        text: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where, args = [], []
        if verdict:
            where.append("verdict=?")
            args.append(verdict)
        if kind:
            where.append("kind=?")
            args.append(kind)
        if text:
            where.append("value LIKE ? ESCAPE '\\'")
            escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            args.append(f"%{escaped}%")
        sql = "SELECT * FROM nodes"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY COALESCE(score, -1) DESC, last_seen DESC LIMIT ? OFFSET ?"
        return [_node_dict(r) for r in self._query(sql, [*args, limit, offset])]

    def stats(self) -> dict[str, Any]:
        def count(sql: str) -> int:
            return int(self._query(sql)[0][0])

        by_verdict = {
            (r["verdict"] or "unscored"): r["n"]
            for r in self._query("SELECT verdict, COUNT(*) n FROM nodes GROUP BY verdict")
        }
        by_kind = {r["kind"]: r["n"] for r in self._query("SELECT kind, COUNT(*) n FROM nodes GROUP BY kind")}
        return {
            "nodes": count("SELECT COUNT(*) FROM nodes"),
            "edges": count("SELECT COUNT(*) FROM edges"),
            "evidence": count("SELECT COUNT(*) FROM evidence"),
            "cached_responses": count("SELECT COUNT(*) FROM cache"),
            "by_verdict": by_verdict,
            "by_kind": by_kind,
        }

    # -- edges -------------------------------------------------------------

    def add_relation(self, rel: Relation, source: str) -> None:
        now = time.time()
        with self._lock:
            self._db.execute(
                "INSERT INTO edges VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(src, dst, rel) DO UPDATE SET last_seen=excluded.last_seen",
                (rel.src.key, rel.dst.key, rel.rel, source, now, now),
            )

    def edges_of(self, key: str) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT src, dst, rel, source FROM edges WHERE src=?"
            " UNION ALL SELECT src, dst, rel, source FROM edges WHERE dst=?",
            (key, key),
        )
        return [dict(r) for r in rows]

    def neighbourhood(self, key: str, depth: int = 1, limit: int = 200) -> dict[str, Any]:
        """Nodes within ``depth`` hops of ``key`` (both directions), capped at ``limit``."""
        rows = self._query(
            """
            WITH RECURSIVE walk(key, depth) AS (
                SELECT ?, 0
                UNION
                SELECT e.dst, w.depth + 1 FROM walk w JOIN edges e ON e.src = w.key
                 WHERE w.depth < ?
                UNION
                SELECT e.src, w.depth + 1 FROM walk w JOIN edges e ON e.dst = w.key
                 WHERE w.depth < ?
            )
            SELECT key, MIN(depth) AS depth FROM walk GROUP BY key ORDER BY depth LIMIT ?
            """,
            (key, depth, depth, limit),
        )
        depths = {r["key"]: r["depth"] for r in rows}
        nodes = self.nodes(depths)
        for n in nodes:
            n["depth"] = depths[n["key"]]
        keys = list(depths)
        edges: list[dict[str, Any]] = []
        for i in range(0, len(keys), 400):
            chunk = keys[i : i + 400]
            marks = ",".join("?" * len(chunk))
            edges += [
                dict(r)
                for r in self._query(
                    f"SELECT src, dst, rel, source FROM edges WHERE src IN ({marks})",  # noqa: S608
                    chunk,
                )
                if r["dst"] in depths
            ]
        return {"root": key, "nodes": nodes, "edges": edges}

    # -- evidence ----------------------------------------------------------

    def replace_evidence(self, key: str, source: str, items: Iterable[Evidence]) -> None:
        """Swap one source's evidence for a node. Re-running a lookup never duplicates."""
        now = time.time()
        with self.transaction() as db:
            db.execute("DELETE FROM evidence WHERE node=? AND source=?", (key, source))
            db.executemany(
                "INSERT INTO evidence (node, source, verdict, confidence, detail, url, observed_at)"
                " VALUES (?,?,?,?,?,?,?)",
                [(key, source, e.verdict.value, e.confidence, e.detail, e.url, now) for e in items],
            )

    def evidence(self, key: str) -> list[Evidence]:
        rows = self._query(
            "SELECT source, verdict, confidence, detail, url FROM evidence WHERE node=? ORDER BY id",
            (key,),
        )
        return [
            Evidence(r["source"], Verdict(r["verdict"]), r["detail"], r["confidence"], r["url"]) for r in rows
        ]

    # -- cache -------------------------------------------------------------

    def cache_get(self, key: str, max_age: float) -> tuple[int, bytes] | None:
        rows = self._query(
            "SELECT status, body FROM cache WHERE key=? AND fetched_at >= ?",
            (key, time.time() - max_age),
        )
        return (rows[0]["status"], bytes(rows[0]["body"])) if rows else None

    def cache_put(self, key: str, status: int, body: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO cache VALUES (?,?,?,?)", (key, status, body, time.time())
            )

    # -- retention ---------------------------------------------------------

    def prune(self, older_than_days: float) -> dict[str, int]:
        """Drop cached responses and evidence older than the cut-off, then orphan nodes."""
        cutoff = time.time() - older_than_days * 86400
        with self.transaction() as db:
            cache = db.execute("DELETE FROM cache WHERE fetched_at < ?", (cutoff,)).rowcount
            ev = db.execute("DELETE FROM evidence WHERE observed_at < ?", (cutoff,)).rowcount
            edges = db.execute("DELETE FROM edges WHERE last_seen < ?", (cutoff,)).rowcount
            nodes = db.execute(
                "DELETE FROM nodes WHERE last_seen < ?"
                " AND key NOT IN (SELECT node FROM evidence)"
                " AND key NOT IN (SELECT src FROM edges)"
                " AND key NOT IN (SELECT dst FROM edges)",
                (cutoff,),
            ).rowcount
        with self._lock:
            self._db.execute("PRAGMA optimize")
        return {"cache": cache, "evidence": ev, "edges": edges, "nodes": nodes}


def _node_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["attrs"] = json.loads(d["attrs"])
    return d
