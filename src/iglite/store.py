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

SCHEMA_VERSION = 5

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
    observed_at REAL NOT NULL,
    last_seen   REAL
);
CREATE INDEX IF NOT EXISTS evidence_node ON evidence(node, source);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    at          REAL NOT NULL,
    key         TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       INTEGER NOT NULL,
    context     TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'open'
);

-- Analyst verdicts that override the computed one ("false_positive" / "confirmed").
-- `sources` records which sources were flagging it when marked, for per-source FP stats.
CREATE TABLE IF NOT EXISTS feedback (
    key         TEXT PRIMARY KEY,
    verdict     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    sources     TEXT NOT NULL DEFAULT '[]',
    at          REAL NOT NULL
);

-- AI false-positive triage results (one row per run; the newest per alert wins).
CREATE TABLE IF NOT EXISTS triage (
    id          INTEGER PRIMARY KEY,
    alert_id    INTEGER,
    key         TEXT NOT NULL,
    status      TEXT NOT NULL,              -- running | done | error
    assessment  TEXT,                        -- likely_false_positive | likely_true_positive | uncertain
    confidence  REAL,
    summary     TEXT,
    reasons     TEXT NOT NULL DEFAULT '[]',
    action      TEXT,
    model       TEXT,
    steps       TEXT NOT NULL DEFAULT '[]',
    error       TEXT,
    trigger     TEXT NOT NULL DEFAULT 'manual',
    at          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS triage_alert ON triage(alert_id);
CREATE INDEX IF NOT EXISTS triage_key ON triage(key);

-- Alert suppression rules: never alert for this indicator / process.
CREATE TABLE IF NOT EXISTS suppressions (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    at          REAL NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS routes (
    id          INTEGER PRIMARY KEY,
    at          REAL NOT NULL,
    target      TEXT NOT NULL,
    ip          TEXT NOT NULL,
    hops        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cache (
    key         TEXT PRIMARY KEY,
    status      INTEGER NOT NULL,
    body        BLOB NOT NULL,
    fetched_at  REAL NOT NULL
);
"""


class Store:
    # (table, column, declaration) added after v1; applied to older databases on open.
    _ADDED_COLUMNS = (
        ("evidence", "last_seen", "REAL"),
        ("alerts", "status", "TEXT NOT NULL DEFAULT 'open'"),
    )

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
            else:
                # Migrations are additive: new tables come from CREATE ... IF NOT
                # EXISTS above, new columns are added here, then the version is bumped.
                for table, column, decl in self._ADDED_COLUMNS:
                    cols = {r[1] for r in self._db.execute(f"PRAGMA table_info({table})")}
                    if column not in cols:
                        self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
                self._db.execute("UPDATE meta SET v=? WHERE k='schema_version'", (str(SCHEMA_VERSION),))

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
            "alerts": count("SELECT COUNT(*) FROM alerts"),
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
                "INSERT INTO evidence (node, source, verdict, confidence, detail, url, observed_at, last_seen)"
                " VALUES (?,?,?,?,?,?,?,?)",
                [
                    (key, source, e.verdict.value, e.confidence, e.detail, e.url, now, e.last_seen)
                    for e in items
                ],
            )

    def evidence(self, key: str) -> list[Evidence]:
        rows = self._query(
            "SELECT source, verdict, confidence, detail, url, last_seen FROM evidence WHERE node=? ORDER BY id",
            (key,),
        )
        return [
            Evidence(
                r["source"], Verdict(r["verdict"]), r["detail"], r["confidence"], r["url"], r["last_seen"]
            )
            for r in rows
        ]

    # -- analyst feedback --------------------------------------------------

    def set_feedback(self, key: str, verdict: str, note: str, sources: list[str]) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO feedback (key, verdict, note, sources, at) VALUES (?,?,?,?,?)",
                (key, verdict, note, json.dumps(sorted(set(sources))), time.time()),
            )

    def clear_feedback(self, key: str) -> bool:
        with self._lock:
            return self._db.execute("DELETE FROM feedback WHERE key=?", (key,)).rowcount > 0

    def feedback(self, key: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM feedback WHERE key=?", (key,))
        return {**dict(rows[0]), "sources": json.loads(rows[0]["sources"])} if rows else None

    def all_feedback(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._query("SELECT * FROM feedback ORDER BY at DESC LIMIT ?", (limit,))
        return [{**dict(r), "sources": json.loads(r["sources"])} for r in rows]

    def source_feedback_stats(self) -> dict[str, dict[str, int]]:
        """Per source: how often its flags were confirmed vs. marked false positive."""
        stats: dict[str, dict[str, int]] = {}
        for row in self._query("SELECT verdict, sources FROM feedback"):
            field = "false_positives" if row["verdict"] == "false_positive" else "confirmed"
            for src in json.loads(row["sources"]):
                stats.setdefault(src, {"false_positives": 0, "confirmed": 0})[field] += 1
        return stats

    # -- AI triage -------------------------------------------------------------

    _TRIAGE_JSON = ("reasons", "steps")

    def start_triage(self, key: str, alert_id: int | None, model: str, trigger: str) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO triage (alert_id, key, status, model, trigger, at) VALUES (?,?,?,?,?,?)",
                (alert_id, key, "running", model, trigger, time.time()),
            )
            return int(cur.lastrowid or 0)

    def finish_triage(self, triage_id: int, **fields: Any) -> None:
        allowed = {
            "status",
            "assessment",
            "confidence",
            "summary",
            "reasons",
            "action",
            "steps",
            "error",
            "model",
        }
        cols = {
            k: (json.dumps(v) if k in self._TRIAGE_JSON else v) for k, v in fields.items() if k in allowed
        }
        if not cols:
            return
        sets = ", ".join(f"{k}=?" for k in cols)  # keys come from the allow-list above
        with self._lock:
            self._db.execute(f"UPDATE triage SET {sets} WHERE id=?", (*cols.values(), triage_id))  # noqa: S608

    def _triage_row(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        for k in self._TRIAGE_JSON:
            d[k] = json.loads(d[k] or "[]")
        return d

    def triage(self, triage_id: int) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM triage WHERE id=?", (triage_id,))
        return self._triage_row(rows[0]) if rows else None

    def latest_triage(
        self, *, key: str | None = None, alert_ids: Iterable[int] = ()
    ) -> dict[Any, dict[str, Any]]:
        """Newest triage per alert id (or for one key, under that key)."""
        if key is not None:
            rows = self._query("SELECT * FROM triage WHERE key=? ORDER BY id DESC LIMIT 1", (key,))
            return {key: self._triage_row(rows[0])} if rows else {}
        ids = [int(i) for i in alert_ids]
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        rows = self._query(f"SELECT * FROM triage WHERE alert_id IN ({marks}) ORDER BY id", ids)  # noqa: S608
        return {r["alert_id"]: self._triage_row(r) for r in rows}  # later rows overwrite earlier

    def triage_runs_since(self, since: float, trigger: str = "auto") -> int:
        return int(
            self._query("SELECT COUNT(*) FROM triage WHERE at >= ? AND trigger=?", (since, trigger))[0][0]
        )

    # -- suppression rules ---------------------------------------------------

    def add_suppression(self, kind: str, value: str, note: str = "") -> int:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO suppressions (kind, value, note, at) VALUES (?,?,?,?)",
                (kind, value, note, time.time()),
            )
            row = self._db.execute(
                "SELECT id FROM suppressions WHERE kind=? AND value=?", (kind, value)
            ).fetchone()
            return int(row[0])

    def remove_suppression(self, rule_id: int) -> bool:
        with self._lock:
            return self._db.execute("DELETE FROM suppressions WHERE id=?", (rule_id,)).rowcount > 0

    def suppressions(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._query("SELECT * FROM suppressions ORDER BY kind, value")]

    # -- alerts ------------------------------------------------------------

    def add_alert(self, key: str, verdict: str, score: int, context: str = "{}") -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO alerts (at, key, verdict, score, context) VALUES (?,?,?,?,?)",
                (time.time(), key, verdict, score, context),
            )
            return int(cur.lastrowid or 0)

    def recent_alert_verdicts(self, since: float) -> dict[str, tuple[str, float]]:
        """Latest alert per indicator since ``since``: key -> (verdict, at)."""
        rows = self._query(
            "SELECT key, verdict, MAX(at) AS at FROM alerts WHERE at >= ? GROUP BY key", (since,)
        )
        return {r["key"]: (r["verdict"], r["at"]) for r in rows}

    def set_alert_status(self, key: str, status: str) -> int:
        """Resolve every open alert for an indicator (false_positive / confirmed / open)."""
        with self._lock:
            return self._db.execute(
                "UPDATE alerts SET status=? WHERE key=? AND (status='open' OR ?='open')",
                (status, key, status),
            ).rowcount

    def alerts(self, since_id: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._query("SELECT * FROM alerts WHERE id > ? ORDER BY id DESC LIMIT ?", (since_id, limit))
        return [{**dict(r), "context": json.loads(r["context"])} for r in rows]

    # -- routes ------------------------------------------------------------

    def add_route(self, target: str, ip: str, hops: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO routes (at, target, ip, hops) VALUES (?,?,?,?)", (time.time(), target, ip, hops)
            )

    def routes(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._query("SELECT * FROM routes ORDER BY id DESC LIMIT ?", (limit,))
        return [{**dict(r), "hops": json.loads(r["hops"])} for r in rows]

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
            alerts = db.execute("DELETE FROM alerts WHERE at < ?", (cutoff,)).rowcount
            db.execute("DELETE FROM routes WHERE at < ?", (cutoff,))
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
        return {"cache": cache, "evidence": ev, "edges": edges, "nodes": nodes, "alerts": alerts}


def _node_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["attrs"] = json.loads(d["attrs"])
    return d
