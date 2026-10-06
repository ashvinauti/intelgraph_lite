"""Investigation engine: bounded breadth-first pivoting.

    seeds -> [lookup every (indicator, source) pair in parallel]
          -> persist evidence + relations
          -> next frontier = pivotable neighbours not yet visited
          -> ... until depth, budget or deadline is reached
          -> rescore everything touched

Three hard limits keep cost predictable no matter what the sources return:

* ``depth``    - how many hops from the seeds to expand,
* ``budget``   - how many indicators may be looked up in total,
* ``deadline`` - wall-clock seconds; outstanding lookups are abandoned and the
                 report is marked ``partial``.

Lookups run in a thread pool (they are I/O bound); all database writes happen
on the calling thread.
"""

from __future__ import annotations

import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any

from . import scoring
from .config import Config
from .extract import derive, extract, is_public
from .fetch import Fetcher
from .model import Assessment, Indicator, Kind, Relation, Verdict
from .netwatch import NetWatch
from .sources import Context, Source, build
from .store import Store
from .trace import Tracer

# Kinds that are context, never looked up.
_PASSIVE = frozenset({Kind.ORG, Kind.TAG, Kind.REPORT, Kind.PROCESS, Kind.HOST})


@dataclass
class Report:
    seeds: list[str]
    assessments: dict[str, dict[str, Any]] = field(default_factory=dict)
    looked_up: int = 0
    lookups: int = 0
    network_calls: int = 0
    errors: list[str] = field(default_factory=list)
    partial: bool = False
    elapsed: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "seeds": self.seeds,
            "assessments": self.assessments,
            "looked_up": self.looked_up,
            "lookups": self.lookups,
            "network_calls": self.network_calls,
            "errors": self.errors,
            "partial": self.partial,
            "elapsed": round(self.elapsed, 2),
        }


class Engine:
    def __init__(
        self,
        config: Config,
        store: Store | None = None,
        sources: list[Source] | None = None,
        fetcher: Fetcher | None = None,
    ) -> None:
        self.config = config
        self.store = store or Store(config.db_path)
        self.sources = build(config) if sources is None else sources
        limits: dict[str, float] = {}
        for src in self.sources:
            limits.update(src.rate_limits)
        self.fetcher = fetcher or Fetcher(
            self.store, timeout=config.timeout, offline=config.offline, min_interval=limits
        )
        self.ctx = Context(self.fetcher, config)
        self._netwatch: NetWatch | None = None
        self._tracer: Tracer | None = None
        self._desk: Any = None
        self._triage: Any = None

    def agent_desk(self) -> Any:
        """The AI analyst's job runner, created on first use (imports nothing until then)."""
        if self._desk is None:
            from .agent import AgentDesk

            self._desk = AgentDesk(self)
        return self._desk

    def triage_worker(self) -> Any:
        """Background AI false-positive triage, created on first use."""
        if self._triage is None:
            from .triage import TriageWorker

            self._triage = TriageWorker(self)
        return self._triage

    def on_alert(self, alert_id: int) -> None:
        """Hook for live monitoring: hand new alerts to automatic triage (if enabled)."""
        if (self.config.ai_triage or "").lower() == "auto":
            self.triage_worker().on_alert(alert_id)

    def tracer(self) -> Tracer:
        """Traceroute runner, created on first use."""
        if self._tracer is None:
            self._tracer = Tracer(self)
        return self._tracer

    def watcher(self, interval: float | None = None) -> NetWatch:
        """The live network watcher, created on first use."""
        if self._netwatch is None:
            self._netwatch = NetWatch(self, interval=interval or self.config.watch_interval)
        elif interval:
            self._netwatch.interval = max(5.0, float(interval))
        return self._netwatch

    @property
    def trust(self) -> dict[str, float]:
        return {s.name: s.trust for s in self.sources}

    # -- public API --------------------------------------------------------

    def investigate(
        self,
        seeds: list[Indicator],
        *,
        depth: int | None = None,
        budget: int | None = None,
        deadline: float | None = None,
    ) -> Report:
        depth = self.config.depth if depth is None else depth
        budget = self.config.budget if budget is None else budget
        deadline = self.config.deadline if deadline is None else deadline
        started = time.monotonic()
        calls_before = self.fetcher.network_calls
        report = Report(seeds=[s.key for s in seeds])

        visited: set[str] = set()
        touched: set[str] = set()
        frontier = list(dict.fromkeys(seeds))

        # Not a ``with`` block: its exit would wait for abandoned lookups.
        pool = ThreadPoolExecutor(max_workers=max(1, self.config.workers))
        try:
            for level in range(depth + 1):
                batch = []
                for ind in frontier:
                    if ind.key in visited:
                        continue
                    if len(visited) >= budget:
                        report.partial = True
                        break
                    visited.add(ind.key)
                    batch.append(ind)
                if not batch:
                    break

                next_frontier: list[Indicator] = []
                futures: dict[Future, tuple[Indicator, Source]] = {}
                for ind in batch:
                    self.store.upsert_node(ind)
                    touched.add(ind.key)
                    for rel in derive(ind):
                        self._save_relation(rel, "derived", touched)
                        next_frontier.append(rel.dst)
                    if ind.kind in _PASSIVE:
                        continue
                    public = is_public(ind)
                    for src in self.sources:
                        if src.handles(ind) and (public or not src.remote):
                            futures[pool.submit(src.lookup, ind, self.ctx)] = (ind, src)
                report.lookups += len(futures)

                pending = set(futures)
                while pending:
                    remaining = deadline - (time.monotonic() - started)
                    if remaining <= 0:
                        report.partial = True
                        for fut in pending:
                            fut.cancel()
                        report.errors.append(f"deadline reached, {len(pending)} lookup(s) abandoned")
                        break
                    done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
                    for fut in done:
                        ind, src = futures[fut]
                        try:
                            finding = fut.result()
                        except Exception as exc:  # a broken source must not sink the run
                            report.errors.append(f"{src.name} {ind.key}: {exc}")
                            continue
                        if finding is None:
                            continue
                        self.store.replace_evidence(ind.key, src.name, finding.evidence)
                        if finding.attributes:
                            self.store.upsert_node(
                                ind, {f"{src.name}.{k}": v for k, v in finding.attributes.items()}
                            )
                        for rel in finding.relations:
                            self._save_relation(rel, src.name, touched)
                            if rel.pivot and level < depth:
                                next_frontier.append(rel.dst if rel.src == ind else rel.src)
                if report.partial and pending:
                    break
                frontier = next_frontier
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        report.looked_up = len(visited)
        assessments = self.rescore(touched)
        report.assessments = {k: assessments[k].as_dict() for k in report.seeds if k in assessments}
        report.network_calls = self.fetcher.network_calls - calls_before
        report.elapsed = time.monotonic() - started
        return report

    def ingest(self, text: str, report_name: str) -> list[Indicator]:
        """Record a report and the indicators it mentions (no lookups)."""
        indicators = extract(text)
        doc = Indicator(Kind.REPORT, report_name)
        self.store.upsert_node(doc, {"indicators": len(indicators)})
        for ind in indicators:
            self.store.upsert_node(ind)
            self.store.add_relation(Relation(doc, "mentions", ind), "ingest")
        return indicators

    def assess(self, key: str) -> Assessment:
        return self._assess(key, neighbours=self._bad_neighbours(key))

    def _assess(self, key: str, neighbours: list[tuple[str, str]] | None = None) -> Assessment:
        node = self.store.node(key)
        return scoring.assess(
            self.store.evidence(key),
            self.trust,
            neighbours or (),
            shared_infra=self.shared_infra(node) if node else None,
            feedback=self.store.feedback(key),
            half_life_days=self.config.evidence_half_life_days,
        )

    def shared_infra(self, node: dict[str, Any]) -> str | None:
        """Name of the CDN/cloud operator if this IP is shared infrastructure."""
        if node["kind"] != Kind.IP.value:
            return None
        attrs = node["attrs"]
        owners = " | ".join(
            str(attrs.get(k) or "") for k in ("shodan.org", "shodan.isp", "rdap.net_name", "rdap.net_handle")
        ).lower()
        for name in self.config.shared_infra:
            if name.lower() in owners:
                return name.title()
        tags = {str(t).lower() for k in ("internetdb.tags", "shodan.tags") for t in attrs.get(k) or []}
        return "CDN" if "cdn" in tags else None

    def set_feedback(self, key: str, verdict: str | None, note: str = "") -> Assessment:
        """Record an analyst verdict (false_positive / confirmed) or clear it (None)."""
        if self.store.node(key) is None:
            raise KeyError(key)
        if verdict is None:
            self.store.clear_feedback(key)
            self.store.set_alert_status(key, "open")
        else:
            if verdict not in ("false_positive", "confirmed"):
                raise ValueError("verdict must be false_positive or confirmed")
            flagging = [
                e.source
                for e in self.store.evidence(key)
                if e.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            ]
            self.store.set_feedback(key, verdict, note.strip()[:500], flagging)
            self.store.set_alert_status(key, verdict)
        return self.rescore({key})[key]

    def rescore(self, keys: set[str]) -> dict[str, Assessment]:
        """Rescore ``keys`` and their direct neighbours (whose association hint may change)."""
        affected = set(keys)
        for key in keys:
            for e in self.store.edges_of(key):
                affected.add(e["src"])
                affected.add(e["dst"])
        out = {}
        for key in affected:
            a = self.assess(key)
            self.store.set_assessment(key, a.score, a.verdict)
            out[key] = a
        return out

    # -- internals ---------------------------------------------------------

    def _save_relation(self, rel: Relation, source: str, touched: set[str]) -> None:
        for end in (rel.src, rel.dst):
            if end.key not in touched:
                self.store.upsert_node(end)
                touched.add(end.key)
        self.store.add_relation(rel, source)

    def _bad_neighbours(self, key: str) -> list[tuple[str, str]]:
        out = []
        for e in self.store.edges_of(key):
            if e["rel"] not in scoring.PROPAGATING:
                continue
            other = e["dst"] if e["src"] == key else e["src"]
            # Judge the neighbour on its own evidence only, to avoid loops
            # (analyst feedback and shared-infrastructure discounts included).
            direct = self._assess(other)
            if direct.verdict is Verdict.MALICIOUS:
                out.append((other, e["rel"]))
        return out
