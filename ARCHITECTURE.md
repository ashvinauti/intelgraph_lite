# IntelGraph Lite: Architecture

IntelGraph Lite covers the same subject as IntelGraph: threat intelligence that
correlates IOCs in a knowledge graph and explains every verdict. It adds OSINT
(registration data, DNS, certificate transparency, exposed services, and
extracting indicators from public reports). It is built differently so that it
stays cheap to run and easy to maintain.

## Design goals

| Goal | How |
|------|-----|
| Low CPU / memory | The graph lives in SQLite and is traversed with indexed recursive SQL, so nothing is loaded wholesale into RAM. Lookups are I/O bound and run in a small thread pool. |
| Fast and predictable | Every investigation has three hard limits: **depth**, **budget** (max indicators) and **deadline** (seconds). Every HTTP answer is cached with a per-source TTL, so a repeated investigation makes zero network calls. |
| Sustainable | **Zero runtime dependencies.** Standard library only: `sqlite3`, `urllib`, `concurrent.futures`, `http.server`, `tomllib`. No dependency churn, nothing to patch but Python itself. About 2.3k lines of code. |
| Logical | One direction of data flow and one contract per layer (below). Sources never touch the database, and scoring is a pure function. |
| Explainable | Every score is a sum of named contributions, and each one is shown to the user. |
| Safe by default | Private IPs and internal names are never sent to third parties. The API binds to localhost and needs a token to listen publicly. API keys come from the environment only. |

## Data flow

```
                ┌──────────────────────────────────────────────────────┐
  input         │  CLI (argparse)        API + dashboard (http.server)  │
                └───────────────┬──────────────────────────┬───────────┘
                                │ indicators / report text │
                ┌───────────────▼──────────────────────────▼───────────┐
  extract       │  extract.py: refang → regex → normalise → classify   │
                │              derive (URL→host, email→domain)          │
                └───────────────┬──────────────────────────────────────┘
                                │ Indicator
                ┌───────────────▼──────────────────────────────────────┐
  engine        │  engine.py: bounded BFS                               │
                │   level 0..depth:                                     │
                │     submit (indicator × source) lookups → thread pool │
                │     persist results on the main thread                │
                │     next frontier = pivotable relations               │
                │   stop at depth | budget | deadline                   │
                └──────┬─────────────────────────────┬─────────────────┘
                       │ lookup(ind, ctx)            │ evidence, relations
  sources       ┌──────▼──────────────────┐   ┌──────▼─────────────────┐
                │ OSINT (free, keyless)   │   │ store.py (SQLite, WAL)  │
                │  dns  rdap  crtsh       │   │  nodes   edges          │
                │  internetdb             │   │  evidence  cache        │
                │ CTI (API key)           │   └──────┬─────────────────┘
                │  otx virustotal urlhaus │          │ evidence per node
                │ Lists (local / feed)    │   ┌──────▼─────────────────┐
                │  blocklists allowlists  │   │ scoring.py (pure)       │
                └──────┬──────────────────┘   │  log-odds → 0..100      │
                       │ HTTP                 │  reasons, contradiction │
                ┌──────▼──────────────────┐   └──────┬─────────────────┘
                │ fetch.py: cache + TTL,  │          │
                │ per-host rate limit,    │   ┌──────▼─────────────────┐
                │ offline mode            │   │ export.py               │
                └─────────────────────────┘   │  STIX 2.1  JSON  CSV    │
                                              └────────────────────────┘
```

## Layer contracts

| Module | Input | Output | Must not |
|--------|-------|--------|----------|
| `model.py` | none | `Indicator`, `Evidence`, `Relation`, `Finding`, `Assessment` (immutable) | contain logic |
| `extract.py` | text / raw value | `Indicator`s, derived `Relation`s | do I/O |
| `sources/*` | `Indicator`, `Context` | `Finding` or `None` | write to the store |
| `fetch.py` | URL, TTL | `(status, body)` from cache or network | cache transient errors (429/5xx) |
| `store.py` | model objects | rows | know about sources or scoring |
| `scoring.py` | evidence and trust weights | `Assessment` | do I/O |
| `engine.py` | seeds and limits | `Report` | parse source responses |
| `cli.py`, `api.py` | user requests | engine and store calls | contain business logic |

## Scoring

```
z     = -2.0                                            (prior: unknown)
      + Σ per source: trust × confidence × sign × 3     (strongest item per source only)
      + 1.0 if a direct neighbour is malicious          (once, via resolves_to / hosted_on / serves)
score = 100 / (1 + e^-z)

malicious ≥ 70 · suspicious ≥ 30 · else benign (if any benign evidence) or unknown
contradiction = a trusted source says malicious AND a trusted source says benign
```

* **Corroboration is required for "malicious".** One trusted source alone
  gives "suspicious", and two independent ones give "malicious". A single
  feed can't stack votes, because only its strongest item counts.
* **Guilt by association is a hint, not a conviction.** A malicious neighbour
  adds +1.0 once. That's not enough on its own to reach "suspicious". The
  neighbour is judged on its *own* evidence only, so scores can't feed back in
  loops.
* **Allowlists fight false positives.** They add strong benign evidence, and
  any disagreement is flagged instead of averaged away.
* Trust weights are in `iglite.toml`. Rescoring is cheap, so tuning is safe.

## Storage

```sql
nodes    (key PK, kind, value, attrs JSON, score, verdict, first_seen, last_seen)
edges    (src, dst, rel, source, first_seen, last_seen)   PK(src,dst,rel), INDEX(dst)
evidence (node, source, verdict, confidence, detail, url, observed_at)  INDEX(node,source)
cache    (key PK, status, body, fetched_at)
```

* A node key is `kind:value`, e.g. `ip:45.155.205.20`. It is human readable,
  and the same value from different sources collapses into one node.
* Re-running a source **replaces** its evidence for that node. Results never
  duplicate, and a delisted indicator loses its old evidence.
* `iglite prune --days N` enforces retention (cache, evidence, edges and
  orphaned nodes).
* The schema version is stored in `meta`. A newer database is refused rather
  than corrupted.

## Measured cost

From a benchmark on the CI container, with 100k indicators and 300k relations:

| Operation | Cost |
|-----------|------|
| Database size | 61 MB |
| 2-hop neighbourhood (~40 nodes) | ~1 ms |
| Rescore 50 seeds and their neighbours (~330 nodes) | ~60 ms |
| Peak memory of the process | ~94 MB |
| Repeat investigation (cached) | 0 network calls |
| Full test suite (39 tests, offline) | ~3 s |

## Compared with [IntelGraph](https://github.com/Berkayy123-h/intelgraph)

| | IntelGraph | IntelGraph Lite |
|---|---|---|
| Code size | ~43k lines, 285 modules | ~2.3k lines, 17 modules |
| Runtime dependencies | 15 (FastAPI, uvicorn, strawberry, stix2, pydantic, …) | 0 |
| Graph | In-memory adjacency list, loaded from storage | SQLite tables and recursive SQL |
| Concurrency | Async framework | Thread pool for I/O, single DB writer |
| Cost control | Per-feature | Global depth / budget / deadline, and a response cache |
| OSINT | Entity types | RDAP, DNS, crt.sh, InternetDB, report ingestion |
| Explainability | Evidence chains | A contribution per source in every score |
| Out of scope | | Multi-tenancy, RBAC, GraphQL, NLP, ML prediction, notifications |

The out-of-scope items are deliberate. Each one is a separate service you can
put in front of the JSON API if you need it, rather than weight every install
has to carry.

## Extending

**Add a source.** Subclass `Source`, set `name`, `kinds`, `trust` and `ttl`,
implement `lookup()`, and append the class to `BUILTIN` in
`sources/__init__.py`. Use `ctx.fetcher.json(...)` for HTTP, which gives you
caching and rate limiting for free. Test it with the `FakeTransport` fixture.

**Add a feed.** No code needed. Add a line under `[blocklists]` in
`iglite.toml`.

**Scale up.** The store is one small class. Moving to PostgreSQL means
implementing the same methods: the recursive query is standard SQL.
