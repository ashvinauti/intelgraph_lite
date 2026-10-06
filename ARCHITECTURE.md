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
| Sustainable | **Zero runtime dependencies.** Standard library only: `sqlite3`, `urllib`, `concurrent.futures`, `http.server`, `tomllib`. No dependency churn, nothing to patch but Python itself. About 4.1k lines of code; the core needs no third-party packages. |
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
                │ shodan (API key)        │
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
| `fetch.py` | URL, TTL | `(status, body)` from cache or network | cache transient errors (429/5xx) or auth failures (401/403), or put credentials in cache keys |
| `store.py` | model objects | rows | know about sources or scoring |
| `scoring.py` | evidence and trust weights | `Assessment` | do I/O |
| `engine.py` | seeds and limits | `Report` | parse source responses |
| `cli.py`, `api.py` | user requests | engine and store calls | contain business logic |

## Live network monitoring

```
netwatch.collect()            OS connection table + owning process (+ DNS cache on Windows)
   │  Snapshot(connections, dns)
NetWatch.scan()
   ├─ record  process ─connected_to→ ip,  domain ─resolves_to→ ip   (local, no lookups)
   ├─ due = public IPs not checked in the last hour, capped at 25 per scan
   ├─ engine.investigate(due, depth=0)                               (cached, rate-limited)
   └─ alert when verdict ∈ {suspicious, malicious}: once/day, or on escalation
```

The watcher runs in a daemon thread inside `iglite serve --watch` or in the
foreground with `iglite watch`. Reading the connection table instead of
sniffing packets means no capture driver, no admin rights and process
attribution for free. The cost is that very short-lived connections between
snapshots are missed.

## Traceroute

```
Tracer.start(target) ──thread──▶ tracert -d | traceroute -n | tracepath -n
                                   │  lines parsed as they arrive (dashboard polls the job)
                                   ▼
                        this computer ─next_hop→ hop1 ─next_hop→ … → target   (stored edges)
                        engine.investigate(hops, depth=0)   (private hops: local lists only)
```

At most 3 traces run at once, and each is killed after 120 s. Targets are
validated as an IP, domain or URL before they reach the command line, and they
are passed as an argument list, never through a shell.

## AI analyst (optional)

```
question ─▶ Analyst.ask ──▶ Claude (tools + system prompt cached) ──▶ tool_use?
                ▲                                                      │ yes
                └──── tool_result (JSON, ≤12k chars) ◀── Toolbox ◀─────┘ runs engine/store/watcher/tracer
                                                      no ─▶ answer (bottom line, evidence, actions)
```

`agent.py` is the only module that imports a third-party package
(`anthropic`, via the `[ai]` extra), and nothing imports `agent.py` until the
analyst is used. It runs a manual tool loop on the Messages API: strict tool
schemas, at most `ai_max_steps` turns, every tool result returned in one
message, prompt caching on the stable tools and system prefix, server-side
refusal fallback, and `stop_reason` checked before any tool runs. Tools only
call the same engine methods the CLI and API use, so the agent can't do
anything a user of the dashboard couldn't.

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
| Full test suite (71 tests, offline) | ~6 s |

## Compared with [IntelGraph](https://github.com/Berkayy123-h/intelgraph)

| | IntelGraph | IntelGraph Lite |
|---|---|---|
| Code size | ~43k lines, 285 modules | ~4.1k lines, 20 modules |
| Runtime dependencies | 15 (FastAPI, uvicorn, strawberry, stix2, pydantic, …) | 0 (1 optional: `anthropic`, for the AI analyst) |
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
