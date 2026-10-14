"""Command-line interface (argparse, no third-party dependencies)."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__, attack, config, export
from .engine import Engine
from .extract import classify, extract
from .model import KINDS, Indicator
from .sources import describe

_COLOUR = {"malicious": "\033[31m", "suspicious": "\033[33m", "benign": "\033[32m", "unknown": "\033[2m"}


def _paint(verdict: str | None, text: str) -> str:
    if not sys.stdout.isatty() or not verdict:
        return text
    return f"{_COLOUR.get(verdict, '')}{text}\033[0m"


def _parse_indicators(values: list[str]) -> list[Indicator]:
    out = []
    for v in values:
        ind = classify(v)
        if ind is None:
            raise SystemExit(f"error: cannot recognise {v!r} as an indicator")
        out.append(ind)
    return out


def _resolve_key(value: str) -> str:
    if ":" in value and value.split(":", 1)[0] in KINDS and not value.startswith(("http:", "https:", "ftp:")):
        return value
    ind = classify(value)
    if ind is None:
        raise SystemExit(f"error: cannot recognise {value!r}")
    return ind.key


def _print_assessment(key: str, a: dict[str, Any]) -> None:
    flag = "  [CONTRADICTION]" if a["contradiction"] else ""
    print(_paint(a["verdict"], f"{a['verdict'].upper():<10} {a['score']:>3}  {key}") + flag)
    for r in a["reasons"]:
        sign = "+" if r["contribution"] >= 0 else "-"
        print(f"           {sign}{abs(r['contribution']):.2f}  {r['source']:<12} {r['detail']}")


def _read_input(spec: str) -> tuple[str, str]:
    if spec == "-":
        return sys.stdin.read(), "stdin"
    if spec.startswith(("http://", "https://")):
        req = urllib.request.Request(spec, headers={"User-Agent": f"iglite/{__version__}"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - http(s) only
            return resp.read(4 * 1024 * 1024).decode("utf-8", "replace"), spec
    return Path(spec).read_text(encoding="utf-8", errors="replace"), Path(spec).name


def cmd_investigate(engine: Engine, args: argparse.Namespace) -> int:
    seeds = _parse_indicators(args.indicators)
    if args.file:
        seeds += extract(_read_input(args.file)[0])
    if not seeds:
        raise SystemExit("error: no indicators given")
    report = engine.investigate(seeds, depth=args.depth, budget=args.budget, deadline=args.deadline)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
        return 0
    for key, a in report.assessments.items():
        _print_assessment(key, a)
    note = " (partial: limit reached)" if report.partial else ""
    print(
        f"\n{report.looked_up} indicator(s), {report.lookups} lookup(s), "
        f"{report.network_calls} network call(s), {report.elapsed:.1f}s{note}"
    )
    for err in report.errors[:10]:
        print(f"  ! {err}", file=sys.stderr)
    return 0


def cmd_ingest(engine: Engine, args: argparse.Namespace) -> int:
    text, name = _read_input(args.source)
    found = engine.ingest(text, args.name or name)
    print(f"{len(found)} indicator(s) extracted from {args.name or name}")
    for ind in found:
        print(f"  {ind.key}")
    if args.investigate and found:
        report = engine.investigate(found, depth=args.depth, budget=args.budget, deadline=args.deadline)
        print()
        for key, a in sorted(report.assessments.items(), key=lambda kv: -kv[1]["score"]):
            _print_assessment(key, a)
    return 0


def cmd_show(engine: Engine, args: argparse.Namespace) -> int:
    key = _resolve_key(args.indicator)
    node = engine.store.node(key)
    if node is None:
        raise SystemExit(f"{key} is not in the database; run `iglite investigate` first")
    a = engine.assess(key).as_dict()
    if args.json:
        print(
            json.dumps(
                {"node": node, "assessment": a, "edges": engine.store.edges_of(key)}, indent=2, default=str
            )
        )
        return 0
    _print_assessment(key, a)
    for k, v in sorted(node["attrs"].items()):
        print(f"           {k} = {v}")
    for e in engine.store.edges_of(key):
        arrow = f"--{e['rel']}--> {e['dst']}" if e["src"] == key else f"<--{e['rel']}-- {e['src']}"
        print(f"           {arrow}  ({e['source']})")
    if techniques := attack.techniques_of(engine.store, key):
        print("\n           MITRE ATT&CK:")
        _print_techniques(techniques)
    return 0


def _print_techniques(techniques: list[dict[str, Any]], indent: str = "           ") -> None:
    for t in techniques:
        via = f" via {', '.join(dict.fromkeys(t['via']))}" if t.get("via") else ""
        tactics = ", ".join(t["tactics"]) or "-"
        print(f"{indent}{t['id']:<10} {t['name'][:48]:<48} [{tactics}]  {'/'.join(t['basis'])}{via}")


def cmd_attack(engine: Engine, args: argparse.Namespace) -> int:
    what = args.what
    if what == "update":
        import urllib.request

        print(f"Downloading MITRE ATT&CK Enterprise from {attack.STIX_URL} ...", flush=True)
        req = urllib.request.Request(attack.STIX_URL, headers={"User-Agent": f"iglite/{__version__}"})
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL
            data = attack.build(json.loads(resp.read()))
        path = attack.save(data)
        print(
            f"ATT&CK v{data['version']}: {len(data['techniques'])} techniques, {len(data['software'])} software, "
            f"{len(data['groups'])} groups -> {path}"
        )
        return 0
    if what == "navigator":
        layer = json.dumps(attack.navigator_layer(engine.store, associated=args.associated), indent=2)
        if args.output:
            Path(args.output).write_text(layer, encoding="utf-8")
            print(f"wrote {args.output} (open it at https://mitre-attack.github.io/attack-navigator/)")
        else:
            print(layer)
        return 0
    if args.indicator:
        key = _resolve_key(args.indicator)
        techniques = attack.techniques_of(engine.store, key, associated=args.associated)
        print(f"{key}: {len(techniques)} ATT&CK technique(s)")
        _print_techniques(techniques, "  ")
        return 0
    if what != "matrix":
        tech = attack.technique_node(what)
        if tech is None:
            raise SystemExit("usage: iglite attack [matrix | T1234[.001] | navigator | update]")
        d = attack.detail(engine.store, tech.value, associated=args.associated)
        print(f"{d['id']}  {d['name']}  [{', '.join(d['tactics']) or 'not in the catalogue'}]")
        if d.get("url"):
            print(f"  {d['url']}")
        for r in d["indicators"]:
            score = "" if r["score"] is None else r["score"]
            print(
                _paint(r["verdict"], f"  {r['verdict'] or '-':<10} {score!s:>3}  {r['key']}")
                + f"  ({', '.join(dict.fromkeys(r['basis']))})"
            )
        if not d["indicators"]:
            print("  no indicators linked yet")
        return 0
    s = attack.summary(engine.store, associated=args.associated)
    print(
        f"MITRE ATT&CK v{s['version']}: {s['techniques']} technique(s) across {s['indicators']} indicator(s)"
    )
    if not s["techniques"]:
        print("Nothing mapped yet. Techniques come from feeds (OTX), tags, ingested reports and live alerts.")
    for tactic in s["tactics"]:
        if not tactic["techniques"]:
            continue
        print(f"\n{tactic['name']} ({tactic['id']})")
        for t in tactic["techniques"]:
            mix = ", ".join(f"{n} {v}" for v, n in sorted(t["verdicts"].items()))
            line = f"  {t['id']:<10} {t['name'][:46]:<46} {t['count']:>4}  ({mix}; {'/'.join(t['basis'])})"
            print(_paint(t["top_verdict"], line))
    return 0


def cmd_list(engine: Engine, args: argparse.Namespace) -> int:
    rows = engine.store.search(verdict=args.verdict, kind=args.kind, text=args.search, limit=args.limit)
    for n in rows:
        verdict = n["verdict"] or "-"
        score = "" if n["score"] is None else n["score"]
        print(_paint(n["verdict"], f"{verdict:<10} {score!s:>3}  {n['key']}"))
    return 0


def cmd_graph(engine: Engine, args: argparse.Namespace) -> int:
    print(
        json.dumps(
            engine.store.neighbourhood(_resolve_key(args.indicator), args.depth, args.limit),
            indent=2,
            default=str,
        )
    )
    return 0


def cmd_export(engine: Engine, args: argparse.Namespace) -> int:
    verdicts = set(args.verdict) if args.verdict else None
    data = export.FORMATS[args.format](engine.store, verdicts)
    if args.output:
        Path(args.output).write_text(data, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(data)
    return 0


def cmd_sources(engine: Engine, args: argparse.Namespace) -> int:
    stats = engine.store.source_feedback_stats()
    for s in describe(engine.config):
        st = stats.get(s["name"])
        marks = f"  [{st['false_positives']} FP / {st['confirmed']} confirmed]" if st else ""
        print(f"{s['name']:<12} {s['status']:<12} trust={s['trust']:<4} {s['description']}{marks}")
    return 0


def cmd_mark(engine: Engine, args: argparse.Namespace) -> int:
    key = _resolve_key(args.indicator)
    verdict = {"fp": "false_positive", "confirm": "confirmed", "unmark": None}[args.command]
    try:
        a = engine.set_feedback(key, verdict, args.note or "")
    except KeyError:
        raise SystemExit(f"{key} is not in the database")
    _print_assessment(key, a.as_dict())
    return 0


_ASSESS = {
    "likely_false_positive": ("benign", "LIKELY FALSE POSITIVE"),
    "likely_true_positive": ("malicious", "LIKELY REAL"),
    "uncertain": ("suspicious", "UNCERTAIN"),
}


def _print_triage(t: dict[str, Any]) -> None:
    if t.get("status") == "error":
        print(f"  triage failed: {t.get('error')}")
        return
    colour, label = _ASSESS.get(t.get("assessment") or "", ("unknown", "?"))
    print(_paint(colour, f"  AI: {label} ({(t.get('confidence') or 0):.0%})") + f"  [{t.get('model')}]")
    if t.get("summary"):
        print(f"  {t['summary']}")
    for r in t.get("reasons") or []:
        print(f"   - {r}")
    print(f"  suggested: {(t.get('action') or '').replace('_', ' ')}")


def _origin(ctx: dict[str, Any]) -> str:
    """Who made the connection: a program (this computer) or a LAN device (gateway mode)."""
    if ctx.get("device"):
        name = f" ({ctx['device_name']})" if ctx.get("device_name") else ""
        arrow = " inbound" if ctx.get("inbound") else " dns query" if ctx.get("query") else ""
        return f"{ctx['device']}{name}{arrow}"
    return ctx.get("process") or "?"


def cmd_alerts(engine: Engine, args: argparse.Namespace) -> int:
    alerts = engine.store.alerts(limit=args.limit)
    triage = engine.store.latest_triage(alert_ids=[a["id"] for a in alerts])
    if not alerts:
        print("No alerts yet. Run `iglite watch` or `iglite serve --watch`.")
    for a in alerts:
        c = a["context"] or {}
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(a["at"]))
        status = "" if a["status"] == "open" else f" [{a['status'].replace('_', ' ')}]"
        print(
            _paint(a["verdict"], f"#{a['id']:<4} {when}  {a['verdict']:<10} {a['score']:>3}  {a['key']}")
            + f"  <- {_origin(c)}:{c.get('remote_port')}{status}"
        )
        if t := triage.get(a["id"]):
            _print_triage(t)
    return 0


def cmd_triage(engine: Engine, args: argparse.Namespace) -> int:
    from .llm import AgentUnavailable
    from .triage import Triager

    targets: list[tuple[int | None, str | None]] = [(i, None) for i in args.alert]
    if args.indicator:
        targets.append((None, _resolve_key(args.indicator)))
    if args.open:
        targets += [(a["id"], None) for a in engine.store.alerts(limit=200) if a["status"] == "open"]
    if not targets:
        raise SystemExit("usage: iglite triage ALERT_ID... | --indicator X | --open")
    try:
        triager = Triager(engine)
    except AgentUnavailable as exc:
        raise SystemExit(f"error: {exc}")
    print(f"Triage agent: {triager.backend.model} via {triager.backend.endpoint}\n")
    for alert_id, key in targets:
        label = f"alert #{alert_id}" if alert_id is not None else key
        print(f"{label}: investigating...", flush=True)
        try:
            _print_triage(triager.run(alert_id=alert_id, key=key, trigger="manual"))
        except KeyError as exc:
            print(f"  not found: {exc}")
        print()
    return 0


def cmd_feedback(engine: Engine, args: argparse.Namespace) -> int:
    rows = engine.store.all_feedback()
    if not rows:
        print("No indicators marked yet. Use `iglite fp <indicator>` or `iglite confirm <indicator>`.")
    for r in rows:
        label = "FALSE POS" if r["verdict"] == "false_positive" else "CONFIRMED"
        note = f"  ({r['note']})" if r["note"] else ""
        print(f"{label:<10} {r['key']}{note}   flagged by: {', '.join(r['sources']) or '-'}")
    stats = engine.store.source_feedback_stats()
    if stats:
        print("\nPer source (how often its flags turned out wrong):")
        for name, st in sorted(stats.items(), key=lambda kv: -kv[1]["false_positives"]):
            total = st["false_positives"] + st["confirmed"]
            rate = st["false_positives"] / total
            hint = "  -> consider lowering its trust in iglite.toml" if total >= 3 and rate > 0.5 else ""
            print(
                f"  {name:<14} {st['false_positives']} false positive(s), {st['confirmed']} confirmed ({rate:.0%} FP){hint}"
            )
    return 0


def cmd_suppress(engine: Engine, args: argparse.Namespace) -> int:
    if args.action == "list":
        rules = engine.store.suppressions()
        for r in rules:
            print(f"#{r['id']:<4} {r['kind']:<10} {r['value']}" + (f"  ({r['note']})" if r["note"] else ""))
        if not rules:
            print("No suppression rules.")
        return 0
    if args.action == "remove":
        if not args.value or not args.value.isdigit():
            raise SystemExit("usage: iglite suppress remove <rule id>")
        print("removed" if engine.store.remove_suppression(int(args.value)) else "no such rule")
        return 0
    if not args.value:
        raise SystemExit(f"usage: iglite suppress {args.action} <value>")
    if args.action == "indicator":
        value = _resolve_key(args.value)
    elif args.action == "device":
        ind = classify(args.value)
        if ind is None or ind.kind.value != "ip":
            raise SystemExit("error: a device is its LAN IP address, e.g. 192.168.1.23")
        value = ind.value
    else:
        value = args.value.lower()
    rule = engine.store.add_suppression(args.action, value, args.note or "")
    print(f"#{rule}: no alerts for {args.action} {value}")
    return 0


def cmd_stats(engine: Engine, args: argparse.Namespace) -> int:
    print(json.dumps(engine.store.stats(), indent=2))
    return 0


def cmd_prune(engine: Engine, args: argparse.Namespace) -> int:
    print(json.dumps(engine.store.prune(args.days), indent=2))
    return 0


def _apply_gateway(engine: Engine, args: argparse.Namespace) -> None:
    cfg = engine.config
    if args.syslog:
        cfg.gateway_syslog = args.syslog
    if args.netflow:
        cfg.gateway_netflow = args.netflow
    if args.conntrack:
        cfg.gateway_conntrack = True
    if args.ssh:
        cfg.gateway_ssh = args.ssh
    if args.ssh_port:
        cfg.gateway_ssh_port = args.ssh_port
    if args.ssh_key:
        cfg.gateway_ssh_key = args.ssh_key
    cfg.gateway_files = [*cfg.gateway_files, *(args.tail or [])]
    cfg.gateway_leases = [*cfg.gateway_leases, *(args.leases or [])]
    cfg.lan_networks = [*cfg.lan_networks, *(args.lan or [])]
    if args.include_blocked:
        cfg.gateway_include_blocked = True
    if args.max_new:
        cfg.watch_max_new = args.max_new
    if cfg.gateway:
        try:
            watch = engine.watcher(args.interval)
        except OSError as exc:  # port in use, or < 1024 without privileges
            raise SystemExit(f"error: cannot open a gateway listener: {exc}")
        except ValueError as exc:  # a malformed --ssh target
            raise SystemExit(f"error: {exc}")
        inputs = ", ".join(watch.gateway.inputs) if watch.gateway else ""
        print(f"Gateway mode: monitoring the network behind this router/firewall via {inputs}")


def cmd_serve(engine: Engine, args: argparse.Namespace) -> int:
    from .api import serve

    _apply_gateway(engine, args)
    if args.watch or engine.config.gateway:
        engine.watcher(args.interval).start()
        print(f"Watching live connections every {engine.watcher().interval:.0f}s")
    serve(engine, args.host, args.port)
    return 0


def _print_connections(rows: list[dict[str, Any]], show_all: bool) -> None:
    shown = [r for r in rows if show_all or r["verdict"] not in ("private",)]
    who = "DEVICE" if any(r.get("device") for r in rows) else "PROCESS"
    print(f"{'VERDICT':<11}{'SCORE':>5}  {who:<22}{'REMOTE':<42}{'CONN':>4}  NAMES")
    for r in shown:
        remote = f"{r['remote_ip']}:{r['remote_port']}" + (" (in)" if r.get("inbound") else "")
        if r.get("device"):
            proc = f"{r['device']} {r['device_name']}" if r.get("device_name") else r["device"]
        else:
            proc = f"{r['process'] or '?'} ({r['pid']})" if r["pid"] else (r["process"] or "?")
        score = "" if r["score"] is None else r["score"]
        line = f"{r['verdict']:<11}{score!s:>5}  {proc[:21]:<22}{remote[:41]:<42}{r['count']:>4}  {', '.join(r['names'])}"
        print(_paint(r["verdict"], line))


def cmd_blocklist(engine: Engine, args: argparse.Namespace) -> int:
    text = export.blocklist(
        engine.store,
        args.kind,
        suspicious=args.suspicious,
        min_score=args.min_score,
        shared_infra=engine.shared_infra,
        comments=args.comments,
    )
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {len(text.splitlines())} {args.kind}(s) to {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def cfg_listens(engine: Engine) -> bool:
    cfg = engine.config
    return bool(cfg.gateway_syslog or cfg.gateway_netflow or cfg.gateway_files or cfg.gateway_ssh)


def cmd_watch(engine: Engine, args: argparse.Namespace) -> int:
    import time

    _apply_gateway(engine, args)
    watch = engine.watcher(args.interval)
    since = max((a["id"] for a in engine.store.alerts(limit=1)), default=0)
    if not args.once:
        print(f"Watching live connections every {watch.interval:.0f}s. Ctrl+C to stop.\n")
    elif cfg_listens(engine):  # syslog/NetFlow/log events arrive over time: listen for one interval
        print(f"Listening for {min(watch.interval, 30):.0f}s...", flush=True)
        time.sleep(min(watch.interval, 30))
    while True:
        result = watch.scan()
        if args.once:
            _print_connections(watch.rows, args.all)
            print(
                f"\n{result['connections']} connection(s), {result['public_ips']} public IP(s), "
                f"{result['domains']} queried domain(s), {result['investigated']} looked up"
            )
            if watch.gateway is not None:
                print(json.dumps(watch.gateway.status(), indent=2))
            return 0
        for alert in reversed(engine.store.alerts(since)):
            since = max(since, alert["id"])
            ctx = alert["context"]
            names = f" ({', '.join(ctx.get('names') or [])})" if ctx.get("names") else ""
            print(
                _paint(
                    alert["verdict"],
                    f"ALERT {alert['verdict'].upper()} {alert['score']:>3}  "
                    f"{alert['key']}:{ctx.get('remote_port')}{names}  <- {_origin(ctx)}",
                )
            )
        stamp = time.strftime("%H:%M:%S")
        extra = f", {result['domains']} domains" if result["domains"] else ""
        print(
            f"[{stamp}] {result['connections']} connections, {result['public_ips']} public IPs{extra}, "
            f"{result['investigated']} looked up, {watch.status()['flagged']} flagged",
            flush=True,
        )
        time.sleep(watch.interval)


def cmd_trace(engine: Engine, args: argparse.Namespace) -> int:
    from .trace import TraceUnavailable

    tracer = engine.tracer()
    try:
        _, ip = tracer.resolve(args.target)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")
    print(f"Tracing route to {args.target} [{ip}], max {args.max_hops} hops\n")

    def show(hop) -> None:
        rtt = f"{hop.rtt:7.1f} ms" if hop.rtt is not None else "      *   "
        print(f"{hop.n:>3}  {rtt}  {hop.ip or 'no reply'}", flush=True)

    try:
        job = tracer.run(args.target, args.max_hops, on_hop=show)
    except TraceUnavailable as exc:
        raise SystemExit(f"error: {exc}")
    if job.status == "error":
        raise SystemExit(f"error: {job.error}")
    print("\nHops looked up against your sources:")
    for h in tracer.describe(job)["hops"]:
        if h["ip"]:
            where = " ".join(x for x in (h["org"], h["country"]) if x) or (
                "private network" if h["private"] else ""
            )
            score = "" if h["score"] is None else h["score"]
            print(
                _paint(
                    h["verdict"],
                    f"{h['n']:>3}  {h['verdict'] or '-':<10} {score!s:>3}  {h['ip']:<40} {where}",
                )
            )
    return 0


def _analyst(engine: Engine, args: argparse.Namespace):
    from .agent import AgentUnavailable, Analyst

    try:
        return Analyst(engine, model=args.model, effort=args.effort)
    except AgentUnavailable as exc:
        raise SystemExit(f"error: {exc}")


def _answer(analyst, question: str, history: list) -> None:
    from .agent import AgentUnavailable

    def step(s) -> None:
        mark = "ok" if s.ok else "failed"
        detail = json.dumps(s.input)[:80]
        print(f"  \u2192 {s.tool} {detail}  [{mark}: {s.summary}]", file=sys.stderr, flush=True)

    snapshot = len(history)
    try:
        a = analyst.ask(question, history, on_step=step)
    except AgentUnavailable as exc:
        del history[snapshot:]
        print(f"error: {exc}", file=sys.stderr)
        return
    print("\n" + a.text + "\n")
    print(
        f"[{a.model} \u00b7 {len(a.steps)} tool call(s) \u00b7 {a.input_tokens:,} in / "
        f"{a.output_tokens:,} out tokens, {a.cache_read_tokens:,} from cache]",
        file=sys.stderr,
    )


def cmd_ask(engine: Engine, args: argparse.Namespace) -> int:
    question = " ".join(args.question)
    if args.file:
        question += "\n\n" + _read_input(args.file)[0][:100_000]
    _answer(_analyst(engine, args), question, [])
    return 0


def cmd_chat(engine: Engine, args: argparse.Namespace) -> int:
    analyst = _analyst(engine, args)
    history: list = []
    print(
        f"IntelGraph Lite analyst ({analyst.model}). Ask anything; 'reset' clears the conversation, "
        "'exit' quits.\n"
    )
    while True:
        try:
            question = input("you> ").strip()
        except EOFError:
            return 0
        if question.lower() in ("exit", "quit"):
            return 0
        if question.lower() == "reset":
            history.clear()
            print("(conversation cleared)")
            continue
        if question:
            _answer(analyst, question, history)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iglite", description="Lightweight threat intelligence + OSINT correlation"
    )
    p.add_argument("--version", action="version", version=f"iglite {__version__}")
    p.add_argument("-c", "--config", help="path to iglite.toml")
    p.add_argument("--db", help="database path (default ~/.iglite/iglite.db)")
    p.add_argument("--offline", action="store_true", help="use only cache and local lists")
    sub = p.add_subparsers(dest="command", required=True)

    def limits(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--depth", type=int, help="pivot hops from the seeds")
        sp.add_argument("--budget", type=int, help="max indicators to look up")
        sp.add_argument("--deadline", type=float, help="wall-clock seconds")

    sp = sub.add_parser("investigate", aliases=["inv"], help="look up and correlate indicators")
    sp.add_argument("indicators", nargs="*")
    sp.add_argument("-f", "--file", help="also extract indicators from a file, URL or '-'")
    sp.add_argument("--json", action="store_true")
    limits(sp)
    sp.set_defaults(func=cmd_investigate)

    sp = sub.add_parser("ingest", help="extract indicators from a report (file, URL or '-')")
    sp.add_argument("source")
    sp.add_argument("--name", help="report name to record")
    sp.add_argument("-i", "--investigate", action="store_true", help="also look them up")
    limits(sp)
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("show", help="explain one indicator")
    sp.add_argument("indicator")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("list", help="list stored indicators")
    sp.add_argument("--verdict", choices=["malicious", "suspicious", "benign", "unknown"])
    sp.add_argument("--kind")
    sp.add_argument("--search")
    sp.add_argument("--limit", type=int, default=50)
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("graph", help="print an indicator's neighbourhood as JSON")
    sp.add_argument("indicator")
    sp.add_argument("--depth", type=int, default=2)
    sp.add_argument("--limit", type=int, default=200)
    sp.set_defaults(func=cmd_graph)

    sp = sub.add_parser("export", help="export as json, csv or STIX 2.1")
    sp.add_argument("format", choices=sorted(export.FORMATS))
    sp.add_argument("-o", "--output")
    sp.add_argument("--verdict", action="append", choices=["malicious", "suspicious", "benign", "unknown"])
    sp.set_defaults(func=cmd_export)

    sub.add_parser("sources", help="show sources and whether they are enabled").set_defaults(func=cmd_sources)

    sp = sub.add_parser("attack", help="MITRE ATT&CK techniques seen in your data")
    sp.add_argument(
        "what",
        nargs="?",
        default="matrix",
        help="matrix (default), a technique ID such as T1071.001, navigator (layer JSON), or update",
    )
    sp.add_argument("--indicator", help="techniques linked to one indicator")
    sp.add_argument(
        "--associated", action="store_true", help="include known techniques of linked malware and groups"
    )
    sp.add_argument("-o", "--output", help="with navigator: write the layer to this file")
    sp.set_defaults(func=cmd_attack)

    for name, text in (
        ("fp", "mark an indicator as a false positive"),
        ("confirm", "confirm an indicator is malicious"),
        ("unmark", "remove your mark from an indicator"),
    ):
        sp = sub.add_parser(name, help=text)
        sp.add_argument("indicator")
        sp.add_argument("--note", help="why (shown in the evidence)")
        sp.set_defaults(func=cmd_mark)

    sub.add_parser("feedback", help="list your marks and per-source false-positive rates").set_defaults(
        func=cmd_feedback
    )

    sp = sub.add_parser("alerts", help="list recent alerts with their AI triage")
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(func=cmd_alerts)

    sp = sub.add_parser("triage", help="AI false-positive triage of alerts or an indicator")
    sp.add_argument("alert", nargs="*", type=int, help="alert id(s), see `iglite alerts`")
    sp.add_argument("--indicator", help="triage an indicator that has no alert")
    sp.add_argument("--open", action="store_true", help="triage every open alert")
    sp.set_defaults(func=cmd_triage)

    sp = sub.add_parser("suppress", help="alert suppression rules")
    sp.add_argument(
        "action",
        choices=["process", "indicator", "device", "list", "remove"],
        help="add a rule for a process, indicator or LAN device, list rules, or remove one by id",
    )
    sp.add_argument("value", nargs="?")
    sp.add_argument("--note")
    sp.set_defaults(func=cmd_suppress)
    sub.add_parser("stats", help="database statistics").set_defaults(func=cmd_stats)

    sp = sub.add_parser("prune", help="delete data older than N days")
    sp.add_argument("--days", type=float, default=90)
    sp.set_defaults(func=cmd_prune)

    def gateway(sp: argparse.ArgumentParser) -> None:
        g = sp.add_argument_group(
            "gateway mode", "monitor every device behind a router/firewall instead of this computer"
        )
        g.add_argument(
            "--syslog", metavar="[HOST:]PORT", help="receive router/firewall syslog (UDP), e.g. 5514"
        )
        g.add_argument(
            "--netflow", metavar="[HOST:]PORT", help="receive NetFlow v5/v9/IPFIX (UDP), e.g. 2055"
        )
        g.add_argument("--conntrack", action="store_true", help="read the NAT table (run on the gateway)")
        g.add_argument(
            "--ssh", metavar="USER@ROUTER", help="read the router over SSH (key login), e.g. root@192.168.1.1"
        )
        g.add_argument("--ssh-port", type=int, help="SSH port on the router (default 22)")
        g.add_argument(
            "--ssh-key", metavar="FILE", help="private key for the router (default: ssh agent / ~/.ssh)"
        )
        g.add_argument(
            "--tail", action="append", metavar="FILE", help="tail Zeek, Suricata eve.json or syslog files"
        )
        g.add_argument("--leases", action="append", metavar="FILE", help="DHCP leases file for device names")
        g.add_argument(
            "--lan", action="append", metavar="CIDR", help="inside networks (default: private ranges)"
        )
        g.add_argument("--include-blocked", action="store_true", help="also check flows the firewall blocked")
        g.add_argument("--max-new", type=int, help="new IPs/domains looked up per snapshot (default 25)")

    sp = sub.add_parser("serve", help="run the JSON API and dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8765)
    sp.add_argument("--watch", action="store_true", help="also monitor live network connections")
    sp.add_argument("--interval", type=float, help="seconds between network snapshots (default 30)")
    gateway(sp)
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser(
        "blocklist", help="malicious IPs/domains/URLs as a feed for your firewall or DNS filter"
    )
    sp.add_argument("kind", choices=export.BLOCKLIST_KINDS)
    sp.add_argument("--suspicious", action="store_true", help="include suspicious, not just malicious")
    sp.add_argument("--min-score", type=int, default=0)
    sp.add_argument("--comments", action="store_true", help="add a '#' header line")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_blocklist)

    def ai(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--model", help="Claude model (default claude-opus-5-5)")
        sp.add_argument(
            "--effort", choices=["low", "medium", "high", "xhigh", "max"], help="reasoning effort"
        )

    sp = sub.add_parser("ask", help="ask the AI analyst a question (needs ANTHROPIC_API_KEY)")
    sp.add_argument("question", nargs="+")
    sp.add_argument("-f", "--file", help="attach a report: file, URL or '-'")
    ai(sp)
    sp.set_defaults(func=cmd_ask)

    sp = sub.add_parser("chat", help="interactive conversation with the AI analyst")
    ai(sp)
    sp.set_defaults(func=cmd_chat)

    sp = sub.add_parser("trace", help="traceroute to a target and check every hop")
    sp.add_argument("target", help="IP address, domain or URL")
    sp.add_argument("--max-hops", type=int, default=20)
    sp.set_defaults(func=cmd_trace)

    sp = sub.add_parser("watch", help="monitor live network connections (this computer, or a whole network)")
    sp.add_argument("--interval", type=float, help="seconds between snapshots (default 30, min 5)")
    sp.add_argument("--once", action="store_true", help="take one snapshot, print it and exit")
    sp.add_argument("--all", action="store_true", help="with --once, include private/local peers")
    gateway(sp)
    sp.set_defaults(func=cmd_watch)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = config.load(args.config)
    if args.db:
        cfg.db = args.db
    if args.offline:
        cfg.offline = True
    engine = Engine(cfg)
    try:
        return args.func(engine, args)
    except KeyboardInterrupt:
        return 130
    finally:
        engine.store.close()


if __name__ == "__main__":
    raise SystemExit(main())
