"""Command-line interface (argparse, no third-party dependencies)."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__, config, export
from .engine import Engine
from .extract import classify, extract
from .model import Indicator
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
    if (
        ":" in value
        and value.split(":", 1)[0]
        in {"ip", "domain", "url", "hash", "cve", "email", "asn", "org", "tag", "report"}
        and not value.startswith(("http:", "https:", "ftp:"))
    ):
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
    for s in describe(engine.config):
        print(f"{s['name']:<12} {s['status']:<12} trust={s['trust']:<4} {s['description']}")
    return 0


def cmd_stats(engine: Engine, args: argparse.Namespace) -> int:
    print(json.dumps(engine.store.stats(), indent=2))
    return 0


def cmd_prune(engine: Engine, args: argparse.Namespace) -> int:
    print(json.dumps(engine.store.prune(args.days), indent=2))
    return 0


def cmd_serve(engine: Engine, args: argparse.Namespace) -> int:
    from .api import serve

    serve(engine, args.host, args.port)
    return 0


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
    sub.add_parser("stats", help="database statistics").set_defaults(func=cmd_stats)

    sp = sub.add_parser("prune", help="delete data older than N days")
    sp.add_argument("--days", type=float, default=90)
    sp.set_defaults(func=cmd_prune)

    sp = sub.add_parser("serve", help="run the JSON API and dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8765)
    sp.set_defaults(func=cmd_serve)
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
