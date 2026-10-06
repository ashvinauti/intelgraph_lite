"""AI false-positive triage and the local (Ollama) backend, with scripted models: no network."""

import json
import threading
import time
import urllib.error
import urllib.request
from types import SimpleNamespace as NS

import pytest

from iglite import config
from iglite.agent import Analyst
from iglite.api import make_server
from iglite.cli import main
from iglite.extract import classify
from iglite.llm import AgentUnavailable, ClaudeBackend, OllamaBackend, make_backend
from iglite.netwatch import Connection, NetWatch, Snapshot
from iglite.triage import TRIAGE_TOOLS, Triager, TriageWorker

# -- scripted models ---------------------------------------------------------------------


class FakeOllama:
    """Plays back /api/chat replies and serves /api/tags."""

    def __init__(self, *replies, models=("qwen2.5:7b",), up=True):
        self.replies, self.models, self.up, self.bodies = list(replies), models, up, []

    def __call__(self, method, url, body, timeout):
        if not self.up:
            raise ConnectionRefusedError("refused")
        if url.endswith("/api/tags"):
            return 200, {"models": [{"name": m} for m in self.models]}
        self.bodies.append(json.loads(json.dumps(body)))
        return 200, self.replies.pop(0)


def ollama_msg(content="", calls=()):
    return {
        "message": {
            "role": "assistant",
            "content": content,
            "tool_calls": [{"function": {"name": n, "arguments": a}} for n, a in calls] or None,
        },
        "done_reason": "stop",
        "prompt_eval_count": 900,
        "eval_count": 120,
    }


class FakeClaude:
    def __init__(self, *responses):
        self.responses, self.requests = list(responses), []
        self.beta = NS(messages=NS(create=self.create))
        self.messages = NS(create=self.create)

    def create(self, **kw):
        self.requests.append({**kw, "messages": list(kw["messages"])})  # snapshot: the list keeps growing
        return self.responses.pop(0)


def claude(stop, *blocks):
    return NS(
        stop_reason=stop,
        content=list(blocks),
        usage=NS(input_tokens=500, output_tokens=80, cache_read_input_tokens=0),
    )


def tool_use(id_, name, **inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


VERDICT = {
    "assessment": "likely_false_positive",
    "confidence": 0.82,
    "summary": "Both sightings are over a year old and the IP is Cloudflare.",
    "reasons": ["evidence is 600 days old", "shared Cloudflare IP", "browser to a CDN is normal"],
    "suggested_action": "mark_false_positive",
}


# -- fixtures --------------------------------------------------------------------------------


@pytest.fixture
def alerted(make_engine, lists, monkeypatch):
    """An engine with one live alert (#1) for 203.0.113.66 made by chrome.exe."""
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    engine.config.ai_triage = "manual"
    monkeypatch.setattr("iglite.netwatch.is_public", lambda ind: not ind.value.startswith("192.168."))
    watch = NetWatch(
        engine,
        collector=lambda: Snapshot(
            [Connection("tcp", "192.168.1.5:5000", "203.0.113.66", 443, "ESTABLISHED", 7, "chrome.exe")]
        ),
    )
    assert watch.scan()["alerts"] == 1
    return engine


# -- Ollama backend ------------------------------------------------------------------------------


def test_ollama_tool_loop_and_tool_format(alerted):
    fake = FakeOllama(
        ollama_msg("", [("get_indicator", {"indicator": "203.0.113.66"})]),
        ollama_msg(
            "",
            [
                (
                    "search_indicators",
                    json.dumps({"verdict": "malicious", "kind": "any", "text": "", "limit": 10}),
                )
            ],
        ),
        ollama_msg("ip:203.0.113.66 is flagged by two lists."),
    )
    backend = OllamaBackend(alerted.config, transport=fake)
    answer = Analyst(alerted, backend=backend).ask("is 203.0.113.66 bad?")
    assert "two lists" in answer.text and [s.tool for s in answer.steps] == [
        "get_indicator",
        "search_indicators",
    ]
    assert all(s.ok for s in answer.steps)  # arguments given as a JSON string are parsed too
    first = fake.bodies[0]
    assert first["model"] == "qwen2.5:7b" and first["stream"] is False
    assert first["messages"][0]["role"] == "system"
    assert first["tools"][0]["type"] == "function" and "parameters" in first["tools"][0]["function"]
    second = fake.bodies[1]["messages"]
    assert second[-1]["role"] == "tool" and second[-1]["tool_name"] == "get_indicator"
    assert answer.input_tokens == 2700 and backend.endpoint.startswith("Ollama at localhost:11434")


def test_ollama_setup_problems_are_explained(alerted):
    with pytest.raises(AgentUnavailable, match="isn't running"):
        OllamaBackend(alerted.config, transport=FakeOllama(up=False))
    with pytest.raises(AgentUnavailable, match="ollama pull llama3.1:8b"):
        OllamaBackend(alerted.config, model="llama3.1:8b", transport=FakeOllama())
    assert OllamaBackend(alerted.config, model="qwen2.5", transport=FakeOllama(models=("qwen2.5:latest",)))


def test_provider_settings():
    cfg = config.load(
        env={
            "IGLITE_AI_PROVIDER": "Ollama",
            "OLLAMA_HOST": "127.0.0.1:11500",
            "IGLITE_AI_MODEL": "llama3.1:8b",
            "IGLITE_AI_TRIAGE": "manual",
        }
    )
    assert (cfg.ai_provider, cfg.ollama_url, cfg.ai_model, cfg.ai_triage) == (
        "ollama",
        "127.0.0.1:11500",
        "llama3.1:8b",
        "manual",
    )
    backend = OllamaBackend(cfg, transport=FakeOllama(models=("llama3.1:8b",)))
    assert backend.url == "http://127.0.0.1:11500"
    assert isinstance(make_backend(config.Config(keys={"anthropic": "k"})), ClaudeBackend)


# -- triage ------------------------------------------------------------------------------------


def test_triage_with_claude(alerted):
    fake = FakeClaude(
        claude(
            "tool_use",
            tool_use("t1", "alert_context", alert_id=1),
            tool_use("t2", "similar_marked", indicator="ip:203.0.113.66"),
        ),
        claude("tool_use", tool_use("t3", "submit_triage", **VERDICT)),
    )
    t = Triager(alerted, backend=ClaudeBackend(alerted.config, client=fake)).run(alert_id=1)
    assert t["status"] == "done" and t["assessment"] == "likely_false_positive" and t["confidence"] == 0.82
    assert t["action"] == "mark_false_positive" and len(t["reasons"]) == 3 and t["alert_id"] == 1
    assert [s["tool"] for s in t["steps"]] == ["alert_context", "similar_marked"]
    ctx = json.loads(fake.requests[1]["messages"][-1]["content"][0]["content"])
    assert (
        ctx["alert"]["key"] == "ip:203.0.113.66" and ctx["process_alert_history"]["process"] == "chrome.exe"
    )
    assert {e["source"] for e in ctx["evidence"]} == {"bad", "other"}
    assert {t["name"] for t in fake.requests[0]["tools"]} == {t["name"] for t in TRIAGE_TOOLS}
    assert "set_feedback" not in {t["name"] for t in TRIAGE_TOOLS}  # it can't mark anything itself
    assert alerted.store.latest_triage(alert_ids=[1])[1]["id"] == t["id"]


def test_triage_with_ollama(alerted):
    fake = FakeOllama(
        ollama_msg("", [("alert_context", {"alert_id": 1})]),
        ollama_msg(
            "",
            [
                (
                    "submit_triage",
                    {
                        **VERDICT,
                        "assessment": "likely_true_positive",
                        "confidence": 1.7,
                        "suggested_action": "confirm_malicious",
                    },
                )
            ],
        ),
    )
    t = Triager(alerted, backend=OllamaBackend(alerted.config, transport=fake)).run(alert_id=1)
    assert t["assessment"] == "likely_true_positive" and t["confidence"] == 1.0  # clamped


def test_triage_degrades_to_uncertain(alerted):
    no_verdict = FakeClaude(claude("end_turn", NS(type="text", text="I think it is probably fine.")))
    t = Triager(alerted, backend=ClaudeBackend(alerted.config, client=no_verdict)).run(alert_id=1)
    assert t["assessment"] == "uncertain" and "probably fine" in t["summary"]
    bad = FakeClaude(
        claude(
            "tool_use",
            tool_use(
                "t",
                "submit_triage",
                assessment="definitely_fine",
                confidence="x",
                summary="s",
                reasons=[],
                suggested_action="delete_everything",
            ),
        )
    )
    t = Triager(alerted, backend=ClaudeBackend(alerted.config, client=bad)).run(alert_id=1)
    assert (t["assessment"], t["confidence"], t["action"]) == ("uncertain", 0.0, "investigate_further")


def test_triage_errors_are_recorded(alerted):
    broken = FakeClaude()  # no scripted reply -> IndexError inside the run
    t = Triager(alerted, backend=ClaudeBackend(alerted.config, client=broken)).run(alert_id=1)
    assert t["status"] == "error"
    with pytest.raises(KeyError):
        Triager(alerted, backend=ClaudeBackend(alerted.config, client=broken)).run(alert_id=99)


def test_similar_marked_uses_past_decisions(alerted):
    from iglite.agent import Toolbox

    alerted.store.upsert_node(classify("203.0.113.9"))
    alerted.set_feedback("ip:203.0.113.9", "false_positive", "same office range")
    related = Toolbox(alerted).run("similar_marked", {"indicator": "203.0.113.66"})["related_user_decisions"]
    assert related == [
        {
            "key": "ip:203.0.113.9",
            "user_verdict": "false_positive",
            "note": "same office range",
            "why": "same /24 network",
            "sources_that_flagged_it": [],
        }
    ]


# -- automatic triage --------------------------------------------------------------------------


def _wait(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_new_alerts_are_triaged_automatically(make_engine, lists, monkeypatch):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    monkeypatch.setattr("iglite.netwatch.is_public", lambda ind: not ind.value.startswith("192.168."))
    fake = FakeClaude(claude("tool_use", tool_use("t", "submit_triage", **VERDICT)))
    engine._triage = TriageWorker(
        engine, triager_factory=lambda: Triager(engine, backend=ClaudeBackend(engine.config, client=fake))
    )
    NetWatch(
        engine,
        collector=lambda: Snapshot(
            [Connection("tcp", "192.168.1.5:5000", "203.0.113.66", 443, "ESTABLISHED", 7, "chrome.exe")]
        ),
    ).scan()
    assert _wait(lambda: engine.store.latest_triage(alert_ids=[1]).get(1, {}).get("status") == "done")
    t = engine.store.latest_triage(alert_ids=[1])[1]
    assert t["trigger"] == "auto" and t["assessment"] == "likely_false_positive"


def test_automatic_triage_respects_mode_and_hourly_cap(alerted):
    calls = []
    worker = TriageWorker(
        alerted, triager_factory=lambda: NS(run=lambda **kw: calls.append(kw), backend=None)
    )
    alerted.config.ai_triage = "manual"
    worker.on_alert(1)
    assert calls == [] and worker._queue.qsize() == 0
    alerted.config.ai_triage, alerted.config.ai_triage_per_hour = "auto", 1
    for _ in range(3):
        alerted.store.start_triage("ip:203.0.113.66", 1, "m", "auto")
    worker.on_alert(1)
    assert worker.skipped_cap == 1 and worker._queue.qsize() == 0


def test_unconfigured_ai_does_not_break_monitoring(make_engine, lists, monkeypatch):
    engine = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    monkeypatch.setattr("iglite.netwatch.is_public", lambda ind: True)

    def unavailable():
        raise AgentUnavailable("no key")

    engine._triage = TriageWorker(engine, triager_factory=unavailable)
    watch = NetWatch(
        engine, collector=lambda: Snapshot([Connection("tcp", "l", "203.0.113.66", 443, "ESTABLISHED")])
    )
    assert watch.scan()["alerts"] == 1
    assert engine.triage_worker().last_error == "no key"
    assert engine.triage_worker().status()["available"] is False


# -- API and CLI ------------------------------------------------------------------------------


def test_triage_api(alerted):
    fake = FakeClaude(claude("tool_use", tool_use("t", "submit_triage", **VERDICT)))
    alerted._triage = TriageWorker(
        alerted, triager_factory=lambda: Triager(alerted, backend=ClaudeBackend(alerted.config, client=fake))
    )
    srv = make_server(alerted, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        status = call("/api/triage/status")[1]
        assert status["available"] is True and status["mode"] == "manual"
        assert call("/api/triage", {"alert_id": 1}) == (200, {"queued": True, "alert_id": 1, "key": None})
        assert _wait(lambda: (call("/api/alerts")[1][0]["triage"] or {}).get("status") == "done")
        assert call("/api/triage/latest?alert_id=1")[1]["assessment"] == "likely_false_positive"
        assert call("/api/triage/latest?key=ip:203.0.113.66")[1]["alert_id"] == 1
        assert call("/api/triage", {"alert_id": 42})[0] == 404
        assert call("/api/triage", {})[0] == 400
        assert call("/api/triage", {"key": "ip:9.9.9.9"})[0] == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_alerts_and_triage(alerted, capsys, monkeypatch):
    fake = FakeClaude(claude("tool_use", tool_use("t", "submit_triage", **VERDICT)))
    monkeypatch.setattr("iglite.cli.Engine", lambda cfg: alerted)
    monkeypatch.setattr(alerted.store, "close", lambda: None)  # reused across two main() calls
    monkeypatch.setattr("iglite.triage.make_backend", lambda cfg: ClaudeBackend(cfg, client=fake))
    assert main(["triage", "1"]) == 0
    out = capsys.readouterr().out
    assert "LIKELY FALSE POSITIVE (82%)" in out and "suggested: mark false positive" in out
    assert main(["alerts"]) == 0
    out = capsys.readouterr().out
    assert "#1" in out and "chrome.exe:443" in out and "LIKELY FALSE POSITIVE" in out
