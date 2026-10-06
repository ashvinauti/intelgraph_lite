"""AI analyst tests with a scripted fake model: no network, no API key."""

import json
import threading
import time
import urllib.error
import urllib.request
from types import SimpleNamespace as NS

import pytest

from iglite.agent import TOOLS, AgentDesk, AgentUnavailable, Analyst, Toolbox
from iglite.api import make_server
from iglite.extract import classify


def text(t):
    return NS(type="text", text=t)


def tool(id_, name, **inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


def resp(stop, *blocks, i=100, o=50):
    return NS(
        stop_reason=stop,
        content=list(blocks),
        usage=NS(input_tokens=i, output_tokens=o, cache_read_input_tokens=0),
    )


class FakeClient:
    """Plays back scripted responses and records every request."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []
        self.beta = NS(messages=NS(create=self.create))
        self.messages = NS(create=self.create_plain)

    def create_plain(self, **kw):
        return self.create(_endpoint="messages", **kw)

    def create(self, **kw):
        self.requests.append({**kw, "messages": list(kw["messages"])})
        return self.responses.pop(0)


@pytest.fixture
def engine(make_engine, lists):
    e = make_engine(blocklists={"bad": lists["bad"], "other": lists["other"]})
    e.investigate([classify("203.0.113.66")], depth=0)
    return e


def test_tool_schemas_are_strict_and_closed():
    names = {t["name"] for t in TOOLS}
    assert {"investigate", "get_indicator", "live_connections", "traceroute"} <= names
    for t in TOOLS:
        assert t["strict"] is True
        assert t["input_schema"]["additionalProperties"] is False
        assert set(t["input_schema"]["required"]) == set(t["input_schema"]["properties"])
        assert hasattr(Toolbox, f"t_{t['name']}")


def test_agent_uses_tools_and_answers(engine):
    fake = FakeClient(
        resp(
            "tool_use",
            text("Checking the database."),
            tool("t1", "get_indicator", indicator="203.0.113.66"),
            tool("t2", "search_indicators", verdict="malicious", kind="any", text="", limit=10),
        ),
        resp("end_turn", text("Bottom line: ip:203.0.113.66 is malicious (two blocklists agree).")),
    )
    steps = []
    answer = Analyst(engine, client=fake).ask("Is 203.0.113.66 bad?", on_step=steps.append)

    assert "malicious" in answer.text and answer.stop_reason == "end_turn"
    assert [s.tool for s in steps] == ["get_indicator", "search_indicators"] and all(s.ok for s in steps)
    assert steps[0].summary == "malicious 90"
    # Both tool results went back together, in one user message, matching the call ids.
    results = fake.requests[1]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["t1", "t2"]
    assert json.loads(results[0]["content"])["assessment"]["verdict"] == "malicious"
    # Request shape: default model, effort, caching, stable tools + system, refusal fallback.
    req = fake.requests[0]
    assert req["model"] == "claude-opus-5-5" and req["output_config"] == {"effort": "high"}
    assert req["cache_control"] == {"type": "ephemeral"} and req["tools"] is TOOLS
    assert req["fallbacks"] == "default" and req["betas"] == ["server-side-fallback-2026-07-01"]
    assert req["thinking"] == {"type": "adaptive"} and "_endpoint" not in req
    assert answer.input_tokens == 200 and answer.output_tokens == 100


def test_bad_tool_input_is_returned_as_error_not_raised(engine):
    fake = FakeClient(
        resp("tool_use", tool("t1", "get_indicator", indicator="not an indicator")),
        resp("end_turn", text("That value is not a valid indicator.")),
    )
    answer = Analyst(engine, client=fake).ask("check 'not an indicator'")
    err = fake.requests[1]["messages"][-1]["content"][0]
    assert err["is_error"] is True and "not a recognisable indicator" in err["content"]
    assert answer.steps[0].ok is False


def test_refusal_and_truncation_do_not_run_tools(engine):
    fake = FakeClient(resp("refusal"))
    assert "declined" in Analyst(engine, client=fake).ask("x").text

    fake = FakeClient(
        resp("max_tokens", text("partial"), tool("t1", "investigate", indicators=["8.8.8.8"], depth=0))
    )
    answer = Analyst(engine, client=fake).ask("x")
    assert answer.steps == [] and "cut off" in answer.text


def test_step_limit(engine):
    loop = [resp("tool_use", tool(f"t{i}", "database_stats")) for i in range(3)]
    answer = Analyst(engine, client=FakeClient(*loop), max_steps=3).ask("x")
    assert answer.stop_reason == "step_limit" and len(answer.steps) == 3


def test_tools_respect_engine_limits(engine):
    tb = Toolbox(engine)
    out = tb.run("investigate", {"indicators": ["evil[.]example"] * 30, "depth": 2})
    assert out["looked_up"] >= 1
    with pytest.raises(Exception, match="non-empty"):
        tb.run("investigate", {"indicators": [], "depth": 0})
    assert tb.run("get_indicator", {"indicator": "ip:9.9.9.9"})["found"] is False
    assert tb.run("extract_indicators", {"text": "c2 at 198.51.100[.]7"}) == ["ip:198.51.100.7"]


def test_missing_sdk_or_key_is_a_clear_error(engine, monkeypatch):
    import builtins

    real = builtins.__import__

    def no_anthropic(name, *a, **kw):
        if name == "anthropic":
            raise ImportError
        return real(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_anthropic)
    with pytest.raises(AgentUnavailable, match=r"pip install \.\[ai\]"):
        Analyst(engine)


def test_api_errors_are_explained(engine):
    anthropic = pytest.importorskip("anthropic")
    import httpx2

    req = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    err = anthropic.AuthenticationError("bad key", response=httpx2.Response(401, request=req), body=None)

    class Failing(FakeClient):
        def create(self, **kw):
            raise err

    with pytest.raises(AgentUnavailable, match="ANTHROPIC_API_KEY"):
        Analyst(engine, client=Failing()).ask("x")


def test_desk_keeps_conversation_and_rolls_back_failures(engine):
    fake = FakeClient(resp("end_turn", text("first")), resp("end_turn", text("second")))
    desk = AgentDesk(engine, analyst_factory=lambda: Analyst(engine, client=fake))
    assert desk.status()["available"] is True

    def wait(job):
        for _ in range(100):
            if job.status != "running":
                return job
            time.sleep(0.02)
        raise AssertionError("job did not finish")

    assert wait(desk.ask("one", "s1")).answer.text == "first"
    assert wait(desk.ask("two", "s1")).answer.text == "second"
    assert [m["role"] for m in desk.sessions["s1"]] == ["user", "assistant", "user", "assistant"]
    assert len(fake.requests[1]["messages"]) == 3  # second question saw the first exchange

    failed = wait(desk.ask("three", "s1"))  # script exhausted -> error
    assert failed.status == "error" and len(desk.sessions["s1"]) == 4  # half turn rolled back
    with pytest.raises(ValueError):
        desk.ask("   ", "s1")


def test_agent_api(engine):
    fake = FakeClient(resp("tool_use", tool("t1", "database_stats")), resp("end_turn", text("All quiet.")))
    engine._desk = AgentDesk(engine, analyst_factory=lambda: Analyst(engine, client=fake))
    srv = make_server(engine, "127.0.0.1", 0)
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
        assert call("/api/agent/status")[1]["available"] is True
        status, job = call("/api/agent", {"question": "anything bad?", "session": "x"})
        assert status == 200
        for _ in range(100):
            job = call(f"/api/agent?id={job['id']}")[1]
            if job["status"] != "running":
                break
            time.sleep(0.02)
        assert job["answer"] == "All quiet." and job["steps"][0]["tool"] == "database_stats"
        assert call("/api/agent", {"question": ""})[0] == 400
        assert call("/api/agent?id=999")[0] == 404
        assert call("/api/agent/reset", {"session": "x"})[1] == {"ok": True}
    finally:
        srv.shutdown()
        srv.server_close()


def test_no_credentials_is_reported_up_front(engine, monkeypatch, tmp_path):
    pytest.importorskip("anthropic")
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    engine.config.keys.pop("anthropic", None)
    with pytest.raises(AgentUnavailable, match="ANTHROPIC_API_KEY"):
        Analyst(engine)
    assert AgentDesk(engine).status() == {
        "available": False,
        "reason": "no Anthropic API key found: add ANTHROPIC_API_KEY=... to your .env file",
    }
    engine.config.keys["anthropic"] = "dummy"
    assert Analyst(engine).client is not None


def test_gateway_mode_sends_a_plain_standard_request(engine):
    engine.config.ai_base_url = "https://gateway.example.com/"
    engine.config.ai_model = "claude-opus-4.8"
    fake = FakeClient(resp("end_turn", text("hi")))
    analyst = Analyst(engine, client=fake)
    assert analyst.endpoint == "gateway.example.com" and analyst.official is False
    analyst.ask("hello")
    req = fake.requests[0]
    assert req["_endpoint"] == "messages" and req["model"] == "claude-opus-4.8"
    assert "betas" not in req and "fallbacks" not in req and "cache_control" not in req
    assert req["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert req["thinking"] == {"type": "adaptive"}


def test_official_models_without_fallback_support_skip_it(engine):
    engine.config.ai_model = "claude-opus-4-8"
    fake = FakeClient(resp("end_turn", text("hi")))
    Analyst(engine, client=fake).ask("hello")
    req = fake.requests[0]
    assert (
        req["_endpoint"] == "messages"
        and "fallbacks" not in req
        and req["cache_control"] == {"type": "ephemeral"}
    )


def test_gateway_settings_from_env():
    from iglite import config

    cfg = config.load(
        env={
            "ANTHROPIC_BASE_URL": " https://gateway.example.com ",
            "IGLITE_AI_MODEL": "claude-opus-4.8",
            "ANTHROPIC_API_KEY": "k",
        }
    )
    assert (cfg.ai_base_url, cfg.ai_model, cfg.keys["anthropic"]) == (
        "https://gateway.example.com",
        "claude-opus-4.8",
        "k",
    )


def test_gateway_needs_a_key(engine, monkeypatch):
    pytest.importorskip("anthropic")
    engine.config.ai_base_url = "https://gateway.example.com"
    engine.config.keys.pop("anthropic", None)
    with pytest.raises(AgentUnavailable, match="ANTHROPIC_BASE_URL"):
        Analyst(engine)


def test_real_sdk_sends_gateway_request_to_the_configured_url(engine):
    anthropic = pytest.importorskip("anthropic")
    import httpx2

    seen = {}

    def handler(req):
        seen.update(
            url=str(req.url),
            beta=req.headers.get("anthropic-beta"),
            key=req.headers.get("x-api-key"),
            body=json.loads(req.content),
        )
        return httpx2.Response(
            200,
            json={
                "id": "m",
                "type": "message",
                "role": "assistant",
                "model": "x",
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    engine.config.ai_base_url = "https://gateway.example.com"
    engine.config.ai_model = "claude-opus-4.8"
    client = anthropic.Anthropic(
        api_key="dummy",
        base_url="https://gateway.example.com",
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )
    assert Analyst(engine, client=client).ask("hello").text == "ok"
    assert seen["url"] == "https://gateway.example.com/v1/messages" and seen["beta"] is None
    assert seen["key"] == "dummy" and seen["body"]["model"] == "claude-opus-4.8"
    assert "fallbacks" not in seen["body"] and seen["body"]["thinking"] == {"type": "adaptive"}
