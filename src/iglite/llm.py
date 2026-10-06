"""Model backends for the AI agents: Claude (Anthropic SDK) or a local model (Ollama).

Both expose the same three operations to the agent loop:

* ``user(history, text)``          - append the user's message
* ``step(history, system, tools)`` - one model turn; appends the assistant message
                                     and returns a backend-neutral ``Turn``
* ``results(history, items)``      - append the tool results for that turn

Tools are defined once, in Anthropic's format (``name``/``description``/
``input_schema``); the Ollama backend converts them to its function format.
Pick the backend with ``IGLITE_AI_PROVIDER=anthropic|ollama`` in ``.env``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import Config

CLAUDE_DEFAULT = "claude-opus-5-5"
OLLAMA_DEFAULT = "qwen2.5:7b"  # small, good at tool calling; any tool-capable model works
# Claude models that accept server-side refusal fallback (`fallbacks: "default"`).
FALLBACK_MODELS = frozenset({"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"})


class AgentUnavailable(RuntimeError):
    """The configured model can't be used (missing package, key, server or model)."""


@dataclass
class Call:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class Turn:
    text: str
    calls: list[Call] = field(default_factory=list)
    stop: str = "end"  # end | tool_use | max_tokens | refusal | pause
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0


def make_backend(
    cfg: Config, *, client: Any = None, model: str | None = None, effort: str | None = None
) -> Any:
    if (cfg.ai_provider or "anthropic").lower() == "ollama":
        return OllamaBackend(cfg, model=model)
    return ClaudeBackend(cfg, client=client, model=model, effort=effort)


# -- Claude ------------------------------------------------------------------------


class ClaudeBackend:
    provider = "anthropic"

    def __init__(
        self, cfg: Config, *, client: Any = None, model: str | None = None, effort: str | None = None
    ):
        self.cfg = cfg
        self.model = model or cfg.ai_model or CLAUDE_DEFAULT
        self.effort = effort or cfg.ai_effort
        self.base_url = (cfg.ai_base_url or "").rstrip("/") or None
        # Anthropic-only features (beta endpoint, server-side fallback) are used only on
        # Anthropic's own API; a third-party gateway gets a plain, standard request.
        self.official = self.base_url is None or urlsplit(self.base_url).hostname == "api.anthropic.com"
        self.client = client if client is not None else self._make_client()

    @property
    def endpoint(self) -> str:
        return (urlsplit(self.base_url).hostname or self.base_url) if self.base_url else "api.anthropic.com"

    def _make_client(self) -> Any:
        try:
            import anthropic
        except ImportError:
            raise AgentUnavailable("the Claude backend needs the 'anthropic' package: pip install .[ai]")
        key = self.cfg.keys.get("anthropic")
        if self.base_url and not key:
            raise AgentUnavailable(
                f"ANTHROPIC_BASE_URL is set to {self.base_url} but no ANTHROPIC_API_KEY was found"
            )
        if key:
            if self.base_url:
                return anthropic.Anthropic(api_key=key, base_url=self.base_url)
            return anthropic.Anthropic(api_key=key)
        # No key in .env: the SDK can still use its own credential chain
        # (ANTHROPIC_AUTH_TOKEN, or a profile from `ant auth login`). If none of
        # those exist either, say so now rather than failing on the first question.
        profile = Path.home() / ".config" / "anthropic"
        if not (
            os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_PROFILE") or profile.is_dir()
        ):
            raise AgentUnavailable("no Anthropic API key found: add ANTHROPIC_API_KEY=... to your .env file")
        return anthropic.Anthropic()

    def request(
        self, system: str, tools: list[dict[str, Any]], messages: list[Any]
    ) -> tuple[Any, dict[str, Any]]:
        """The create() function and keyword arguments for one model turn."""
        kw: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 16000,
            "tools": tools,
            "messages": messages,
            "output_config": {"effort": self.effort},
        }
        if "haiku" not in self.model:
            # Opus 4.x runs without reasoning unless asked; newer models accept this too.
            kw["thinking"] = {"type": "adaptive"}
        if self.official:
            kw["system"] = system
            kw["cache_control"] = {"type": "ephemeral"}  # tools + system + history are a stable prefix
            if self.model in FALLBACK_MODELS:
                # If a safety classifier declines, retry on Anthropic's recommended model.
                kw["betas"] = ["server-side-fallback-2026-07-01"]
                kw["fallbacks"] = "default"
                return self.client.beta.messages.create, kw
            return self.client.messages.create, kw
        # Gateway: only long-standing fields. Caching via a block-level marker on the system prompt.
        kw["system"] = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        return self.client.messages.create, kw

    def user(self, history: list[Any], text: str) -> None:
        history.append({"role": "user", "content": text})

    def step(self, history: list[Any], system: str, tools: list[dict[str, Any]]) -> Turn:
        create, kw = self.request(system, tools, history)
        try:
            response = create(**kw)
        except Exception as exc:  # map SDK errors to a message the user can act on
            raise AgentUnavailable(_explain_claude_error(exc, self.endpoint)) from exc
        # Keep the full content (thinking blocks included) so the next turn is valid.
        history.append({"role": "assistant", "content": response.content})
        usage = getattr(response, "usage", None)
        stop = {
            "tool_use": "tool_use",
            "max_tokens": "max_tokens",
            "refusal": "refusal",
            "pause_turn": "pause",
        }.get(response.stop_reason or "", "end")
        calls = [
            Call(b.id, b.name, b.input if isinstance(b.input, dict) else {})
            for b in response.content
            if b.type == "tool_use"
        ]
        if stop == "end" and calls:
            stop = "tool_use"
        return Turn(
            text="\n\n".join(b.text for b in response.content if b.type == "text" and b.text.strip()),
            calls=calls,
            stop=stop,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        )

    def results(self, history: list[Any], items: list[tuple[Call, str, bool]]) -> None:
        # All results for one turn go back together, in a single user message.
        history.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": call.id,
                        "content": content,
                        **({"is_error": True} if err else {}),
                    }
                    for call, content, err in items
                ],
            }
        )


def _explain_claude_error(exc: Exception, endpoint: str) -> str:
    try:
        import anthropic
    except ImportError:  # pragma: no cover - client was injected
        return str(exc)
    if isinstance(exc, anthropic.AuthenticationError):
        return f"{endpoint} rejected the API key. Check ANTHROPIC_API_KEY in your .env file."
    if isinstance(exc, anthropic.PermissionDeniedError):
        return "This API key is not allowed to use the model. Check your account."
    if isinstance(exc, anthropic.RateLimitError):
        return f"Rate limited by {endpoint}. Wait a minute and try again."
    if isinstance(exc, anthropic.BadRequestError):
        return f"{endpoint} rejected the request: {exc.message}"
    if isinstance(exc, anthropic.APIStatusError):
        return f"{endpoint} returned an error ({exc.status_code}). Try again shortly."
    if isinstance(exc, anthropic.APIConnectionError):
        return f"Could not reach {endpoint}. Check your internet connection, proxy or ANTHROPIC_BASE_URL."
    return f"{type(exc).__name__}: {exc}"


# -- Ollama (local) -----------------------------------------------------------------

# (method, url, json body or None, timeout) -> (status, decoded json)
OllamaTransport = Callable[[str, str, dict[str, Any] | None, float], tuple[int, Any]]


def _http_json(method: str, url: str, body: dict[str, Any] | None, timeout: float) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    host = urlsplit(url).hostname or ""
    # A local Ollama must never be routed through a corporate HTTP proxy.
    local = host in ("localhost", "::1") or host.startswith("127.")
    opener = (
        urllib.request.build_opener(urllib.request.ProxyHandler({}))
        if local
        else urllib.request.build_opener()
    )
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - configured http(s) URL
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"null")
        except ValueError:
            return exc.code, None


class OllamaBackend:
    provider = "ollama"
    official = False

    def __init__(
        self,
        cfg: Config,
        *,
        model: str | None = None,
        transport: OllamaTransport | None = None,
        check: bool = True,
    ) -> None:
        self.cfg = cfg
        self.url = (cfg.ollama_url or "http://localhost:11434").rstrip("/")
        if not self.url.startswith(("http://", "https://")):
            self.url = "http://" + self.url
        self.model = model or cfg.ai_model or OLLAMA_DEFAULT
        self._send = transport or _http_json
        if check:
            self._check()

    @property
    def endpoint(self) -> str:
        return (
            f"Ollama at {urlsplit(self.url).netloc} (on this computer)"
            if self.local
            else f"Ollama at {urlsplit(self.url).netloc}"
        )

    @property
    def local(self) -> bool:
        host = urlsplit(self.url).hostname or ""
        return host in ("localhost", "::1") or host.startswith("127.")

    def _check(self) -> None:
        try:
            status, data = self._send("GET", self.url + "/api/tags", None, 3.0)
        except OSError:
            raise AgentUnavailable(
                f"Ollama isn't running at {self.url}: install it from ollama.com and start it"
            )
        if status != 200:
            raise AgentUnavailable(f"Ollama at {self.url} answered HTTP {status}")
        names = {m.get("name", "") for m in (data or {}).get("models", [])}
        wanted = self.model if ":" in self.model else self.model + ":latest"
        if self.model not in names and wanted not in names:
            raise AgentUnavailable(
                f"the Ollama model '{self.model}' isn't downloaded yet: run `ollama pull {self.model}`"
            )

    @staticmethod
    def _tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    def user(self, history: list[Any], text: str) -> None:
        history.append({"role": "user", "content": text})

    def step(self, history: list[Any], system: str, tools: list[dict[str, Any]]) -> Turn:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *history],
            "tools": self._tools(tools),
            "stream": False,
            "options": {"temperature": 0.2, "num_ctx": 16384},
        }
        try:
            status, data = self._send("POST", self.url + "/api/chat", body, 600.0)
        except OSError as exc:
            raise AgentUnavailable(f"Could not reach Ollama at {self.url}: {exc}")
        if status != 200 or not isinstance(data, dict):
            detail = (data or {}).get("error") if isinstance(data, dict) else None
            raise AgentUnavailable(f"Ollama returned HTTP {status}: {detail or 'no details'}")
        msg = data.get("message") or {}
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            args = fn.get("arguments") or {}
            if isinstance(args, str):  # some models return a JSON string
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            calls.append(
                Call(
                    f"call_{len(history)}_{i}",
                    str(fn.get("name", "")),
                    args if isinstance(args, dict) else {},
                )
            )
        history.append(
            {
                k: v
                for k, v in {
                    "role": "assistant",
                    "content": msg.get("content") or "",
                    "tool_calls": msg.get("tool_calls"),
                }.items()
                if v is not None
            }
        )
        stop = "tool_use" if calls else ("max_tokens" if data.get("done_reason") == "length" else "end")
        return Turn(
            text=(msg.get("content") or "").strip(),
            calls=calls,
            stop=stop,
            input_tokens=data.get("prompt_eval_count", 0) or 0,
            output_tokens=data.get("eval_count", 0) or 0,
        )

    def results(self, history: list[Any], items: list[tuple[Call, str, bool]]) -> None:
        for call, content, _err in items:
            history.append({"role": "tool", "tool_name": call.name, "content": content})
