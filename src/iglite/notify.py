"""Alert notifications: send new live-monitoring alerts to Slack, Teams, email or a webhook.

Destinations are secrets, so they come from the environment (or ``.env``) only:

    IGLITE_NOTIFY_SLACK=https://hooks.slack.com/services/...
    IGLITE_NOTIFY_TEAMS=https://...  (a Teams "Workflows" webhook)
    IGLITE_NOTIFY_WEBHOOK=https://... (receives the alert as JSON)
    IGLITE_NOTIFY_EMAIL=you@example.com,soc@example.com  + IGLITE_SMTP_HOST/PORT/USER/PASSWORD/FROM

Sending happens on a background thread so monitoring never waits on it. Only
alerts at or above ``notify_min_verdict`` are sent, at most ``notify_per_hour``
of them; offline mode (and the demo) never sends anything.
"""

from __future__ import annotations

import json
import queue
import smtplib
import ssl
import threading
import time
import urllib.request
from collections import deque
from email.message import EmailMessage
from typing import Any

from . import __version__
from .store import Store

RANK = {"malicious": 2, "suspicious": 1}


def message(
    alert: dict[str, Any], case_id: int | None = None, dashboard: str | None = None
) -> dict[str, Any]:
    """The alert in the shapes the channels want: a title, plain text lines and a link."""
    ctx = alert.get("context") or {}
    kind, _, value = alert["key"].partition(":")
    who = " ".join(
        x for x in (ctx.get("device_name"), f"({ctx['device']})" if ctx.get("device") else None) if x
    )
    who = who or ctx.get("process") or ""
    how = "looked up" if ctx.get("query") else "contacted by" if ctx.get("inbound") else "connected to"
    title = f"{alert['verdict'].capitalize()} {kind}: {value} (score {alert['score']})"
    lines = [
        f"{who or 'A device'} {how} {value}"
        + (f" on port {ctx['remote_port']}" if ctx.get("remote_port") and not ctx.get("query") else ""),
    ]
    if ctx.get("names"):
        lines.append("Names: " + ", ".join(ctx["names"]))
    if ctx.get("attack"):
        lines.append("MITRE ATT&CK: " + ", ".join(ctx["attack"]))
    if case_id:
        lines.append(f"Filed in case #{case_id}")
    link = f"{dashboard.rstrip('/')}/#live" if dashboard else None
    return {"title": title, "lines": lines, "link": link, "alert": alert, "case_id": case_id}


def anomaly_message(a: dict[str, Any], dashboard: str | None = None) -> dict[str, Any]:
    from .behaviour import describe

    who = a.get("who_name") or a["who"].split(":", 1)[1]
    return {
        "title": f"Behaviour: {describe(a['kind'])} on {who} ({a['severity']})",
        "lines": [a["detail"]],
        "link": f"{dashboard.rstrip('/')}/#behaviour" if dashboard else None,
        "alert": None,
        "anomaly": a,
        "case_id": None,
    }


def _post(url: str, payload: dict[str, Any], timeout: float = 10.0) -> None:
    req = urllib.request.Request(  # noqa: S310 - the person's own configured destination
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": f"iglite/{__version__}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        resp.read(1024)


def send_slack(url: str, msg: dict[str, Any], **_: Any) -> None:
    text = (
        f"*{msg['title']}*\n"
        + "\n".join(msg["lines"])
        + (f"\n<{msg['link']}|Open the dashboard>" if msg["link"] else "")
    )
    _post(url, {"text": text})


def send_teams(url: str, msg: dict[str, Any], **_: Any) -> None:
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": msg["title"], "weight": "Bolder", "size": "Medium", "wrap": True},
        *({"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"} for line in msg["lines"]),
    ]
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if msg["link"]:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open the dashboard", "url": msg["link"]}]
    _post(
        url,
        {
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
        },
    )


def send_webhook(url: str, msg: dict[str, Any], **_: Any) -> None:
    _post(
        url,
        {
            "source": "iglite",
            "title": msg["title"],
            "text": "\n".join(msg["lines"]),
            "link": msg["link"],
            "case_id": msg["case_id"],
            "alert": msg["alert"],
            "anomaly": msg.get("anomaly"),
        },
    )


def send_email(to: str, msg: dict[str, Any], *, smtp: dict[str, str], **_: Any) -> None:
    if not smtp.get("host"):
        raise RuntimeError("IGLITE_SMTP_HOST is not set")
    em = EmailMessage()
    em["Subject"] = f"[IntelGraph Lite] {msg['title']}"
    em["From"] = smtp.get("from") or smtp.get("user") or "iglite@localhost"
    em["To"] = to
    em.set_content(
        "\n".join(msg["lines"]) + (f"\n\nOpen the dashboard: {msg['link']}" if msg["link"] else "") + "\n"
    )
    port = int(smtp.get("port") or 587)
    ctx = ssl.create_default_context()
    if port == 465:
        server: smtplib.SMTP = smtplib.SMTP_SSL(smtp["host"], port, timeout=15, context=ctx)
    else:
        server = smtplib.SMTP(smtp["host"], port, timeout=15)
        server.starttls(context=ctx)
    with server:
        if smtp.get("user"):
            server.login(smtp["user"], smtp.get("password", ""))
        server.send_message(em)


SENDERS = {"slack": send_slack, "teams": send_teams, "webhook": send_webhook, "email": send_email}


class Notifier:
    """Queues alerts and sends them to every configured channel from one background thread."""

    def __init__(self, cfg: Any, store: Store, senders: dict[str, Any] | None = None) -> None:
        self.cfg, self.store = cfg, store
        self.senders = senders or SENDERS
        self.sent: deque[float] = deque()
        self.log: deque[dict[str, Any]] = deque(maxlen=20)  # recent deliveries, for the status endpoint
        self._q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=200)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def channels(self) -> list[str]:
        return [c for c in self.cfg.notify if c in self.senders]

    def wanted(self, alert: dict[str, Any]) -> bool:
        floor = RANK.get(self.cfg.notify_min_verdict, 2)
        return RANK.get(alert["verdict"], 0) >= floor

    def on_anomaly(self, anomaly: dict[str, Any]) -> bool:
        """Queue a behaviour anomaly at or above ``behaviour_notify`` severity."""
        floor = {"low": 0, "medium": 1, "high": 2}.get(str(self.cfg.behaviour_notify).lower())
        if floor is None or not self.channels or self.cfg.offline:
            return False
        if {"low": 0, "medium": 1, "high": 2}.get(anomaly["severity"], 0) < floor:
            return False
        return self._queue(anomaly_message(anomaly, self.cfg.dashboard_url), f"anomaly {anomaly['id']}")

    def on_alert(self, alert_id: int) -> bool:
        """Queue an alert if it should go out. Returns whether it was queued."""
        if not self.channels or self.cfg.offline:
            return False
        alert = self.store.alert(alert_id)
        if alert is None or not self.wanted(alert):
            return False
        return self._queue(message(alert, alert.get("case_id"), self.cfg.dashboard_url), f"alert {alert_id}")

    def _queue(self, msg: dict[str, Any], what: str) -> bool:
        now = time.time()
        while self.sent and self.sent[0] < now - 3600:
            self.sent.popleft()
        if len(self.sent) >= self.cfg.notify_per_hour:
            self.log.append(
                {
                    "at": now,
                    "channel": "*",
                    "ok": False,
                    "detail": f"hourly cap reached; {what} not sent",
                }
            )
            return False
        self.sent.append(now)
        try:
            self._q.put_nowait(msg)
        except queue.Full:
            return False
        self._ensure_thread()
        return True

    def send_now(self, msg: dict[str, Any]) -> list[dict[str, Any]]:
        """Deliver one message to every channel; returns one result per channel."""
        results = []
        for channel in self.channels:
            try:
                self.senders[channel](self.cfg.notify[channel], msg, smtp=self.cfg.smtp)
                result = {"at": time.time(), "channel": channel, "ok": True, "detail": msg["title"]}
            except Exception as exc:  # a broken destination must not stop the others
                result = {
                    "at": time.time(),
                    "channel": channel,
                    "ok": False,
                    "detail": f"{type(exc).__name__}: {exc}"[:300],
                }
            self.log.append(result)
            results.append(result)
        return results

    def test(self) -> list[dict[str, Any]]:
        if not self.channels:
            raise RuntimeError(
                "no notification channel is configured (set IGLITE_NOTIFY_SLACK, _TEAMS, _WEBHOOK or _EMAIL)"
            )
        alert = {
            "id": 0,
            "key": "domain:test-alert.example",
            "verdict": "malicious",
            "score": 99,
            "status": "open",
            "at": time.time(),
            "context": {"device_name": "Test device", "device": "10.0.0.2", "query": True},
        }
        msg = message(alert, None, self.cfg.dashboard_url)
        msg["title"] = "Test notification: " + msg["title"]
        return self.send_now(msg)

    def status(self) -> dict[str, Any]:
        return {
            "channels": self.channels,
            "min_verdict": self.cfg.notify_min_verdict,
            "per_hour": self.cfg.notify_per_hour,
            "sent_last_hour": sum(1 for t in self.sent if t > time.time() - 3600),
            "offline": bool(self.cfg.offline),
            "recent": list(self.log)[::-1],
        }

    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._loop, name="iglite-notify", daemon=True)
                self._thread.start()

    def _loop(self) -> None:
        while True:
            try:
                msg = self._q.get(timeout=60)
            except queue.Empty:
                with self._lock:  # idle: exit, unless an alert arrived just now
                    if self._q.empty():
                        self._thread = None
                        return
                continue
            self.send_now(msg)
