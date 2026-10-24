"""Notifications: Discord embeds, or any Apprise URL as markdown (see notice.py)."""

from __future__ import annotations

import logging
import time

from .bus import push_alert
from .findings import Finding
from .notice import Outbox, digest
from .state import State

log = logging.getLogger(__name__)

AUTHOR = "Unraid agent"
FOREVER_HOURS = 24 * 365 * 10


class Notifier:
    def __init__(self, urls: list[str], renotify_hours: int, state: State, bot_url: str = "", bot_token: str = ""):
        self.renotify_hours = renotify_hours
        self.state = state
        self.bot_url, self.bot_token = bot_url, bot_token  # Discord bot first, Apprise as fallback
        self.outbox = Outbox(urls)

    def send(self, findings: list[Finding], diagnosis: str | None = None, complete: bool = True) -> None:
        """One digest per cycle: new issues, reminders every renotify_hours, and issues that cleared.

        complete=False (some checks couldn't run) suppresses "cleared": a missing finding then
        means "not checked", not "fixed".
        """
        notified = self.state["notified"]
        now = time.time()
        current = {f.key for f in findings} if complete else set(notified) | {f.key for f in findings}

        due = []
        for f in findings:
            prev = notified.get(f.key)
            hours = FOREVER_HOURS if f.once else self.renotify_hours
            if prev is None or now - prev["ts"] >= hours * 3600:
                due.append(f)

        cleared = [v["summary"] for k, v in notified.items()
                   if k not in current and not v.get("once") and v.get("severity") in ("warning", "error")]
        for k in [k for k in notified if k not in current]:
            del notified[k]

        if not due and not cleared and not diagnosis:
            return
        for f in due:
            notified[f.key] = {"ts": now, "summary": f.summary, "severity": f.severity, "once": f.once}

        msg = digest(AUTHOR, due, cleared, diagnosis)
        body = msg.markdown()
        log.info("%s\n%s", msg.title, body)
        if self.bot_url and push_alert(self.bot_url, self.bot_token, "unraid", msg.title, body, due, diagnosis):
            return
        self.outbox.send(msg)
