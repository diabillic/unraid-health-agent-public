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
        # From a digest that wasn't delivered: one-off events (syslog lines, forwarded notices) and the
        # diagnosis, which no later cycle finds again. Open issues come back by themselves.
        self.unsent: list[Finding] = []
        self.unsent_diagnosis: str | None = None

    def send(self, findings: list[Finding], diagnosis: str | None = None, complete: bool = True,
             unchecked: tuple[str, ...] = ()) -> None:
        """One digest per cycle: new issues, reminders every renotify_hours, and issues that cleared.

        complete=False (some checks couldn't run) suppresses "cleared": a missing finding then
        means "not checked", not "fixed". unchecked does the same for keys with these prefixes
        (one check's data source was unavailable). Nothing counts as sent until it's delivered.
        """
        keys = {f.key for f in findings}
        findings = findings + [f for f in self.unsent if f.key not in keys]
        diagnosis = diagnosis or self.unsent_diagnosis
        notified = self.state["notified"]
        now = time.time()
        current = {f.key for f in findings} if complete else set(notified) | {f.key for f in findings}
        current |= {k for k in notified if k.startswith(tuple(unchecked))}

        due = []
        for f in findings:
            prev = notified.get(f.key)
            hours = FOREVER_HOURS if f.once else self.renotify_hours
            if prev is None or now - prev["ts"] >= hours * 3600:
                due.append(f)

        gone = [k for k in notified if k not in current]
        cleared = [notified[k]["summary"] for k in gone
                   if not notified[k].get("once") and notified[k].get("severity") in ("warning", "error")]

        if due or cleared or diagnosis:
            msg = digest(AUTHOR, due, cleared, diagnosis)
            body = msg.markdown()
            log.info("%s\n%s", msg.title, body)
            delivered = bool(self.bot_url and push_alert(self.bot_url, self.bot_token, "unraid", msg.title, body, due,
                                                         diagnosis)) or self.outbox.send(msg)
            if not delivered:
                self.unsent, self.unsent_diagnosis = [f for f in due if f.once], diagnosis
                return  # the cleared items stay recorded, so they're reported cleared again next cycle
        self.unsent, self.unsent_diagnosis = [], None
        for k in gone:
            del notified[k]
        for f in due:
            notified[f.key] = {"ts": now, "summary": f.summary, "severity": f.severity, "once": f.once}
