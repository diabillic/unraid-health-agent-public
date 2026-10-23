"""Notifications via Apprise (Discord, Pushover, ntfy, Telegram, email, ... by URL)."""

from __future__ import annotations

import logging
import time

import apprise

from .findings import Finding
from .state import State

log = logging.getLogger(__name__)

ICON = {"info": "ℹ️", "warning": "⚠️", "error": "❌"}
FOREVER_HOURS = 24 * 365 * 10


class Notifier:
    def __init__(self, urls: list[str], renotify_hours: int, state: State):
        self.renotify_hours = renotify_hours
        self.state = state
        self.apobj = apprise.Apprise()
        for url in urls:
            if not self.apobj.add(url):
                log.warning("Ignoring invalid notification URL (scheme %s)", url.split(":", 1)[0])

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

        lines = [f"{ICON.get(f.severity, '•')} {f.summary}" for f in sorted(due, key=lambda f: f.severity != "error")]
        lines += [f"✅ Cleared: {s}" for s in cleared]
        if diagnosis:
            lines += ["", "🧠 Diagnosis:", diagnosis]
        open_issues = sum(1 for f in due if f.severity in ("warning", "error"))
        title = f"Unraid agent: {open_issues} issue(s)" + (f", {len(cleared)} cleared" if cleared else "")
        body = "\n".join(lines)

        log.info("%s\n%s", title, body)
        if len(self.apobj) and not self.apobj.notify(title=title, body=body):
            log.warning("One or more notification targets failed")
