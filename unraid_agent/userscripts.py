"""User Scripts plugin: failed, missed, stuck and killed runs.

User Scripts throws away each script's exit code, so a run is judged by its log. The data comes from
deploy/unraid/userscripts-report.php, the only command the agent's SSH key may run on Unraid.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import date, datetime, time as dtime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .findings import Finding

log = logging.getLogger(__name__)

PREFIX = "uscript:"
# Unraid's run-parts times, used if the report doesn't include root's crontab
RUN_PARTS = {"hourly": "47 * * * *", "daily": "40 4 * * *", "weekly": "30 4 * * 0", "monthly": "20 4 1 * *"}
NOT_TIMED = {"disabled", "start", "stop", "boot", ""}  # array start/stop, first array start, off
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class ReportError(Exception):
    pass


# --- SSH ---

def ensure_ssh(key_path: str, known_hosts_path: str, host: str, host_key: str) -> None:
    """The agent's key is made here, once, and never leaves its volume."""
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    if not os.path.exists(key_path):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "unraid-agent-userscripts", "-f", key_path],
                       check=True, timeout=30)
    with open(known_hosts_path, "w", encoding="utf-8") as fh:
        fh.write(f"{host} {host_key}\n")


def fetch_report(host: str, key_path: str, known_hosts_path: str, timeout: float = 60) -> dict:
    command = ["ssh", "-i", key_path, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts_path}",
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", f"root@{host}", "report"]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ReportError("the report timed out") from None
    except OSError as exc:
        raise ReportError(str(exc)) from None
    if done.returncode:
        raise ReportError(done.stderr.strip()[-300:] or f"ssh exit {done.returncode}")
    try:
        return json.loads(done.stdout)
    except ValueError:
        raise ReportError(f"the report isn't JSON: {done.stdout[:200]!r}") from None


# --- cron ---

NAMES = {
    3: {n: i for i, n in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)},
    4: {n: i for i, n in enumerate("sun mon tue wed thu fri sat".split())},
}
BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
MACROS = {"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
          "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}


def _value(text: str, i: int) -> int:
    named = NAMES.get(i, {}).get(text)
    return named if named is not None else int(text)


def _field(text: str, i: int) -> set[int]:
    lo, hi = BOUNDS[i]
    out: set[int] = set()
    for part in text.lower().split(","):
        base, _, step = part.partition("/")
        if base == "*":
            a, b = lo, hi
        else:
            a_txt, _, b_txt = base.partition("-")
            a = _value(a_txt, i)
            b = _value(b_txt, i) if b_txt else (hi if step else a)
        n = int(step) if step else 1
        if not (lo <= a <= hi and lo <= b <= hi and n > 0):
            raise ValueError(f"{part!r} is out of range")
        out.update(range(a, b + 1, n))
    if i == 4 and 7 in out:
        out = (out - {7}) | {0}
    return out


def previous_fire(expr: str, before: datetime) -> datetime | None:
    """The latest time at or before `before` (naive local time) that the cron expression fires."""
    fields = MACROS.get(expr.strip().lower(), expr).split()
    if len(fields) != 5:
        raise ValueError(f"{expr!r} doesn't have 5 fields")
    minutes, hours, doms, months, dows = (_field(f, i) for i, f in enumerate(fields))
    dom_any, dow_any = fields[2] == "*", fields[4] == "*"
    day = before.date()
    for _ in range(400):
        dom_ok, dow_ok = day.day in doms, (day.isoweekday() % 7) in dows
        day_ok = (dom_ok and dow_ok) if (dom_any or dow_any) else (dom_ok or dow_ok)
        if day.month in months and day_ok:
            for h in sorted(hours, reverse=True):
                for m in sorted(minutes, reverse=True):
                    t = datetime.combine(day, dtime(h, m))
                    if t <= before:
                        return t
        day -= timedelta(days=1)
    return None


def run_parts(crontab: list[str]) -> dict[str, str]:
    out = dict(RUN_PARTS)
    for line in crontab:
        m = re.match(r"\s*(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+.*run-parts\s+/etc/cron\.(hourly|daily|weekly|monthly)\b", line)
        if m:
            out[m.group(2)] = m.group(1)
    return out


# --- checks ---

def _zone(name: str):
    try:
        return ZoneInfo(name) if name else None
    except (ZoneInfoNotFoundError, ValueError):
        return None


def _clean(line: str) -> str:
    return ANSI.sub("", line).strip()


def _when(ts: float, tz) -> str:
    return datetime.fromtimestamp(ts, tz).strftime("%b %d %H:%M")


def check(report: dict, cfg: Any) -> list[Finding]:
    """Findings for one report. cfg: the agent Config (userscripts_* settings)."""
    now = float(report.get("now") or 0)
    tz = _zone(str(report.get("timezone") or "")) or _zone(cfg.timezone)
    booted = report.get("booted") or 0
    errors = [re.compile(p) for p in cfg.userscripts_error_patterns]
    ignore = [re.compile(p) for p in cfg.userscripts_ignore_patterns]
    skip = {n.lower() for n in cfg.userscripts_ignore}
    timed = run_parts(report.get("crontab") or [])
    scripts = {s.get("name"): s for s in report.get("scripts") or [] if s.get("name")}
    schedules = {}
    for entry in report.get("schedule") or []:
        path = str(entry.get("script") or "")
        schedules[os.path.basename(os.path.dirname(path))] = entry

    out: list[Finding] = []
    for name in sorted(set(scripts) | set(schedules)):
        if name.lower() in skip:
            continue
        s, sched = scripts.get(name), schedules.get(name) or {}
        freq = str(sched.get("frequency") or "").lower()
        if s is None:
            if freq not in NOT_TIMED:
                out.append(Finding(f"{PREFIX}{name}:gone", f"User script '{name}' is scheduled ({freq}) but its script "
                                   "no longer exists, so it never runs. Delete the schedule or restore the script.",
                                   "info", once=True))
            continue
        run = s.get("log") or {}
        running = s.get("running")
        started = run.get("started_at")

        if running and running.get("alive"):
            hours = (now - float(running.get("since") or now)) / 3600
            if hours >= cfg.userscripts_max_runtime_hours:
                out.append(Finding(f"{PREFIX}{name}:long", f"User script '{name}' has been running for {hours:.1f} h "
                                   f"(limit {cfg.userscripts_max_runtime_hours:g} h): it may be stuck.",
                                   details={"tail": run.get("tail", [])[-10:]}))
        elif running or (started and not run.get("finished")):
            # The plugin writes "Script Finished" and removes the running marker when the script exits.
            since = (running or {}).get("since") or started
            out.append(Finding(f"{PREFIX}{name}:killed:{started or since}",
                               f"User script '{name}' started {_when(since, tz)} but never finished: its process is gone "
                               "(killed, out of memory, or aborted).", "error", once=True,
                               details={"tail": run.get("tail", [])[-10:]}))
        elif started:
            lines = []
            for raw in run.get("hits") or []:
                line = _clean(raw)
                if any(rx.search(line) for rx in errors) and not any(rx.search(line) for rx in ignore):
                    lines.append(line)
            if lines:
                more = f" (and {run.get('hits_total', 0) - len(run.get('hits') or [])} more lines not read)" \
                    if run.get("hits_total", 0) > len(run.get("hits") or []) else ""
                out.append(Finding(f"{PREFIX}{name}:failed:{started}",
                                   f"User script '{name}' logged {len(lines)} error line(s) in its run of "
                                   f"{_when(started, tz)}{more}, e.g.: {lines[0][:220]}",
                                   "error", once=True,
                                   details={"errors": lines[:20], "tail": [_clean(l) for l in run.get("tail", [])[-10:]]}))

        expr = timed.get(freq) if freq in timed else (sched.get("custom") if freq == "custom" else None)
        if not expr or not tz:
            continue
        try:
            local_now = datetime.fromtimestamp(now - cfg.userscripts_grace_minutes * 60, tz).replace(tzinfo=None)
            due = previous_fire(str(expr), local_now)
        except ValueError as exc:
            out.append(Finding(f"{PREFIX}{name}:schedule", f"User script '{name}' has a schedule the agent can't read "
                               f"({expr!r}: {exc}), so missed runs aren't checked.", "info", once=True))
            continue
        if due is None:
            continue
        due_ts = due.replace(tzinfo=tz).timestamp()
        if due_ts <= booted:
            continue  # the server was down or booting then: nothing to expect
        if (started or 0) < due_ts - 120 and not (running and running.get("alive")):
            last = f"last run {_when(started, tz)}" if started else "no run since the server booted"
            out.append(Finding(f"{PREFIX}{name}:missed",
                               f"User script '{name}' didn't run at {due:%b %d %H:%M} ({freq}: {expr}); {last}. "
                               "Scripts can skip themselves when the array is stopped or a parity check runs: "
                               "the syslog says so if that happened."))
    return out
