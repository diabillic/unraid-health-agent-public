import copy
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from unraid_agent import userscripts as u
from unraid_agent.checks import Checks
from unraid_agent.config import Config
from unraid_agent.state import State

TZ = ZoneInfo("America/New_York")


def ts(*args):
    return datetime(*args, tzinfo=TZ).timestamp()


NOW = ts(2026, 11, 7, 12, 0)
BASE = "/boot/config/plugins/user.scripts/scripts"


def script(name, started=None, finished=True, hits=(), running=None, tail=()):
    log = None
    if started:
        log = {"started_at": started, "finished_at": started + 60 if finished else None,
               "finished": "x" if finished else None, "hits": list(hits), "hits_total": len(hits), "tail": list(tail)}
    return {"name": name, "path": f"{BASE}/{name}/script", "running": running, "log": log}


def sched(name, frequency, custom=""):
    return {"script": f"{BASE}/{name}/script", "frequency": frequency, "custom": custom}


def report(*scripts, schedule=(), booted=ts(2026, 10, 1)):
    return {"now": NOW, "timezone": "America/New_York", "booted": booted,
            "crontab": ["40 4 * * * /usr/bin/run-parts /etc/cron.daily 1> /dev/null"],
            "schedule": list(schedule), "scripts": list(scripts)}


def cfg(**kw):
    c = Config(mcp_url="https://unraid:9876/mcp", mcp_api_key="k", timezone="America/New_York")
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def keys(findings):
    return {f.key for f in findings}


# --- cron ---

@pytest.mark.parametrize("expr, before, expected", [
    ("0 2 * * *", datetime(2026, 11, 7, 1, 59), datetime(2026, 11, 6, 2, 0)),
    ("0 2 * * *", datetime(2026, 11, 7, 2, 0), datetime(2026, 11, 7, 2, 0)),
    ("*/15 * * * *", datetime(2026, 11, 7, 10, 44), datetime(2026, 11, 7, 10, 30)),
    ("30 4 * * sun", datetime(2026, 11, 7, 12, 0), datetime(2026, 11, 1, 4, 30)),  # Nov 7 2026 is a Saturday
    ("30 4 * * 7", datetime(2026, 11, 7, 12, 0), datetime(2026, 11, 1, 4, 30)),
    ("0 0 1,15 * mon", datetime(2026, 11, 7, 12, 0), datetime(2026, 11, 2, 0, 0)),  # dom OR dow
    ("0 9 1-7 * *", datetime(2026, 11, 20, 0, 0), datetime(2026, 11, 7, 9, 0)),
    ("@daily", datetime(2026, 11, 7, 12, 0), datetime(2026, 11, 7, 0, 0)),
    ("0 12 29 feb *", datetime(2026, 11, 7, 12, 0), None),  # next leap day is outside the 400-day look-back
])
def test_previous_fire(expr, before, expected):
    assert u.previous_fire(expr, before) == expected


@pytest.mark.parametrize("expr", ["0 2 * *", "61 * * * *", "x * * * *"])
def test_previous_fire_rejects_bad_expressions(expr):
    with pytest.raises(ValueError):
        u.previous_fire(expr, datetime(2026, 11, 7))


def test_run_parts_reads_unraids_times():
    times = u.run_parts(["10 5 * * * /usr/bin/run-parts /etc/cron.daily 1> /dev/null"])
    assert times["daily"] == "10 5 * * *" and times["hourly"] == "47 * * * *"


# --- runs ---

def test_clean_runs_on_time_report_nothing():
    r = report(script("backup", ts(2026, 11, 7, 8, 0), hits=["if an error shows above, nothing to delete"]),
               script("prune", ts(2026, 11, 7, 4, 40)),
               schedule=[sched("backup", "custom", "0 8 * * *"), sched("prune", "daily")])
    assert u.check(r, cfg()) == []


def test_error_lines_alert_once_per_run():
    started = ts(2026, 11, 7, 8, 0)
    r = report(script("backup", started, hits=["2026/11/07 08:10:00 ERROR : a.jpg: Failed to copy: quota",
                                                "\x1b[0mErrors:                 3 (retrying may help)",
                                                "INFO : renamed error-log.txt"]))
    [f] = u.check(r, cfg())
    assert f.key == f"uscript:backup:failed:{started}" and f.severity == "error" and f.once
    assert f.details["errors"] == ["2026/11/07 08:10:00 ERROR : a.jpg: Failed to copy: quota",
                                   "Errors:                 3 (retrying may help)"]


def test_ignore_patterns_and_ignored_scripts():
    r = report(script("backup", ts(2026, 11, 7, 8, 0), hits=["ERROR : known flaky file"]),
               script("noisy", ts(2026, 11, 7, 8, 0), hits=["fatal: whatever"]))
    assert u.check(r, cfg(userscripts_ignore_patterns=["known flaky"], userscripts_ignore=["Noisy"])) == []


def test_unfinished_run_without_process_is_killed():
    started = ts(2026, 11, 7, 8, 0)
    dead = script("a", started, finished=False, running={"pid": 4242, "since": started, "alive": False})
    gone = script("b", started, finished=False)
    found = u.check(report(dead, gone), cfg())
    assert keys(found) == {f"uscript:a:killed:{started}", f"uscript:b:killed:{started}"}
    assert all(f.severity == "error" for f in found)


def test_running_scripts_are_not_judged_until_they_finish_but_long_runs_alert():
    started = ts(2026, 11, 7, 8, 0)
    busy = script("a", started, finished=False, hits=["ERROR : retrying"],
                  running={"pid": 1, "since": started, "alive": True})
    assert u.check(report(busy), cfg()) == []
    [f] = u.check(report(busy), cfg(userscripts_max_runtime_hours=3))
    assert f.key == "uscript:a:long"


def test_missed_scheduled_run():
    r = report(script("pics", ts(2026, 11, 6, 2, 0)), schedule=[sched("pics", "custom", "0 2 * * *")])
    [f] = u.check(r, cfg())
    assert f.key == "uscript:pics:missed" and "Nov 07 02:00" in f.summary


def test_daily_uses_unraids_run_parts_time():
    r = report(script("prune", ts(2026, 11, 6, 4, 40)), schedule=[sched("prune", "daily")])
    assert keys(u.check(r, cfg())) == {"uscript:prune:missed"}


def test_no_missed_run_within_grace_or_before_boot_or_unscheduled():
    within = report(script("a", ts(2026, 11, 6, 11, 50)), schedule=[sched("a", "custom", "50 11 * * *")])
    assert u.check(within, cfg()) == []  # due 11:50, now 12:00, grace 15 min
    rebooted = report(script("a"), schedule=[sched("a", "custom", "0 2 * * *")], booted=ts(2026, 11, 7, 3, 0))
    assert u.check(rebooted, cfg()) == []
    for freq in ("disabled", "start", "stop", "boot"):
        assert u.check(report(script("a"), schedule=[sched("a", freq)]), cfg()) == []


def test_never_ran_since_boot_is_missed():
    [f] = u.check(report(script("a"), schedule=[sched("a", "custom", "0 2 * * *")]), cfg())
    assert f.key == "uscript:a:missed" and "no run since the server booted" in f.summary


def test_schedule_for_deleted_script_and_unreadable_schedule():
    r = report(script("odd"), schedule=[sched("move", "daily"), sched("old", "disabled"), sched("odd", "custom", "0 2 *")])
    assert keys(u.check(r, cfg())) == {"uscript:move:gone", "uscript:odd:schedule"}


# --- wiring ---

class HealthyMCP:
    def call_tool(self, name, arguments=None):
        return {"status": "ok", "graphqlReachable": True} if name == "unraid_health_check" else []


def test_unreachable_report_keeps_open_alerts(tmp_path, monkeypatch):
    c = cfg(state_path=str(tmp_path / "s.json"), userscripts_host="unraid.local", userscripts_host_key="ssh-ed25519 AAAA",
            userscripts_key_path=str(tmp_path / "key"))
    monkeypatch.setattr(u, "ensure_ssh", lambda *a: None)

    def refuse(*a, **k):
        raise u.ReportError("Permission denied (publickey)")
    monkeypatch.setattr(u, "fetch_report", refuse)
    checks = Checks(HealthyMCP(), State(c.state_path), c, datetime.fromtimestamp(NOW, TZ))
    found = checks.user_scripts()
    assert keys(found) == {"userscripts:unreachable"} and checks.unchecked == ["uscript:"]


def test_check_runs_only_when_configured(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(u, "ensure_ssh", lambda *a: None)
    monkeypatch.setattr(u, "fetch_report", lambda *a, **k: calls.append(a) or report())
    for host, expected in (("", 0), ("unraid.local", 1)):
        c = cfg(state_path=str(tmp_path / "s.json"), userscripts_host=host, userscripts_host_key="ssh-ed25519 AAAA",
                userscripts_key_path=str(tmp_path / "key"), check_vms=False)
        Checks(HealthyMCP(), State(c.state_path), c, datetime.fromtimestamp(NOW, TZ)).run()
        assert len(calls) == expected
