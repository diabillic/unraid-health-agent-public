"""Read-only health checks over unraidclaw MCP tools. Nothing here changes the server.

Most unraidclaw tools front Unraid's GraphQL API; their exact payloads vary by Unraid
version, so field access is defensive (wrapper keys, alternate names, missing values).
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests

from .config import CPU_TEMP_SENSORS, Config, trusted_temp_sensors
from .findings import Finding
from .graphql import GraphQLError, UnraidGraphQL
from .mcp import MCPClient, MCPError, ToolError
from .state import State

log = logging.getLogger(__name__)

DISK_OK_STATUSES = {"DISK_OK", "DISK_NP"}  # DISK_NP = empty slot
RUNNING_VM_STATES = {"RUNNING", "STARTED", "IDLE"}


def items(data: Any, *keys: str) -> list[dict]:
    """Normalise list payloads that may be bare lists or wrapped ({"containers": [...]})."""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for k in keys:
            if isinstance(data.get(k), list):
                return [d for d in data[k] if isinstance(d, dict)]
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return v
    return []


def first(d: dict, *names: str, default: Any = None) -> Any:
    for n in names:
        if d.get(n) is not None:
            return d[n]
    return default


def number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        m = re.search(r"-?\d+(\.\d+)?", value)
        return float(m.group()) if m else None
    return None


def to_dt(value: Any) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        ts = value / 1000 if value > 1e11 else value  # ms or s
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def short_hash(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:12]


class Checks:
    def __init__(self, mcp: MCPClient, state: State, cfg: Config, now: datetime, gql: UnraidGraphQL | None = None):
        self.mcp, self.state, self.cfg, self.now, self.gql = mcp, state, cfg, now, gql
        self.syslog_rx = [re.compile(p, re.I) for p in cfg.syslog_patterns]
        self.parity_disks: int | None = None  # learned from array status; None = unknown
        # Key prefixes of checks whose Unraid API data couldn't be read: their open alerts aren't cleared
        self.unchecked: list[str] = []

    def run(self) -> list[Finding]:
        try:
            health = self.mcp.call_tool("unraid_health_check")
        except (MCPError, requests.RequestException) as exc:
            hint = " (TLS fingerprint mismatch: unraidclaw's certificate changed)" if "fingerprint" in str(exc).lower() else ""
            return [Finding("mcp:down", f"unraidclaw MCP is unreachable at {self.cfg.mcp_url}: {exc}{hint}", "error")]

        findings: list[Finding] = []
        degraded = isinstance(health, dict) and (
            str(health.get("status", "ok")).lower() != "ok" or health.get("graphqlReachable") is False
        )
        if degraded:
            # unraidclaw probes GRAPHQL_URL (default http://localhost/graphql) with its own Unraid API key.
            findings.append(Finding(
                "mcp:degraded",
                "unraidclaw is degraded: it can't query Unraid's GraphQL API, so array, disk, Docker, VM and "
                "notification checks are unavailable. Fix: Settings > Management Access > API, copy an API key "
                "with the ADMIN role, paste it into Settings > UnraidClaw > Unraid API Key, check Unraid WebUI "
                "Port, and Apply. If it persists, run `unraid-api status` on the server.",
                "error",
            ))

        unavailable: list[str] = []
        forbidden: dict[str, str] = {}
        checks: list[tuple[str, Callable[[], list[Finding]]]] = [
            ("array", self.array), ("disks", self.disks), ("smart", self.smart), ("parity", self.parity), ("docker", self.docker),
            ("docker sizes", self.docker_sizes), ("temperatures", self.temperatures),
            ("vms", self.vms), ("notifications", self.notifications), ("syslog", self.syslog),
            ("system", self.system), ("plugins", self.plugins),
        ]
        if not self.cfg.check_vms:
            checks = [c for c in checks if c[0] != "vms"]
        for name, check in checks:
            try:
                findings += check()
            except ToolError as exc:
                denied = re.search(r"Permission denied: (\S+)", str(exc))
                if "FORBIDDEN" in str(exc) and denied:
                    forbidden[name] = denied.group(1)
                else:
                    log.warning("%s check unavailable: %s", name, exc)
                    unavailable.append(name)
            except (MCPError, requests.RequestException) as exc:
                log.warning("%s check unavailable: %s", name, exc)
                unavailable.append(name)
        if forbidden:
            perms = ", ".join(sorted(set(forbidden.values())))
            findings.append(Finding(
                "mcp:permissions",
                f"unraidclaw denied read access, so these checks were skipped: {', '.join(forbidden)}. "
                f"Grant {perms} in Settings > UnraidClaw > Permissions.",
                details={"denied": forbidden},
            ))
        if unavailable and not degraded:
            findings.append(Finding(
                "mcp:tools-failing", f"Checks unavailable due to unraidclaw tool errors: {', '.join(unavailable)}.",
                escalate=True, details={"checks": unavailable},
            ))
        return findings

    # --- array & disks ---

    def array(self) -> list[Finding]:
        data = self.mcp.call_tool("unraid_array_status")
        if isinstance(data, dict):
            parities = first(data, "parities", "parityDisks")
            if isinstance(parities, list):
                self.parity_disks = len(parities)
        state = str(first(data, "state", "status", default="") if isinstance(data, dict) else "").upper()
        if state and state != "STARTED":
            return [Finding("array:state", f"Unraid array is {state}, not STARTED.", "error", escalate=True)]
        return []

    @staticmethod
    def _pool_row(p: dict) -> dict:
        row = dict(p)
        size, used = number(p.get("fsSize")), number(p.get("fsUsed"))
        if size and used is not None:
            row["usedPercent"] = round(used / size * 100, 1)
        return row

    def disks(self) -> list[Finding]:
        out: list[Finding] = []
        rows = items(self.mcp.call_tool("unraid_disk_list"), "disks")
        if self.gql:
            try:
                rows += [self._pool_row(p) for p in self.gql.pool_disks()]
            except (GraphQLError, requests.RequestException, ValueError) as exc:
                self.unchecked.append("disk:")
                out.append(Finding("disk:pools-unavailable",
                                   f"Couldn't read pool disks from Unraid's API ({self.cfg.unraid_graphql_url}): {exc}"))
        if not rows and not out:
            # Pool-only servers: unraidclaw lists only array and parity disks.
            hint = "" if self.gql else " Set UNRAID_GRAPHQL_URL and UNRAID_API_KEY to monitor pool disks directly."
            return [Finding("disk:none", "No disks are visible, so disk status, temperature and usage aren't monitored "
                                         f"directly. Disk problems still arrive via Unraid notifications and syslog.{hint}",
                            "info", once=True)]
        for d in rows:
            name = str(first(d, "name", "id", "device", default="?"))
            status = str(d.get("status") or "").upper()
            if status and status not in DISK_OK_STATUSES:
                out.append(Finding(f"disk:{name}:status", f"Disk {name} status is {status}.", "error", escalate=True,
                                   details={"disk": d}))
            temp = number(first(d, "temp", "temperature"))
            if temp is not None and temp >= self.cfg.disk_temp_crit:
                out.append(Finding(f"disk:{name}:temp", f"Disk {name} is at {temp:.0f}°C (critical ≥ {self.cfg.disk_temp_crit}).", "error"))
            elif temp is not None and temp >= self.cfg.disk_temp_warn:
                out.append(Finding(f"disk:{name}:temp", f"Disk {name} is at {temp:.0f}°C (warn ≥ {self.cfg.disk_temp_warn})."))
            # Unraid's per-disk warning/critical are disk utilization thresholds (%), not temperatures.
            used = number(first(d, "usedPercent", "usage"))
            use_warn = number(d.get("warning")) or self.cfg.disk_usage_warn
            use_crit = number(d.get("critical"))
            if used is not None and use_crit and used >= use_crit:
                out.append(Finding(f"disk:{name}:usage", f"Disk {name} is {used:.0f}% full (critical ≥ {use_crit:.0f}%).", "error"))
            elif used is not None and used >= use_warn:
                out.append(Finding(f"disk:{name}:usage", f"Disk {name} is {used:.0f}% full (warn ≥ {use_warn:.0f}%)."))
            errors = number(d.get("numErrors"))
            if errors:
                out.append(Finding(f"disk:{name}:errors", f"Disk {name} has {errors:.0f} read/write error(s).", "error",
                                   escalate=True, details={"disk": d}))
        return out

    def smart(self) -> list[Finding]:
        """SMART health per physical disk, via Unraid's API (unraidclaw doesn't expose it)."""
        if not self.gql:
            return []
        try:
            disks = self.gql.physical_disks()
        except (GraphQLError, requests.RequestException, ValueError) as exc:
            self.unchecked.append("smart:")
            return [Finding("smart:unavailable", f"Couldn't read SMART status from Unraid's API: {exc}")]
        streak = self.state["smart"]
        present, out = set(), []
        for d in disks:
            device = str(d.get("device") or "?").removeprefix("/dev/")
            serial = str(d.get("serialNum") or device)
            present.add(serial)
            status = str(d.get("smartStatus") or "").upper()
            if status == "OK":
                streak.pop(serial, None)
                continue
            # Don't skip on isSpinning: some servers report false for every disk, NVMe included,
            # while standby drives still read OK. The consecutive-readings rule absorbs one-off glitches.
            streak[serial] = streak.get(serial, 0) + 1
            if streak[serial] >= self.cfg.smart_unknown_cycles:
                label = f"{device} ({' '.join(str(x) for x in (d.get('vendor'), d.get('name')) if x)}, serial {serial})"
                out.append(Finding(
                    f"smart:{serial}",
                    f"SMART status for {label} is {status or 'missing'} for {streak[serial]} checks in a row. Unraid reports "
                    "a failing SMART self-assessment this way. Check the disk's SMART attributes on Unraid's Main tab.",
                    "error", escalate=True, details={"disk": d},
                ))
        for gone in [s for s in streak if s not in present]:
            del streak[gone]
        return out

    def parity(self) -> list[Finding]:
        if self.parity_disks == 0:
            return []  # no parity disk, so parity history is meaningless
        p = self.mcp.call_tool("unraid_parity_status")
        if not isinstance(p, dict) or p.get("running"):
            return []
        last = p.get("lastCheck") or {}
        finished = to_dt(last.get("finished"))
        stamp = last.get("finished") or "none"
        out = []
        errors = number(first(last, "errors", default=p.get("errors"))) or 0
        if errors > 0:
            out.append(Finding(f"parity:errors:{stamp}", f"Last parity check found {errors:.0f} error(s).", "error",
                               escalate=True, once=True, details={"parity": p}))
        exit_status = last.get("exitStatus")
        if finished and exit_status not in (None, 0):
            out.append(Finding(f"parity:exit:{stamp}", f"Last parity check ended abnormally (exit status {exit_status}).",
                               once=True, details={"parity": p}))
        if finished is None:
            out.append(Finding("parity:none", "No completed parity check is on record.", "info", once=True))
        elif (self.now - finished).days > self.cfg.parity_max_age_days:
            out.append(Finding("parity:stale", f"Last parity check finished {(self.now - finished).days} days ago "
                                               f"(> {self.cfg.parity_max_age_days}).", once=True))
        return out

    # --- docker & VMs ---

    def _quiet(self, windows: list[tuple[int, int]]) -> bool:
        if not windows:
            return False
        try:
            local = self.now.astimezone(ZoneInfo(self.cfg.timezone)) if self.cfg.timezone else self.now.astimezone()
        except (ZoneInfoNotFoundError, ValueError):
            local = self.now.astimezone()
        m = local.hour * 60 + local.minute
        return any(a <= m < b if a <= b else m >= a or m < b for a, b in windows)

    def _guests(self, kind: str, rows: list[dict], ignore: list[str], is_running: Callable[[dict], bool],
                problem: Callable[[dict], str | None], quiet: bool = False) -> list[Finding]:
        out, seen = [], set()
        last = self.state["last_running"]
        for r in rows:
            name = first(r, "name", "names", "id", default="?")
            name = (name[0] if isinstance(name, list) and name else str(name)).lstrip("/")
            key = f"{kind}:{name}"
            seen.add(key)
            if name in ignore:
                continue
            running = is_running(r)
            label = "Container" if kind == "docker" else "VM"
            state_txt = str(first(r, "state", "status", default="unknown"))
            issue = problem(r)
            if issue:
                out.append(Finding(f"{key}:issue", f"{label} {name} is {issue}.", escalate=True, details={kind: r}))
            elif not running and last.get(key) is True and quiet:
                # Expected stop (e.g. a backup): keep it as running, so it alerts if still down after the window
                log.info("%s %s is %s during a quiet window; not alerting", label, name, state_txt)
                continue
            elif not running and first(r, "autoStart", "autostart") is True:
                out.append(Finding(f"{key}:down", f"{label} {name} is {state_txt} but set to autostart.", "error",
                                   escalate=True, details={kind: r}))
            elif not running and last.get(key) is True:
                out.append(Finding(f"{key}:down", f"{label} {name} stopped (was running last check): {state_txt}.", "error",
                                   escalate=True, details={kind: r}))
            last[key] = running
        for k in [k for k in last if k.startswith(f"{kind}:") and k not in seen]:
            del last[k]
        return out

    def docker(self) -> list[Finding]:
        rows = items(self.mcp.call_tool("unraid_docker_list"), "containers", "docker")

        def running(r: dict) -> bool:
            return str(first(r, "state", default="")).lower() == "running"

        def problem(r: dict) -> str | None:
            status = str(first(r, "status", "health", default="")).lower()
            if "unhealthy" in status:
                return "unhealthy"
            # The API reports a crash-looping container as state EXITED; only the status text says "Restarting".
            if str(first(r, "state", default="")).lower() == "restarting" or status.startswith("restarting"):
                return f"crash-looping ({first(r, 'status', default='restarting')})"
            return None

        return self._guests("docker", rows, self.cfg.docker_ignore, running, problem,
                            self._quiet(self.cfg.docker_quiet_windows))

    def temperatures(self) -> list[Finding]:
        """CPU and board temperatures against each sensor's Unraid thresholds (trusted sensors only), or
        CPU_TEMP_WARN/CPU_TEMP_CRIT for the CPU."""
        if not self.gql or not self.cfg.temp_sensors:
            return []
        try:
            sensors = self.gql.temperature_sensors()
        except (GraphQLError, requests.RequestException, ValueError) as exc:
            self.unchecked.append("temp:")
            return [Finding("temp:unavailable", f"Couldn't read temperature sensors from Unraid's API: {exc}")]
        sensors = [s for s in sensors if s.get("type") not in ("DISK", "NVME")]
        wanted = trusted_temp_sensors(self.cfg.temp_sensors, [str(s.get("name") or "") for s in sensors])
        cpu = re.compile(CPU_TEMP_SENSORS, re.I)
        units = {"CELSIUS": "°C", "FAHRENHEIT": "°F", "KELVIN": "K", "RANKINE": "°R"}
        hot = self.state["temp_hot"]  # sensor -> when it first read over its limit, for the spike grace period
        now = self.now.timestamp()
        out, still_hot = [], set()
        for s in sensors:
            name = str(s.get("name") or "")
            if not wanted.search(name):
                continue
            cur = s.get("current") or {}
            value, warn, crit = number(cur.get("value")), number(s.get("warning")), number(s.get("critical"))
            own_limits = cpu.search(name) and (self.cfg.cpu_temp_warn or self.cfg.cpu_temp_crit)
            if own_limits:  # Unraid's limits (and the status it derives from them) don't fit this CPU
                warn, crit = self.cfg.cpu_temp_warn or warn, self.cfg.cpu_temp_crit or crit
            if value is None or not 0 < value < 150:
                continue  # unconnected headers read 0, negative or absurd values
            unit = units.get(str(cur.get("unit")), "°")
            status = "" if own_limits else str(cur.get("status") or "").upper()
            limit = lambda v: f"{v:g}{unit}" if v else "Unraid's limit"  # noqa: E731
            if (crit and value >= crit) or status == "CRITICAL":
                f = Finding(f"temp:{name}", f"{name} is at {value:.0f}{unit} (critical ≥ {limit(crit)}).", "error",
                            escalate=True, details={"sensor": s})
            elif (warn and value >= warn) or status == "WARNING":
                f = Finding(f"temp:{name}", f"{name} is at {value:.0f}{unit} (warn ≥ {limit(warn)}).",
                            escalate=True, details={"sensor": s})
            else:
                continue
            still_hot.add(name)
            since = hot.setdefault(name, now)
            minutes = (now - since) / 60
            if minutes < self.cfg.temp_grace_minutes:
                log.info("%s spike (%.0f%s), waiting %d min before alerting", name, value, unit, self.cfg.temp_grace_minutes)
                continue
            if minutes >= 1:
                f.summary += f" Hot for {minutes:.0f} min."
            out.append(f)
        for name in [n for n in hot if n not in still_hot]:
            del hot[name]  # cooled down (or gone): the next spike starts a new grace period
        return out

    def docker_sizes(self) -> list[Finding]:
        """Containers filling docker.img: big writable layers, big logs, fast writable-layer growth.

        The same query reports image updates, which become one-time notices.
        """
        if not self.gql:
            return []
        try:
            rows = self.gql.container_sizes()
        except (GraphQLError, requests.RequestException, ValueError) as exc:
            self.unchecked.append("docker:")  # also holds container-down alerts for this cycle; they clear next one
            return [Finding("docker:sizes-unavailable", f"Couldn't read container sizes from Unraid's API: {exc}")]
        history = self.state["docker_sizes"]  # name -> [[ts, rw_bytes], ...], about hourly, last 24 h
        now = self.now.timestamp()
        out, present = [], set()
        for r in rows:
            names = r.get("names") or []
            name = str(names[0] if names else "?").lstrip("/")
            present.add(name)
            if name in self.cfg.docker_ignore:
                continue
            if self.cfg.docker_updates and r.get("isUpdateAvailable"):
                out.append(Finding(f"docker:{name}:update", f"Container update available: {name}.", "info", once=True))
            rw, log_size = number(r.get("sizeRw")), number(r.get("sizeLog"))
            if rw is not None and rw / 1e9 >= self.cfg.docker_rw_warn_gb:
                out.append(Finding(f"docker:{name}:rw",
                                   f"Container {name} has {rw / 1e9:.1f} GB in its writable layer (warn ≥ "
                                   f"{self.cfg.docker_rw_warn_gb:g} GB). It is writing inside docker.img; map that path "
                                   "to appdata or a share.", escalate=True, details={"container": r}))
            if log_size is not None and log_size / 1e9 >= self.cfg.docker_log_warn_gb:
                out.append(Finding(f"docker:{name}:log",
                                   f"Container {name}'s log is {log_size / 1e9:.1f} GB (warn ≥ {self.cfg.docker_log_warn_gb:g} GB). "
                                   "Enable Docker log rotation in Settings > Docker, or fix what it's logging."))
            if rw is None:
                continue
            samples = [s for s in history.get(name, []) if now - s[0] <= 24 * 3600]
            if samples:
                growth = rw - min(s[1] for s in samples)
                if growth / 1e9 >= self.cfg.docker_rw_growth_gb:
                    out.append(Finding(f"docker:{name}:growth",
                                       f"Container {name}'s writable layer grew {growth / 1e9:.1f} GB in the last 24 h "
                                       f"(now {rw / 1e9:.1f} GB). Something in it is writing inside docker.img.",
                                       escalate=True, details={"container": r}))
            if not samples or now - samples[-1][0] >= 55 * 60:
                samples.append([now, rw])
            history[name] = samples
        for gone in [n for n in history if n not in present]:
            del history[gone]
        return out

    def vms(self) -> list[Finding]:
        try:
            data = self.mcp.call_tool("unraid_vm_list")
        except ToolError as exc:
            if "VMs are not available" in str(exc):
                return []  # VM Manager disabled: nothing to monitor, not a failure
            raise
        rows = items(data, "vms", "domains", "domain")

        def running(r: dict) -> bool:
            return str(first(r, "state", "status", default="")).upper() in RUNNING_VM_STATES

        def problem(r: dict) -> str | None:
            state = str(first(r, "state", "status", default="")).upper()
            if state == "CRASHED":
                return "crashed"
            return "paused" if state in {"PAUSED", "PMSUSPENDED"} else None

        return self._guests("vm", rows, self.cfg.vm_ignore, running, problem)

    # --- notifications & syslog ---

    def notifications(self) -> list[Finding]:
        rows = items(self.mcp.call_tool("unraid_notification_list"), "notifications", "list")
        seen = self.state["seen"]
        baseline = "notif:baseline" not in seen
        relevant = []
        for n in rows:
            nid = str(first(n, "id", "file", "timestamp", default=""))
            archived = first(n, "archived", default=None)
            if archived is None:
                archived = str(first(n, "type", default="")).upper() == "ARCHIVE"
            level = str(first(n, "importance", "level", "severity", default="")).lower()
            if not nid or archived or level not in self.cfg.notification_levels or f"notif:{nid}" in seen:
                continue
            seen[f"notif:{nid}"] = self.now.timestamp()
            relevant.append((nid, level, n))
        if baseline:
            # First run: don't replay the backlog, just say it exists. (Non-numeric so it never expires.)
            seen["notif:baseline"] = True
            if relevant:
                return [Finding("notif:backlog", f"{len(relevant)} unread warning/alert notification(s) already on Unraid "
                                                 "(not forwarded individually).", "info", once=True)]
            return []
        out = []
        for nid, level, n in relevant:
            text = " — ".join(str(x) for x in (first(n, "title"), first(n, "subject"), first(n, "description")) if x)
            out.append(Finding(f"notif:{nid}", f"Unraid {level}: {text[:300]}", "error" if level == "alert" else "warning",
                               escalate=level == "alert", once=True, details={"notification": n}))
        return out

    def syslog(self) -> list[Finding]:
        data = self.mcp.call_tool("unraid_syslog", {"lines": self.cfg.syslog_lines})
        if isinstance(data, dict):
            lines = first(data, "lines", "entries", "log", default=[])
        else:
            lines = data
        if isinstance(lines, str):
            lines = lines.splitlines()
        lines = [l if isinstance(l, str) else str(first(l, "message", "line", default=l)) for l in lines or []]
        seen = self.state["seen"]
        new = []
        for line in lines:
            if any(rx.search(line) for rx in self.syslog_rx):
                key = f"syslog:{short_hash(line)}"
                if key not in seen:
                    seen[key] = self.now.timestamp()
                    new.append(line)
        if not new:
            return []
        return [Finding(f"syslog:{short_hash(new[0])}", f"{len(new)} new error line(s) in the Unraid syslog, e.g.: {new[0][:220]}",
                        "error", escalate=True, once=True, details={"lines": new[:25]})]

    # --- system & plugins ---

    def system(self) -> list[Finding]:
        m = self.mcp.call_tool("unraid_system_metrics")
        out = []
        mem = number(first((m or {}).get("memory") or {}, "usedPercent", "usagePercent"))
        if mem is not None and mem >= self.cfg.mem_warn_percent:
            out.append(Finding("system:memory", f"Memory usage is {mem:.0f}% (warn ≥ {self.cfg.mem_warn_percent:.0f}%).", escalate=True))
        load = number(((m or {}).get("cpuLoad") or {}).get("load15m"))
        if self.cfg.load_warn and load is not None and load >= self.cfg.load_warn:
            out.append(Finding("system:load", f"15-minute load average is {load:.2f} (warn ≥ {self.cfg.load_warn})."))
        return out

    def plugins(self) -> list[Finding]:
        out = []
        for p in items(self.mcp.call_tool("unraid_plugins_list"), "plugins"):
            if p.get("updateAvailable"):
                name = p.get("name", p.get("file"))
                out.append(Finding(f"plugin:{name}:{p.get('stagedVersion') or p.get('version')}",
                                   f"Plugin update available: {name} (installed {p.get('version')}).", "info", once=True))
        return out
