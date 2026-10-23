"""Environment-driven configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw and raw.strip() else default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw and raw.strip() else default


def _list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


DEFAULT_SYSLOG_PATTERNS = (
    r"I/O error|Buffer I/O error|blk_update_request|critical medium error",
    r"BTRFS (error|critical|warning)|XFS .*(corrupt|error|shutdown)|EXT4-fs error",
    r"ata\d+(\.\d+)?: .*(failed command|exception|link is slow|hard resetting link)",
    r"Machine Check|mce: \[Hardware Error\]",
    r"Out of memory|oom-kill|invoked oom-killer",
    r"md: disk\d+ (read|write) error|md: recovery thread",
    r"nvme\d+.*(timeout|reset controller|I/O)",
    # ZFS: ZED fault events, vdevs leaving ONLINE, suspended pools
    r"zed\[\d+\]: .*class=(checksum|io|data|deadman|probe_failure|vdev\.\w+)",
    r"vdev_state=(DEGRADED|FAULTED|REMOVED|UNAVAIL)",
    r"pool '[^']+' has encountered an uncorrectable I/O failure|zpool .*(DEGRADED|FAULTED|SUSPENDED)",
    # NUT UPS (Unraid's API only reads apcupsd): power loss, low battery, lost link, forced shutdown
    r"upsmon.*(on battery|battery is low|communications? (with UPS .* )?lost|replace battery|forced shutdown|FSD)",
)

# CPU and board sensors worth trusting. Super-I/O chips (e.g. nct6798) also expose voltage inputs
# (in0..in14), fans and unconnected AUXTIN headers as "temperatures"; disks and NVMe are checked
# by the disk check. TSI*_TEMP is left out: it's the board's copy of the AMD CPU reading that
# k10temp Tctl already reports, so including it doubles every CPU alert.
DEFAULT_TEMP_SENSORS = r"k10temp|coretemp|zenpower|Tctl|Tdie|Tccd|Package id|Core \d+|CPUTIN|SYSTIN|MB Temp"


@dataclass
class Config:
    mcp_url: str
    mcp_api_key: str
    mcp_fingerprint: str = ""
    mcp_verify_tls: bool = True
    # Optional direct read-only access to Unraid's GraphQL API (pool disks; unraidclaw omits them)
    unraid_graphql_url: str = ""
    unraid_api_key: str = ""

    interval_minutes: int = 10
    state_path: str = "/var/lib/unraid-agent/state.json"
    notify_urls: list[str] = field(default_factory=list)
    renotify_hours: int = 12

    # Thresholds
    disk_temp_warn: int = 50
    disk_temp_crit: int = 55
    disk_usage_warn: float = 90.0
    smart_unknown_cycles: int = 2  # consecutive non-OK SMART readings before alerting
    parity_max_age_days: int = 45
    mem_warn_percent: float = 90.0
    load_warn: float = 0.0  # 15-min load average; 0 disables
    syslog_lines: int = 300
    syslog_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_SYSLOG_PATTERNS))
    notification_levels: list[str] = field(default_factory=lambda: ["warning", "alert"])

    docker_ignore: list[str] = field(default_factory=list)
    # Container growth inside docker.img (needs UNRAID_API_KEY), in GB
    docker_rw_warn_gb: float = 5.0
    docker_log_warn_gb: float = 1.0
    docker_rw_growth_gb: float = 2.0  # writable-layer growth within 24 h
    docker_updates: bool = True  # one-time notice per container with an image update
    temp_sensors: str = DEFAULT_TEMP_SENSORS  # regex over sensor names; empty disables
    check_vms: bool = True
    vm_ignore: list[str] = field(default_factory=list)

    # LLM diagnosis via OpenCode Go
    opencode_api_key: str = ""
    server_notes: str = ""  # free text about this server, added to the diagnosis prompt
    opencode_model: str = "glm-5.2"
    opencode_base_url: str = "https://opencode.ai/inference/go/openai/v1"
    escalate_cooldown_hours: int = 24

    @property
    def escalation_enabled(self) -> bool:
        return bool(self.opencode_api_key)

    @property
    def pools_enabled(self) -> bool:
        return bool(self.unraid_graphql_url and self.unraid_api_key)

    @classmethod
    def from_env(cls) -> "Config":
        url = os.environ.get("UNRAIDCLAW_URL", "").strip()
        key = os.environ.get("UNRAIDCLAW_API_KEY", "").strip()
        if not url or not key:
            raise SystemExit("UNRAIDCLAW_URL and UNRAIDCLAW_API_KEY are required")
        patterns = _list("SYSLOG_PATTERNS")  # comma-separated; replaces the defaults when set
        return cls(
            mcp_url=url,
            mcp_api_key=key,
            mcp_fingerprint=os.environ.get("UNRAIDCLAW_TLS_FINGERPRINT", "").strip(),
            mcp_verify_tls=_bool("UNRAIDCLAW_VERIFY_TLS", True),
            unraid_graphql_url=os.environ.get("UNRAID_GRAPHQL_URL", "").strip(),
            unraid_api_key=os.environ.get("UNRAID_API_KEY", "").strip(),
            interval_minutes=_int("INTERVAL_MINUTES", 10),
            state_path=os.environ.get("STATE_PATH", "/var/lib/unraid-agent/state.json"),
            notify_urls=_list("NOTIFY_URLS"),
            renotify_hours=_int("RENOTIFY_HOURS", 12),
            disk_temp_warn=_int("DISK_TEMP_WARN", 50),
            disk_temp_crit=_int("DISK_TEMP_CRIT", 55),
            disk_usage_warn=_float("DISK_USAGE_WARN", 90.0),
            smart_unknown_cycles=max(1, _int("SMART_UNKNOWN_CYCLES", 2)),
            parity_max_age_days=_int("PARITY_MAX_AGE_DAYS", 45),
            mem_warn_percent=_float("MEM_WARN_PERCENT", 90.0),
            load_warn=_float("LOAD_WARN", 0.0),
            syslog_lines=_int("SYSLOG_LINES", 300),
            syslog_patterns=patterns or list(DEFAULT_SYSLOG_PATTERNS),
            notification_levels=[l.lower() for l in _list("NOTIFICATION_LEVELS", "warning,alert")],
            docker_ignore=_list("DOCKER_IGNORE"),
            docker_rw_warn_gb=_float("DOCKER_RW_WARN_GB", 5.0),
            docker_log_warn_gb=_float("DOCKER_LOG_WARN_GB", 1.0),
            docker_rw_growth_gb=_float("DOCKER_RW_GROWTH_GB", 2.0),
            docker_updates=_bool("DOCKER_UPDATES", True),
            temp_sensors=os.environ.get("TEMP_SENSORS", DEFAULT_TEMP_SENSORS).strip(),
            check_vms=_bool("CHECK_VMS", True),
            vm_ignore=_list("VM_IGNORE"),
            opencode_api_key=os.environ.get("OPENCODE_API_KEY", "").strip(),
            server_notes=os.environ.get("SERVER_NOTES", "").strip(),
            opencode_model=os.environ.get("OPENCODE_MODEL", "").strip() or "glm-5.2",
            opencode_base_url=os.environ.get("OPENCODE_BASE_URL", "").strip() or "https://opencode.ai/inference/go/openai/v1",
            escalate_cooldown_hours=_int("ESCALATE_COOLDOWN_HOURS", 24),
        )
