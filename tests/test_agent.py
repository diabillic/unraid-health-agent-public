import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from unraid_agent.checks import Checks
from unraid_agent.config import Config
from unraid_agent.escalate import read_only_tools, run_agent
from unraid_agent.findings import Finding
from unraid_agent.mcp import MCPClient, MCPError, ToolError
from unraid_agent.notify import Notifier
from unraid_agent.state import State

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
HEALTHY = {
    "unraid_health_check": {"status": "ok", "graphqlReachable": True},
    "unraid_array_status": {"state": "STARTED"},
    "unraid_disk_list": [{"name": "disk1", "status": "DISK_OK", "temp": 35, "usedPercent": 40},
                         {"name": "parity", "status": "DISK_OK", "temp": "*"}],
    "unraid_parity_status": {"running": False, "lastCheck": {"finished": (NOW - timedelta(days=10)).isoformat(),
                                                             "exitStatus": 0, "errors": 0}},
    "unraid_docker_list": {"containers": [{"name": "sonarr", "state": "running", "status": "Up 2 days", "autoStart": True}]},
    "unraid_vm_list": [],
    "unraid_notification_list": [],
    "unraid_syslog": {"lines": ["Oct 23 kernel: all good"]},
    "unraid_system_metrics": {"memory": {"usedPercent": 40.0}, "cpuLoad": {"load15m": 1.0}},
    "unraid_plugins_list": {"plugins": [{"name": "a", "version": "1", "updateAvailable": False}]},
}


class FakeMCP:
    def __init__(self, responses=None, **overrides):
        self.r = copy.deepcopy(responses if responses is not None else HEALTHY)
        self.r.update(overrides)
        self.calls = []

    def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        v = self.r.get(name)
        if isinstance(v, Exception):
            raise v
        return copy.deepcopy(v)


def cfg(tmp_path, **kw):
    c = Config(mcp_url="https://unraid:9876/mcp", mcp_api_key="k", state_path=str(tmp_path / "s.json"))
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def run(mcp, tmp_path, state=None, now=NOW, **kw):
    c = cfg(tmp_path, **kw)
    return Checks(mcp, state or State(c.state_path), c, now).run()


def keys(findings):
    return {f.key for f in findings}


# --- overall ---

def test_healthy_server_has_no_findings(tmp_path):
    assert run(FakeMCP(), tmp_path) == []


def test_unreachable_mcp_is_single_finding(tmp_path):
    fs = run(FakeMCP(unraid_health_check=MCPError("connection refused")), tmp_path)
    assert keys(fs) == {"mcp:down"}


def test_degraded_graphql_reported_once_not_per_tool(tmp_path):
    err = ToolError("INTERNAL_ERROR")
    fs = run(FakeMCP(unraid_health_check={"status": "degraded", "graphqlReachable": False},
                     unraid_array_status=err, unraid_disk_list=err, unraid_docker_list=err), tmp_path)
    assert "mcp:degraded" in keys(fs) and "mcp:tools-failing" not in keys(fs)


def test_permission_denials_name_the_grant(tmp_path):
    # Format from unraidclaw's requirePermission + tool util: "Error: FORBIDDEN: Permission denied: <res>:<act>"
    fs = run(FakeMCP(unraid_docker_list=ToolError("unraid_docker_list: Error: FORBIDDEN: Permission denied: docker:read"),
                     unraid_syslog=ToolError("unraid_syslog: Error: FORBIDDEN: Permission denied: logs:read")), tmp_path)
    [f] = fs
    assert f.key == "mcp:permissions" and not f.escalate
    assert "docker:read, logs:read" in f.summary and "docker, syslog" in f.summary


def test_tool_errors_when_not_degraded_escalate(tmp_path):
    fs = run(FakeMCP(unraid_vm_list=ToolError("boom")), tmp_path)
    [f] = fs
    assert f.key == "mcp:tools-failing" and f.escalate and f.details["checks"] == ["vms"]


# --- array, disks, parity ---

def test_array_not_started(tmp_path):
    [f] = run(FakeMCP(unraid_array_status={"state": "STOPPED"}), tmp_path)
    assert f.severity == "error" and f.escalate


def test_disk_problems(tmp_path):
    disks = [{"name": "disk1", "status": "DISK_DSBL"}, {"name": "disk2", "status": "DISK_OK", "temp": "56 C"},
             {"name": "disk3", "status": "DISK_OK", "temp": 51, "usedPercent": 95.2}, {"name": "disk4", "status": "DISK_NP"}]
    fs = {f.key: f for f in run(FakeMCP(unraid_disk_list={"disks": disks}), tmp_path)}
    assert fs["disk:disk1:status"].escalate
    assert fs["disk:disk2:temp"].severity == "error"
    assert fs["disk:disk3:temp"].severity == "warning" and "disk:disk3:usage" in fs
    assert not any(k.startswith("disk:disk4") for k in fs)


def test_parity_errors_and_staleness(tmp_path):
    old = (NOW - timedelta(days=60)).isoformat()
    fs = keys(run(FakeMCP(unraid_parity_status={"running": False, "lastCheck": {"finished": old, "exitStatus": 0, "errors": 3}}), tmp_path))
    assert f"parity:errors:{old}" in fs and "parity:stale" in fs
    assert run(FakeMCP(unraid_parity_status={"running": True, "lastCheck": {"errors": 9}}), tmp_path) == []
    assert keys(run(FakeMCP(unraid_parity_status={"running": False, "lastCheck": {"finished": None}}), tmp_path)) == {"parity:none"}


def test_parity_epoch_timestamps(tmp_path):
    ts = int((NOW - timedelta(days=50)).timestamp())
    assert "parity:stale" in keys(run(FakeMCP(unraid_parity_status={"running": False, "lastCheck": {"finished": ts}}), tmp_path))


# --- docker & vms ---

def test_container_with_autostart_down(tmp_path):
    rows = [{"names": ["/plex"], "state": "exited", "autoStart": True}, {"name": "tmp", "state": "exited", "autoStart": False}]
    [f] = run(FakeMCP(unraid_docker_list=rows), tmp_path)
    assert f.key == "docker:plex:down" and f.severity == "error"


def test_container_crash_detected_by_transition(tmp_path):
    c = cfg(tmp_path)
    st = State(c.state_path)
    up = FakeMCP(unraid_docker_list=[{"name": "radarr", "state": "running"}])
    down = FakeMCP(unraid_docker_list=[{"name": "radarr", "state": "exited"}])
    assert Checks(up, st, c, NOW).run() == []
    [f] = Checks(down, st, c, NOW).run()
    assert f.key == "docker:radarr:down"
    assert Checks(down, st, c, NOW).run() == []  # reported once; still down but no longer a transition


def test_containers_stopping_in_a_quiet_window_alert_only_if_still_down_after(tmp_path):
    c = cfg(tmp_path, docker_quiet_windows=[(300, 310)], timezone="America/New_York")
    st = State(c.state_path)
    at = lambda hh, mm: datetime(2026, 10, 23, hh + 4, mm, tzinfo=timezone.utc)  # EDT is UTC-4
    up = FakeMCP(unraid_docker_list=[{"name": "radarr", "state": "running", "autoStart": True},
                                     {"name": "sab", "state": "running", "autoStart": False}])
    down = FakeMCP(unraid_docker_list=[{"name": "radarr", "state": "exited", "autoStart": True},
                                       {"name": "sab", "state": "exited", "autoStart": False}])
    back = FakeMCP(unraid_docker_list=[{"name": "radarr", "state": "running", "autoStart": True},
                                       {"name": "sab", "state": "exited", "autoStart": False}])
    assert Checks(up, st, c, at(4, 55)).run() == []
    assert Checks(down, st, c, at(5, 0)).run() == []  # the backup stopped both
    assert Checks(down, st, c, at(5, 9)).run() == []
    # radarr came back; sab didn't, so it alerts once the window ends at 05:10
    assert keys(Checks(back, st, c, at(5, 10)).run()) == {"docker:sab:down"}
    # a stop outside the window alerts as before
    assert keys(Checks(down, st, c, at(6, 0)).run()) == {"docker:radarr:down"}


def test_quiet_windows_parse_and_wrap_midnight(tmp_path, monkeypatch):
    monkeypatch.setenv("UNRAIDCLAW_URL", "https://u/mcp")
    monkeypatch.setenv("UNRAIDCLAW_API_KEY", "k")
    monkeypatch.setenv("DOCKER_QUIET_WINDOWS", "05:00-05:10, 23:50-0:20")
    monkeypatch.setenv("TZ", "UTC")
    c = Config.from_env()
    assert c.docker_quiet_windows == [(300, 310), (1430, 20)] and c.timezone == "UTC"
    ck = Checks(FakeMCP(), State(str(tmp_path / "s.json")), c, NOW)
    for hh, mm, quiet in [(23, 55, True), (0, 10, True), (0, 20, False), (5, 0, True), (5, 10, False), (12, 0, False)]:
        ck.now = datetime(2026, 10, 23, hh, mm, tzinfo=timezone.utc)
        assert ck._quiet(c.docker_quiet_windows) is quiet, (hh, mm)
    monkeypatch.setenv("DOCKER_QUIET_WINDOWS", "5am-5:10")
    with pytest.raises(SystemExit):
        Config.from_env()


def test_unhealthy_and_ignored_containers(tmp_path):
    rows = [{"name": "a", "state": "running", "status": "Up 1h (unhealthy)"}, {"name": "b", "state": "restarting"},
            {"name": "c", "state": "running", "status": "Up (unhealthy)"}]
    fs = keys(run(FakeMCP(unraid_docker_list=rows), tmp_path, docker_ignore=["c"]))
    assert fs == {"docker:a:issue", "docker:b:issue"}


def test_vm_autostart_down_paused_and_crashed(tmp_path):
    rows = [{"name": "win11", "state": "SHUTOFF", "autoStart": True}, {"name": "hass", "state": "PAUSED"},
            {"name": "nas2", "state": "CRASHED"}]
    assert keys(run(FakeMCP(unraid_vm_list=rows), tmp_path)) == {"vm:win11:down", "vm:hass:issue", "vm:nas2:issue"}


def test_live_pool_only_server_shapes(tmp_path):
    # Captured from the real server (unraidclaw 0.1.37, Unraid 7, pools only, VM Manager off).
    fs = run(FakeMCP(
        unraid_array_status={"state": "STARTED", "capacity": {"kilobytes": {"free": "0", "used": "0", "total": "0"}},
                             "disks": [], "parities": []},
        unraid_disk_list=[],
        unraid_parity_status={"running": False, "lastCheck": {"started": None, "finished": None, "exitStatus": 0, "errors": 0}},
        unraid_vm_list=ToolError("unraid_vm_list: Error: GRAPHQL_ERROR: Failed to retrieve VM domains: VMs are not available"),
        unraid_docker_list=[
            {"id": "a", "names": ["/sonarr"], "state": "RUNNING", "status": "Up 3 hours", "autoStart": True},
            {"id": "b", "names": ["/nebula-sync"], "state": "EXITED", "status": "Restarting (1) 45 seconds ago", "autoStart": True},
            {"id": "c", "names": ["/metube"], "state": "EXITED", "status": "Created", "autoStart": False}],
        unraid_notification_list=[{"id": "x:Unraid_Status_1.notify", "subject": "Notice [TOWER] - array health report [PASS]",
                                   "description": "Array has 9 disks (including pools)", "importance": "INFO",
                                   "timestamp": "2026-10-23T04:20:01.000Z", "type": "UNREAD"}],
    ), tmp_path)
    by = {f.key: f for f in fs}
    assert set(by) == {"disk:none", "docker:nebula-sync:issue"}  # no parity noise, no VM failure, INFO not forwarded
    assert "crash-looping" in by["docker:nebula-sync:issue"].summary and by["docker:nebula-sync:issue"].escalate
    assert by["disk:none"].once and by["disk:none"].severity == "info"


class FakeGQL:
    def __init__(self, pools=None, error=None, physical=None, smart_error=None, containers=None, sensors=None):
        self.pools, self.error = pools or [], error
        self.physical, self.smart_error = physical or [], smart_error
        self.containers = containers or []
        self.sensors = sensors or []

    def temperature_sensors(self):
        return copy.deepcopy(self.sensors)

    def container_sizes(self):
        return copy.deepcopy(self.containers)

    def pool_disks(self):
        if self.error:
            raise self.error
        return copy.deepcopy(self.pools)

    def physical_disks(self):
        if self.smart_error:
            raise self.smart_error
        return copy.deepcopy(self.physical)


def _sensor(name, value, warn=80, crit=90, status="NORMAL", type_="CUSTOM"):
    return {"name": name, "type": type_, "current": {"value": value, "unit": "CELSIUS", "status": status},
            "warning": warn, "critical": crit}


# Captured from a real nct6798 + k10temp: voltages as "temps", a fan, unconnected AUXTIN headers.
REAL_SENSORS = [
    _sensor("nct6798-isa-0290 in0", 0.71), _sensor("nct6798-isa-0290 Array Fan", 0),
    _sensor("nct6798-isa-0290 SYSTIN", 29), _sensor("nct6798-isa-0290 MB Temp", 38.5),
    _sensor("nct6798-isa-0290 AUXTIN0", 85, status="WARNING"), _sensor("nct6798-isa-0290 AUXTIN2", -62),
    _sensor("nct6798-isa-0290 TSI0_TEMP", 74.38), _sensor("k10temp-pci-00c3 Tctl", 74.75),
    _sensor("k10temp-pci-00c3 Tccd1", 75.5), _sensor("nvme-pci-0100 Sensor 2", 46.85, 50, 60, type_="NVME"),
    _sensor("ST00000NT001-TEST", 31, 50, 60, type_="DISK"),
]


def test_temperatures_trust_only_cpu_and_board_sensors(tmp_path):
    c = cfg(tmp_path)
    c.temp_grace_minutes = 0  # sensor selection only; the spike grace period has its own test

    def check(sensors):
        g = FakeGQL([{"name": "x", "status": "DISK_OK"}], sensors=sensors)
        return {f.key: f for f in Checks(FakeMCP(unraid_disk_list=[]), State(c.state_path), c, NOW, g).run()}

    assert check(REAL_SENSORS) == {}  # AUXTIN0's bogus 85°C WARNING is ignored
    # A hot CPU alerts once, via Tctl; the board's TSI0 copy of the same reading is not a second alert.
    hot_cpu = [s for s in REAL_SENSORS if "TSI0" not in s["name"] and "Tctl" not in s["name"]] + [
        _sensor("nct6798-isa-0290 TSI0_TEMP", 82), _sensor("k10temp-pci-00c3 Tctl", 81)]
    assert set(check(hot_cpu)) == {"temp:k10temp-pci-00c3 Tctl"}
    hot = REAL_SENSORS + [_sensor("k10temp-pci-00c3 Tccd2", 83), _sensor("coretemp-isa-0000 Package id 0", 95, crit=None,
                                                                                 status="CRITICAL")]
    fs = check(hot)
    assert set(fs) == {"temp:k10temp-pci-00c3 Tccd2", "temp:coretemp-isa-0000 Package id 0"}
    assert fs["temp:k10temp-pci-00c3 Tccd2"].severity == "warning" and "warn ≥ 80°C" in fs["temp:k10temp-pci-00c3 Tccd2"].summary
    pkg = fs["temp:coretemp-isa-0000 Package id 0"]
    assert pkg.severity == "error" and pkg.escalate and "Unraid's limit" in pkg.summary
    c.temp_sensors = ""
    assert check(hot) == {}  # empty TEMP_SENSORS disables the check


def test_cpu_temp_spike_waits_out_the_grace_period(tmp_path):
    c = cfg(tmp_path)  # default TEMP_GRACE_MINUTES=10
    state = State(c.state_path)
    tctl = "k10temp-pci-00c3 Tctl"

    def check(value, minutes):
        g = FakeGQL([{"name": "x", "status": "DISK_OK"}], sensors=[_sensor(tctl, value)])
        now = NOW + timedelta(minutes=minutes)
        return {f.key: f for f in Checks(FakeMCP(unraid_disk_list=[]), state, c, now, g).run()}

    assert check(85, 0) == {}  # a spike from a job: no alert yet
    assert check(60, 5) == {}  # cooled down within the grace period: never alerts
    assert check(85, 10) == {}  # a new spike starts a new grace period
    assert check(86, 15) == {}
    f = check(91, 20)[f"temp:{tctl}"]  # still hot 10 min later: alert
    assert f.severity == "error" and "Hot for 10 min" in f.summary
    assert check(60, 25) == {} and state["temp_hot"] == {}


def test_docker_update_notices(tmp_path):
    c = cfg(tmp_path)
    rows = [{"names": ["/nzbhydra2"], "state": "RUNNING", "sizeRw": "1000", "sizeLog": "10", "isUpdateAvailable": True},
            {"names": ["/plex"], "state": "RUNNING", "sizeRw": "1000", "sizeLog": "10", "isUpdateAvailable": False}]
    g = FakeGQL([{"name": "x", "status": "DISK_OK"}], containers=rows)
    [f] = Checks(FakeMCP(unraid_disk_list=[]), State(c.state_path), c, NOW, g).run()
    assert f.key == "docker:nzbhydra2:update" and f.once and f.severity == "info"
    c.docker_updates = False
    assert Checks(FakeMCP(unraid_disk_list=[]), State(c.state_path), c, NOW, g).run() == []


def test_nut_ups_events_in_syslog(tmp_path):
    lines = ["Oct 23 upsmon[2211]: UPS ups@localhost on battery",
             "Oct 23 upsmon[2211]: UPS ups@localhost on line power",
             "Oct 23 upsmon[2211]: UPS ups@localhost battery is low",
             "Oct 23 upsmon[2211]: Communications with UPS ups@localhost lost"]
    [f] = run(FakeMCP(unraid_syslog={"entries": lines}), tmp_path)
    assert f.escalate and len(f.details["lines"]) == 3  # "on line power" is the recovery, not an alert


def test_docker_sizes_and_growth(tmp_path):
    c = cfg(tmp_path, docker_ignore=["noisy"])
    st = State(c.state_path)
    GB = 10**9
    base = [{"names": ["/npmplus"], "state": "RUNNING", "sizeRw": str(int(0.15 * GB)), "sizeLog": "1000"},
            {"names": ["/plex"], "state": "RUNNING", "sizeRw": str(6 * GB), "sizeLog": str(int(1.5 * GB))},
            {"names": ["/noisy"], "state": "RUNNING", "sizeRw": str(50 * GB), "sizeLog": str(9 * GB)}]

    def cycle(containers, when):
        g = FakeGQL([{"name": "x", "status": "DISK_OK"}], containers=containers)
        return {f.key: f for f in Checks(FakeMCP(unraid_disk_list=[]), st, c, when, g).run()}

    fs = cycle(base, NOW)
    assert set(fs) == {"docker:plex:rw", "docker:plex:log"}  # noisy is ignored; npmplus is small
    assert fs["docker:plex:rw"].escalate and "6.0 GB" in fs["docker:plex:rw"].summary
    grown = copy.deepcopy(base)
    grown[0]["sizeRw"] = str(int(2.4 * GB))  # npmplus +2.25 GB
    fs = cycle(grown, NOW + timedelta(minutes=10))  # +2.25 GB within the 24 h window, however fast, is growth
    assert fs["docker:npmplus:growth"].escalate and "grew 2.2 GB" in fs["docker:npmplus:growth"].summary
    assert "docker:npmplus:growth" in cycle(grown, NOW + timedelta(hours=3))
    assert len(st["docker_sizes"]["npmplus"]) == 2  # sampled about hourly, not every cycle
    # 25 h later the old baseline has aged out, so steady 2.4 GB is no longer "growth"
    assert "docker:npmplus:growth" not in cycle(grown, NOW + timedelta(hours=28))
    cycle([b for b in grown if b["names"] != ["/npmplus"]], NOW + timedelta(hours=29))
    assert "npmplus" not in st["docker_sizes"]  # removed containers drop out of history


def test_smart_status(tmp_path):
    from unraid_agent.graphql import GraphQLError
    c = cfg(tmp_path)
    st = State(c.state_path)
    sdd = {"device": "/dev/sdd", "vendor": "Seagate", "name": "ST00000NT001-TEST", "serialNum": "ZXTEST01",
           "smartStatus": "UNKNOWN", "isSpinning": True, "temperature": 32}
    ok = {"device": "/dev/sda", "vendor": "Seagate", "name": "ST00000NT001-TEST", "serialNum": "ZXTEST02",
          "smartStatus": "OK", "isSpinning": True}
    # on a real server the API reported isSpinning=false for every disk, so it must not suppress a failing one.
    not_spinning = {"device": "/dev/sdb", "serialNum": "ZXTEST03", "smartStatus": "UNKNOWN", "isSpinning": False}

    def cycle(physical):
        return {f.key: f for f in Checks(FakeMCP(unraid_disk_list=[]), st, c, NOW, FakeGQL([{"name": "x", "status": "DISK_OK"}],
                                                                                           physical=physical)).run()}
    assert cycle([sdd, ok, not_spinning]) == {}  # first non-OK reading: wait for a second one
    fs = cycle([sdd, ok, not_spinning])
    assert set(fs) == {"smart:ZXTEST01", "smart:ZXTEST03"}
    f = fs["smart:ZXTEST01"]
    assert f.severity == "error" and f.escalate and "sdd (Seagate ST00000NT001-TEST, serial ZXTEST01)" in f.summary
    assert cycle([dict(sdd, smartStatus="OK"), ok]) == {}  # recovery resets the streak
    assert st["smart"] == {}
    assert cycle([sdd]) == {}
    # API failure is its own finding; no Unraid API configured means no SMART check at all
    fs = {f.key for f in Checks(FakeMCP(unraid_disk_list=[]), st, c, NOW,
                                FakeGQL([{"name": "x"}], smart_error=GraphQLError("HTTP 500"))).run()}
    assert fs == {"smart:unavailable"}
    assert run(FakeMCP(unraid_disk_list=[{"name": "d1", "status": "DISK_OK"}]), tmp_path) == []


def test_pool_disks_from_graphql(tmp_path):
    from unraid_agent.graphql import GraphQLError
    c = cfg(tmp_path)
    mcp = FakeMCP(unraid_disk_list=[])
    pools = [{"name": "cache", "status": "DISK_OK", "temp": 41, "fsSize": "1000", "fsUsed": "955", "numErrors": 0},
             {"name": "nvme2", "status": "DISK_INVALID", "temp": 57, "fsSize": None, "fsUsed": None, "numErrors": 3}]
    fs = {f.key: f for f in Checks(mcp, State(c.state_path), c, NOW, FakeGQL(pools)).run()}
    assert set(fs) == {"disk:cache:usage", "disk:nvme2:status", "disk:nvme2:temp", "disk:nvme2:errors"}
    assert "96%" in fs["disk:cache:usage"].summary and fs["disk:nvme2:errors"].escalate
    # API failure is reported on its own and doesn't hide unraidclaw's disks
    fs = keys(Checks(FakeMCP(unraid_disk_list=[{"name": "disk1", "status": "DISK_DSBL"}]), State(c.state_path), c, NOW,
                     FakeGQL(error=GraphQLError("HTTP 401: unauthorized"))).run())
    assert fs == {"disk:pools-unavailable", "disk:disk1:status"}


def test_per_disk_utilization_thresholds_and_zed_events(tmp_path):
    c = cfg(tmp_path)
    # Unraid's per-disk warning/critical are utilization % (a real ZFS pool had warning=85), not °C.
    # Temperature always uses the global limits (warn 50, crit 55).
    pools = [{"name": "tank", "status": "DISK_OK", "temp": 48, "warning": 85, "critical": None,
              "fsType": "zfs", "fsSize": "100", "fsUsed": "86"},
             {"name": "cache", "status": "DISK_OK", "temp": 37, "warning": 70, "critical": 90, "fsSize": "100", "fsUsed": "92"},
             {"name": "tank2", "status": "DISK_OK", "temp": None, "isSpinning": False, "fsType": "zfs"},
             {"name": "hot", "status": "DISK_OK", "temp": 56, "warning": 85}]
    fs = {f.key: f for f in Checks(FakeMCP(unraid_disk_list=[]), State(c.state_path), c, NOW, FakeGQL(pools)).run()}
    assert set(fs) == {"disk:tank:usage", "disk:cache:usage", "disk:hot:temp"}
    assert fs["disk:tank:usage"].severity == "warning" and "warn ≥ 85%" in fs["disk:tank:usage"].summary
    assert fs["disk:cache:usage"].severity == "error" and "critical ≥ 90%" in fs["disk:cache:usage"].summary
    assert fs["disk:hot:temp"].severity == "error" and "critical ≥ 55" in fs["disk:hot:temp"].summary
    lines = ["Oct 23 zed[4242]: eid=17 class=checksum pool='tank' vdev=sdc1",
             "Oct 23 zed[4242]: eid=18 class=statechange pool='tank' vdev=sdc1 vdev_state=DEGRADED",
             "Oct 23 zed[4242]: eid=19 class=statechange pool='tank' vdev=sdd1 vdev_state=ONLINE",
             "Oct 23 zed[4242]: eid=20 class=scrub_start pool='tank'"]
    [f] = run(FakeMCP(unraid_syslog={"entries": lines}), tmp_path)
    assert f.escalate and len(f.details["lines"]) == 2  # checksum + DEGRADED; ONLINE and scrub_start ignored


def test_no_disks_hint_mentions_pool_settings(tmp_path):
    [f] = run(FakeMCP(unraid_disk_list=[]), tmp_path)
    assert f.key == "disk:none" and "UNRAID_API_KEY" in f.summary


def test_graphql_client_errors():
    from unraid_agent.graphql import GraphQLError, UnraidGraphQL
    g = UnraidGraphQL("http://unraid:88/graphql", "k")
    g.http.post = lambda *a, **k: FakeResp(body={"errors": [{"message": "Invalid CSRF token"}], "data": None})
    with pytest.raises(GraphQLError, match="CSRF"):
        g.pool_disks()
    g.http.post = lambda *a, **k: FakeResp(body={"data": {"array": {"caches": [{"name": "cache"}]}}})
    assert g.pool_disks() == [{"name": "cache"}]
    assert g.http.headers["x-api-key"] == "k"


def test_vm_checks_disabled(tmp_path):
    mcp = FakeMCP(unraid_vm_list=[{"name": "win11", "state": "SHUTOFF", "autoStart": True}])
    assert run(mcp, tmp_path, check_vms=False) == []
    assert "unraid_vm_list" not in [c[0] for c in mcp.calls]
    tools = TOOLS + [{"name": "unraid_vm_list", "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}}]
    assert [t["function"]["name"] for t in read_only_tools(tools, exclude={"unraid_vm_list"})] == ["unraid_syslog"]


def test_shapes_from_unraidclaw_source(tmp_path):
    # As returned by unraidclaw 0.1.37: docker names[], syslog {entries,total}, metrics usagePercent alias.
    fs = keys(run(FakeMCP(
        unraid_docker_list=[{"id": "x", "names": ["/plex"], "image": "plex", "state": "exited", "status": "Exited (1)", "autoStart": True}],
        unraid_syslog={"entries": ["Oct 23 kernel: Buffer I/O error on dev sdb1"], "total": 1},
        unraid_system_metrics={"memory": {"usagePercent": 97}}), tmp_path))
    assert fs == {"docker:plex:down", "system:memory"} | {k for k in fs if k.startswith("syslog:")}
    assert any(k.startswith("syslog:") for k in fs)


# --- notifications & syslog ---

def test_notifications_baseline_then_forward_new(tmp_path):
    c = cfg(tmp_path)
    st = State(c.state_path)
    old = [{"id": "1", "importance": "WARNING", "title": "old"}, {"id": "2", "importance": "NORMAL", "title": "info"}]
    [f] = Checks(FakeMCP(unraid_notification_list=old), st, c, NOW).run()
    assert f.key == "notif:backlog" and "1 unread" in f.summary
    new = old + [{"id": "3", "importance": "ALERT", "title": "Disk 3", "subject": "SMART", "description": "reallocated"},
                 {"id": "4", "importance": "WARNING", "title": "done", "type": "ARCHIVE"}]
    [f] = Checks(FakeMCP(unraid_notification_list=new), st, c, NOW).run()
    assert f.key == "notif:3" and f.severity == "error" and f.escalate and "SMART" in f.summary
    assert Checks(FakeMCP(unraid_notification_list=new), st, c, NOW).run() == []


def test_syslog_new_errors_once(tmp_path):
    c = cfg(tmp_path)
    st = State(c.state_path)
    lines = "Oct 23 kernel: ata3.00: failed command: READ FPDMA QUEUED\nOct 23 kernel: fine\nOct 23 kernel: BTRFS error (device nvme0n1p1): bdev errs"
    mcp = FakeMCP(unraid_syslog=lines)
    [f] = Checks(mcp, st, c, NOW).run()
    assert f.escalate and len(f.details["lines"]) == 2
    assert ("unraid_syslog", {"lines": 300}) in mcp.calls
    assert Checks(FakeMCP(unraid_syslog=lines), st, c, NOW).run() == []


# --- system & plugins ---

def test_memory_load_and_plugins(tmp_path):
    fs = keys(run(FakeMCP(unraid_system_metrics={"memory": {"usedPercent": 95.5}, "cpuLoad": {"load15m": 20}},
                          unraid_plugins_list={"plugins": [{"name": "zfs", "version": "1", "stagedVersion": "2", "updateAvailable": True}]}),
                  tmp_path, load_warn=16))
    assert fs == {"system:memory", "system:load", "plugin:zfs:2"}


# --- notifier ---

def test_notifier_once_cleared_and_incomplete(tmp_path):
    st = State(str(tmp_path / "s.json"))
    n = Notifier([], 12, st)
    disk = Finding("disk:d1:temp", "hot", "warning")
    once = Finding("plugin:x:2", "update", "info", once=True)
    n.send([disk, once])
    assert set(st["notified"]) == {"disk:d1:temp", "plugin:x:2"}
    st["notified"]["plugin:x:2"]["ts"] -= 10**6  # long ago: once-findings still never repeat
    sent = []
    n.outbox = type("O", (), {"send": lambda s, msg: sent.append(msg.markdown()) or True})()
    n.send([disk, once])
    assert sent == []
    n.send([once], complete=False)  # disk missing because checks were unavailable: not "cleared"
    assert sent == [] and "disk:d1:temp" in st["notified"]
    n.send([once])
    assert len(sent) == 1 and "**✅ Cleared**\n• hot" in sent[0]


# --- LLM + MCP plumbing ---

TOOLS = [
    {"name": "unraid_syslog", "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object", "properties": {"lines": {"type": "number"}}}},
    {"name": "unraid_docker_restart", "annotations": {"destructiveHint": True}, "inputSchema": {"type": "object"}},
    {"name": "unraid_array_stop", "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}},  # mislabelled
    {"name": "unraid_ca_search", "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}},
]


def test_read_only_tool_filter():
    assert [t["function"]["name"] for t in read_only_tools(TOOLS)] == ["unraid_syslog"]


class ScriptedLLM:
    def __init__(self, replies):
        self.replies, self.sent = list(replies), []

    def complete(self, messages, tools):
        self.sent.append(copy.deepcopy(messages))
        return {"choices": [self.replies.pop(0)]}


def test_agent_loop_calls_only_allowed_tools(tmp_path):
    mcp = FakeMCP(unraid_syslog={"lines": ["x apikey=SECRET123 y"]})
    llm = ScriptedLLM([
        {"finish_reason": "tool_calls", "message": {"role": "assistant", "tool_calls": [
            {"id": "a", "function": {"name": "unraid_syslog", "arguments": '{"lines": 20}'}},
            {"id": "b", "function": {"name": "unraid_docker_restart", "arguments": '{"id": "plex"}'}}]}},
        {"finish_reason": "stop", "message": {"role": "assistant", "content": "1. Check cabling."}},
    ])
    out = run_agent(llm, mcp, read_only_tools(TOOLS), "problems")
    assert out == "1. Check cabling."
    assert mcp.calls == [("unraid_syslog", {"lines": 20})]
    results = {m["tool_call_id"]: m["content"] for m in llm.sent[1] if m["role"] == "tool"}
    assert "SECRET123" not in results["a"] and "not available" in results["b"]


def test_agent_tools_give_the_model_pool_smart_temps_and_sizes(tmp_path):
    from unraid_agent.escalate import AGENT_TOOLS_PROMPT, agent_tools
    gql = FakeGQL(
        pools=[{"name": "default_pool_zfs", "device": "sdd", "status": "DISK_OK", "fsType": "zfs", "temp": 32,
                "fsSize": "1000", "fsUsed": "612", "warning": 85, "critical": None, "numErrors": 0}],
        physical=[{"device": "/dev/sdd", "vendor": "Seagate", "name": "ST00000NT001-TEST", "serialNum": "ZXTEST01",
                   "smartStatus": "OK", "temperature": 32}],
        sensors=REAL_SENSORS,
        containers=[{"names": ["/npmplus"], "state": "RUNNING", "sizeRw": "150000000", "sizeLog": "1000", "isUpdateAvailable": False}],
    )
    tools = agent_tools(gql, cfg(tmp_path))
    disks = tools["agent_disk_health"][1]()
    assert disks["poolDisks"][0]["usedPercent"] == 61.2 and disks["poolDisks"][0]["usageWarnPercent"] == 85
    assert disks["physicalDisks"][0]["serial"] == "ZXTEST01"
    temps = tools["agent_temperatures"][1]()
    assert {s["name"] for s in temps["sensors"]} == {"nct6798-isa-0290 SYSTIN", "nct6798-isa-0290 MB Temp",
                                                     "k10temp-pci-00c3 Tctl", "k10temp-pci-00c3 Tccd1"}
    assert temps["excludedSensors"] == len(REAL_SENSORS) - 4  # voltages, fan, AUXTIN, TSI0, NVMe, disk
    assert tools["agent_container_sizes"][1]()[0] == {"name": "npmplus", "state": "RUNNING", "writableLayerGB": 0.15,
                                                      "logGB": 0.0, "updateAvailable": False}
    # In the loop: agent_* tools run locally (never sent to unraidclaw) and the prompt explains them.
    mcp = FakeMCP()
    llm = ScriptedLLM([
        {"finish_reason": "tool_calls", "message": {"role": "assistant", "tool_calls": [
            {"id": "a", "function": {"name": "agent_disk_health", "arguments": "{}"}}]}},
        {"finish_reason": "stop", "message": {"role": "assistant", "content": "disks fine"}},
    ])
    specs = read_only_tools(TOOLS) + [spec for spec, _ in tools.values()]
    assert run_agent(llm, mcp, specs, "p", {n: fn for n, (_, fn) in tools.items()}) == "disks fine"
    assert mcp.calls == [] and "ZXTEST01" in llm.sent[1][-1]["content"]
    assert AGENT_TOOLS_PROMPT.strip()[:20] in llm.sent[0][0]["content"]
    # SERVER_NOTES (a private repo variable) reaches the prompt without living in the code.
    llm = ScriptedLLM([{"finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}])
    run_agent(llm, mcp, specs, "p", server_notes="ZFS pool of 8 disks, no VMs")
    assert llm.sent[0][0]["content"].endswith("About this server, from its operator: ZFS pool of 8 disks, no VMs")


class FakeResp:
    def __init__(self, status=200, body=None, ctype="application/json", headers=None, text=None):
        self.status_code = status
        self.headers = {"content-type": ctype, **(headers or {})}
        self.text = text if text is not None else json.dumps(body)
        self.content = self.text.encode()

    def json(self):
        return json.loads(self.text)


def test_mcp_client_handles_sse_session_and_tool_errors():
    c = MCPClient("https://unraid:9876/mcp", "k", fingerprint="AB:CD")
    replies = [
        FakeResp(body={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "uc"}}},
                 headers={"mcp-session-id": "s1"}),
        FakeResp(status=202, text=""),
        FakeResp(ctype="text/event-stream", text='event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
                 'data: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\\"a\\": 1}"}]}}\n\n'),
        FakeResp(body={"jsonrpc": "2.0", "id": 3, "result": {"isError": True, "content": [{"type": "text", "text": "Error: INTERNAL_ERROR"}]}}),
    ]
    sent = []
    c.http.post = lambda url, json=None, timeout=None: sent.append((json, dict(c.http.headers))) or replies.pop(0)
    assert c.call_tool("unraid_x") == {"a": 1}
    assert sent[2][1]["mcp-session-id"] == "s1" and sent[2][1]["MCP-Protocol-Version"] == "2025-06-18"
    with pytest.raises(ToolError, match="INTERNAL_ERROR"):
        c.call_tool("unraid_y")


def test_mcp_client_unauthorized():
    c = MCPClient("https://unraid:9876/mcp", "bad")
    c.http.post = lambda *a, **k: FakeResp(status=401, body={"ok": False})
    with pytest.raises(MCPError, match="unauthorized"):
        c.call_tool("unraid_health_check")


# --- agent bus (MCP endpoint for the Discord bot) ---

def test_bus_tools_gate_unraidclaw_actions(tmp_path, monkeypatch):
    from unraid_agent import __main__ as main_mod
    from unraid_agent.bus import Runtime
    listed = [
        {"name": "unraid_docker_list", "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}},
        {"name": "unraid_vm_list", "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}},
        {"name": "unraid_docker_restart", "annotations": {"destructiveHint": True}, "inputSchema": {"type": "object"}},
        {"name": "unraid_docker_remove", "annotations": {"destructiveHint": True}, "inputSchema": {"type": "object"}},
        {"name": "unraid_array_stop", "annotations": {"destructiveHint": True}, "inputSchema": {"type": "object"}},
    ]
    calls = []

    class FakeClient:
        def __init__(self, *a, **k): pass
        def list_tools(self): return listed
        def call_tool(self, name, args): calls.append((name, args)); return {"ok": name}

    monkeypatch.setattr(main_mod, "MCPClient", FakeClient)
    c = cfg(tmp_path, check_vms=False)
    tools = {t.name: t for t in main_mod.bus_tools(c, Runtime("unraid"))}
    assert set(tools) == {"agent_status", "agent_last_diagnosis", "agent_run_check",
                          "unraid_docker_list", "unraid_docker_restart"}  # no VM, remove or array tools
    assert tools["unraid_docker_list"].read_only and not tools["unraid_docker_restart"].read_only
    assert tools["agent_run_check"].read_only  # notify-only agent: a check changes nothing
    assert tools["unraid_docker_restart"].fn(id="plex") == {"ok": "unraid_docker_restart"}
    assert calls == [("unraid_docker_restart", {"id": "plex"})]
    # With the Unraid API configured, the agent_* tools are on the bus too.
    c.unraid_graphql_url, c.unraid_api_key = "http://unraid/graphql", "k"
    assert {"agent_disk_health", "agent_temperatures", "agent_container_sizes"} <= {t.name for t in main_mod.bus_tools(c, Runtime("unraid"))}


def test_deploy_renders_every_setting_it_is_given():
    """Every variable/secret passed to the 'Render agent.env' step must be written to agent.env.

    Guards against adding a setting to the step's env block but not to the loop, which silently
    drops it from the deployed config.
    """
    import pathlib
    import re
    wf = (pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    step = wf.split("- name: Render agent.env", 1)[1].split("- name:", 1)[0]
    env_block, run_block = step.split("run: |", 1)
    given = set(re.findall(r"^\s+([A-Z_]+): \$\{\{ (?:vars|secrets)\.", env_block, re.M))
    loop = re.search(r"for v in (.*?); do", run_block, re.S).group(1)
    written = set(re.findall(r"[A-Z_]+", loop))
    assert given - written == set(), f"passed to the step but never written to agent.env: {sorted(given - written)}"


def test_health_fails_when_a_loop_is_overdue_or_an_endpoint_is_down(tmp_path, monkeypatch):
    from unraid_agent import health

    monkeypatch.setenv("HEALTH_DIR", str(tmp_path / "health"))
    assert health.check()[0] == ["nothing has checked in yet"]
    health.beat("main", 60)
    problems, fine = health.check()
    assert not problems and fine[0].startswith("main ran")
    health.beat("slow", -5)
    assert health.check()[0][0].startswith("slow: overdue by 5s")
    health.reset()
    health.beat("main", 60)
    health.endpoint("bus", "http://127.0.0.1:9/health")  # nothing listens on the discard port
    problems, _ = health.check(timeout=2)
    assert len(problems) == 1 and problems[0].startswith("bus: ")


def test_discord_posts_are_sent_under_the_agents_own_name(monkeypatch):
    from unraid_agent import notice

    posted = []
    monkeypatch.setattr(notice, "_post_webhook", lambda url, payload: posted.append(payload) or True)
    url = "https://discord.com/api/webhooks/" + "1/fake-TOKEN"  # split so the public-sync secret scan passes
    assert notice.Outbox([url]).send(notice.Message("hi"))
    notice.Outbox([url], username="Someone else").send(notice.Message("hi"))
    assert [p["username"] for p in posted] == ["unraid-agent", "Someone else"]
    assert posted[0]["avatar_url"].endswith("/png/unraid.png")


def test_temperatures_follow_unraid_labels_and_cpu_limits(tmp_path):
    c = cfg(tmp_path)
    c.temp_grace_minutes = 0
    # What Unraid's System Temp plugin labels: k10temp temp1 is "CPU Temp", the dashboard's CPU reading.
    sensors = [_sensor("k10temp-pci-00c3 CPU Temp", 81, status="WARNING"), _sensor("k10temp-pci-00c3 Tccd1", 87,
               status="WARNING"), _sensor("nct6798-isa-0290 MB Temp", 31), _sensor("nct6798-isa-0290 CPUTIN", 82)]

    def check(sensors):
        g = FakeGQL([{"name": "x", "status": "DISK_OK"}], sensors=sensors)
        return {f.key: f for f in Checks(FakeMCP(unraid_disk_list=[]), State(c.state_path), c, NOW, g).run()}

    # auto: only Unraid's labelled sensors; Tccd1 and CPUTIN aren't what Unraid shows
    assert set(check(sensors)) == {"temp:k10temp-pci-00c3 CPU Temp"}
    c.cpu_temp_warn, c.cpu_temp_crit = 90, 95  # the CPU's own limits replace Unraid's generic 80/90 and its status
    assert check(sensors) == {}
    hot = [_sensor("k10temp-pci-00c3 CPU Temp", 92)] + sensors[1:]
    f = check(hot)["temp:k10temp-pci-00c3 CPU Temp"]
    assert f.severity == "warning" and "warn ≥ 90°C" in f.summary
    assert check([_sensor("k10temp-pci-00c3 CPU Temp", 96)])["temp:k10temp-pci-00c3 CPU Temp"].severity == "error"
    assert set(check([_sensor("nct6798-isa-0290 MB Temp", 85)] + sensors[:1])) == {"temp:nct6798-isa-0290 MB Temp"}
