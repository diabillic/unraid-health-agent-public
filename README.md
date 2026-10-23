# unraid-health-agent

A notify-only monitor for an Unraid server. It talks to the server through the
unraidclaw MCP server (`https://<unraid>:9876/mcp`, Streamable HTTP, `x-api-key` auth), reports problems
to Apprise targets (Discord, etc.), and asks an LLM via OpenCode Go to diagnose anything serious
using **read-only** tools. It never changes the server.

## What it checks each cycle

| Area | Reported when | Sent for diagnosis |
|---|---|---|
| unraidclaw | MCP unreachable, auth/TLS-pin failure, or `degraded` (Unraid GraphQL API down) | no |
| Array | state is not `STARTED` | yes |
| Disks (array, parity, and pools via `UNRAID_API_KEY`) | status not `DISK_OK`/`DISK_NP`; temp ≥ `DISK_TEMP_WARN`/`DISK_TEMP_CRIT`; usage ≥ the disk's own Unraid utilization warning/critical % (else `DISK_USAGE_WARN`); read/write errors | status, errors |
| SMART (via `UNRAID_API_KEY`) | a spinning disk's SMART status isn't `OK` for `SMART_UNKNOWN_CYCLES` checks in a row (default 2). Unraid's API reports a failing self-assessment as `UNKNOWN`. `isSpinning` is ignored because the API reports it false for every disk, while drives in standby still read `OK`. Named by device, model and serial | yes |
| Parity | last check had errors or ended abnormally; older than `PARITY_MAX_AGE_DAYS`; none on record | errors |
| Docker | autostart container not running; running → stopped since last cycle; unhealthy; restarting | yes |
| CPU/board temperatures (via `UNRAID_API_KEY`) | a sensor matching `TEMP_SENSORS` reaches its Unraid warning/critical limit or status. The default list covers CPU (k10temp/coretemp Tctl, Tccd, Package) and board (SYSTIN, CPUTIN, MB Temp) sensors; Super-I/O voltage inputs, fans, unconnected AUXTIN headers and TSI (a duplicate of Tctl) are ignored, and disks/NVMe are covered by the disk check | yes |
| Container updates (via `UNRAID_API_KEY`, `DOCKER_UPDATES`) | an image update is available (once per container) | no |
| UPS (NUT) | `upsmon` syslog events: on battery, battery low, communications lost, replace battery, forced shutdown. Unraid's API only reads apcupsd, so NUT isn't visible there | yes |
| Docker image usage (via `UNRAID_API_KEY`) | a container's writable layer ≥ `DOCKER_RW_WARN_GB` (5), its log ≥ `DOCKER_LOG_WARN_GB` (1), or its writable layer grew ≥ `DOCKER_RW_GROWTH_GB` (2) within 24 h. The API has no docker.img % figure, so this catches the causes; Unraid's own docker.img utilization notifications are forwarded too | writable layer and growth |
| VMs (off when `CHECK_VMS=false`) | autostart VM not running; running → stopped; paused; crashed | yes |
| Unraid notifications | new unarchived `warning`/`alert` (first run only summarises the backlog) | alerts |
| Syslog | new lines matching disk I/O, ATA link, BTRFS/XFS/EXT4, MCE, OOM, NVMe patterns | yes |
| System | memory ≥ `MEM_WARN_PERCENT`; 15-min load ≥ `LOAD_WARN` (if set) | memory |
| Plugins | update available (once per version) | no |

**Notifications:** one digest per cycle. New issues are sent immediately and repeated every
`RENOTIFY_HOURS` while they persist. One-off items (forwarded notices, syslog batches, plugin
updates) are sent once. When an issue goes away you get `✅ Cleared`. A cycle where some checks
couldn't run (unraidclaw degraded or down) never counts as "cleared".

## unraidclaw prerequisites

Reference: [emaspa/unraidclaw](https://github.com/emaspa/unraidclaw) (built against v0.1.37).

- **MCP enabled:** Settings > UnraidClaw > Enable MCP. It's off by default.
- **Unraid API key (ADMIN role)** in Settings > UnraidClaw > Unraid API Key. unraidclaw uses it to
  query `GRAPHQL_URL` (built from "Unraid WebUI Port", default `http://localhost/graphql`). Without it,
  `unraid_health_check` reports `degraded` / `graphqlReachable: false`, and every GraphQL-backed tool
  (array, disks, Docker, VMs, shares, notifications, system info) fails with `INTERNAL_ERROR`. The
  agent reports this as one finding with these fix steps.
- **Pool disks are not in unraidclaw 0.1.37.** Its disk and array tools query only
  `array.disks` and `array.parities`, so a pool-only server shows no disks. Until that changes
  upstream, the agent reads pools (`array.caches`) straight from Unraid's GraphQL API when
  `UNRAID_GRAPHQL_URL` and `UNRAID_API_KEY` are set. Use a read-only Unraid API key, separate
  from unraidclaw's ADMIN key.
- **Read permissions** for the agent's key on the Permissions tab: array, disks, docker, vms,
  notifications, logs, system, plugins. A denial (`FORBIDDEN: Permission denied: docker:read`) is
  reported once, naming the exact grants missing.

## LLM diagnosis (OpenCode Go)

With `OPENCODE_API_KEY` set, the issues marked "yes" above go to `OPENCODE_MODEL` (default `glm-5.2`).
The model may call only unraidclaw tools that are **both** on the agent's read-only allowlist
(`escalate.py: READ_ONLY_TOOLS`) **and** annotated `readOnlyHint` by the server: health, array,
parity, disks, Docker list/inspect/logs, VMs, shares, system, services, notifications, network,
syslog, plugins. Results are redacted and truncated. The same issue set is diagnosed at most once
per `ESCALATE_COOLDOWN_HOURS`.

## TLS

unraidclaw uses a self-signed certificate. Rather than turning verification off, the agent
pins its SHA-256 fingerprint (`UNRAIDCLAW_TLS_FINGERPRINT`). unraidclaw never replaces a
certificate that already has subject alternative names, so the pin only breaks when someone clicks
**Regenerate certificate** (Settings > UnraidClaw > TLS Certificate, which also shows the new
fingerprint). The agent then reports a fingerprint mismatch until you update the variable. The
command to compute the fingerprint is in `.env.example`.

## Deployment

Same pattern as [sonarr-health-agent-public](../../../sonarr-health-agent-public): a systemd service
in an unprivileged Proxmox LXC, deployed by GitHub Actions through a self-hosted runner in a
second LXC.

```
 GitHub ──push──▶ runner LXC (gh-runner, runner instance /opt/actions-runner-<repo>)
                    └─ssh deploy@──▶ unraid-agent LXC ──https:9876/mcp──▶ unraidclaw on Unraid
```

Each push to `main` runs the tests on a GitHub-hosted runner and then, once `AGENT_HOST` is set,
deploys through the root-owned installer `/usr/local/sbin/unraid-agent-install`. The installer
rebuilds the venv when requirements change, writes the systemd unit, and rolls back if the
service isn't up after 20 seconds. Pull requests only run the tests.

One-time setup, from an admin workstation with root SSH to Proxmox and `gh` logged in, inside
your clone:

```bash
PVE_HOST=root@<proxmox-ip> deploy/provision.sh   # STORAGE=, BRIDGE=, VLAN=, RUNNER_CTID=, AGENT_CTID= to override
```

It creates (or reuses, by hostname) a `gh-runner` LXC and registers a runner instance for this
repository, creates the agent LXC, authorises the runner's deploy key on it, and sets
`AGENT_HOST`. Several repositories can share one runner LXC, each with its own instance
directory. The repository is detected from the clone; set `GH_REPO=owner/name` to override.
Re-run it after changing the installer.

### Self-hosted runners and public repositories

GitHub advises against attaching self-hosted runners to public repositories, because a pull
request from a fork could run code on your hardware. This workflow runs tests on GitHub-hosted
runners and never runs the deploy job for pull requests, but to be safe:

- Deploy from a **private** copy of this repository, or
- If you keep it public, set Settings → Actions → General → "Fork pull request workflows" to
  require approval for all outside collaborators, and never add the `self-hosted` label to a job
  that runs on `pull_request`.

## Secrets and variables (required before the first deploy)

This repository contains **no secrets**. Add them yourself under **GitHub → Settings → Secrets and
variables → Actions** before the first deploy. The deploy job stops with a clear error if a
required value is missing. Every setting is also documented in `.env.example`.

### Secrets

| Secret | Required | Expected value |
|---|---|---|
| `UNRAIDCLAW_API_KEY` | **yes** | The unraidclaw API key generated under Unraid → Settings → UnraidClaw → API Key Management (shown once). Give it read permissions for array, disks, docker, vms, notifications, logs, system and plugins. |
| `UNRAID_API_KEY` | recommended | A **VIEWER**-role Unraid API key from Unraid → Settings → Management Access → API. Enables pool disks, SMART, CPU/board temperatures, Docker image usage and container update checks. Don't reuse unraidclaw's ADMIN key. |
| `NOTIFY_URLS` | recommended | One or more [Apprise](https://github.com/caronc/apprise/wiki) URLs, comma separated, e.g. `discord://<webhook_id>/<webhook_token>`, `ntfy://ntfy.sh/<topic>`. Without it, findings only go to the agent's log. |
| `OPENCODE_API_KEY` | optional | An [OpenCode](https://opencode.ai/console) API key on the Go plan. Enables LLM diagnosis. |

### Variables

| Variable | Required | Expected value |
|---|---|---|
| `AGENT_HOST` | **yes** | IP or hostname of the agent LXC. `provision.sh` sets it; the deploy job is skipped until it exists. |
| `UNRAIDCLAW_URL` | **yes** | unraidclaw's MCP endpoint, e.g. `https://192.168.1.10:9876/mcp` (HTTPS; enable MCP in unraidclaw's settings). |
| `UNRAIDCLAW_TLS_FINGERPRINT` | recommended | SHA-256 of unraidclaw's certificate as 64 hex characters (see TLS). Without it, TLS is verified normally, which fails for the default self-signed certificate. |
| `UNRAID_GRAPHQL_URL` | with `UNRAID_API_KEY` | Unraid's GraphQL endpoint on the **WebGUI's HTTP port**, e.g. `http://192.168.1.10/graphql`, or `http://192.168.1.10:88/graphql` if the WebGUI was moved off port 80 (common when a reverse proxy owns 80/443). |
| `CHECK_VMS` | optional | `true` (default); `false` if the server runs no VMs. |
| `SERVER_NOTES` | optional | Free text about your server added to the diagnosis prompt, e.g. `ZFS pool of 8 disks, btrfs cache, no VMs, WebGUI on port 88`. Keeps server specifics out of the code. |
| `DOCKER_IGNORE`, `VM_IGNORE` | optional | Comma-separated container / VM names never to report. |
| thresholds, `NOTIFICATION_LEVELS`, `TEMP_SENSORS`, `DOCKER_UPDATES`, `SMART_UNKNOWN_CYCLES`, `INTERVAL_MINUTES`, `RENOTIFY_HOURS`, `OPENCODE_MODEL` | optional | Overrides; see `.env.example` for defaults. |

Changing a variable or secret takes effect on the next deploy: re-run the workflow
(Actions → test-and-deploy → Run workflow).

### Operating

```bash
ssh root@<agent-ip> journalctl -u unraid-agent -f
cat /opt/unraid-agent/app/REVISION
```

## Agent bus (MCP for an assistant such as Hermes Agent)

Optional. When `AGENT_BUS_TOKEN` is set, the agent serves its tools at `http://<agent>:8765/mcp`
(Streamable HTTP MCP, bearer token) so an assistant you chat with, for example
[Hermes Agent](https://hermes-agent.nousresearch.com) on Discord, can answer questions with live
data: `agent_status`, `agent_last_diagnosis`, `agent_run_check` and the agent's domain tools.

**Actions need your approval, enforced by the agent.** MCP clients generally run any tool their
model picks, so destructive tools (the unraidclaw tools listed in `BUS_ACTION_TOOLS` (default `unraid_docker_start,unraid_docker_restart`; the unraidclaw key needs the matching docker update permission)) never run directly. A call creates a pending action
and the agent sends a **one-time 6-digit code** to `APPROVAL_NOTIFY_URLS`, which must be a channel
your assistant **cannot read**. The model is told to ask you for it; when you give it the code it
calls `confirm_action(action_id, code)`, which runs exactly the stored call. Codes expire after 15
minutes, work once, and three wrong codes cancel the action. Without `APPROVAL_NOTIFY_URLS`,
actions are refused.

| Kind | Name | Expected value |
|---|---|---|
| secret | `AGENT_BUS_TOKEN` | A long random string, also given to your MCP client as `Authorization: Bearer <token>`. Unset disables the endpoint. |
| secret | `APPROVAL_NOTIFY_URLS` | Apprise URL(s) for a channel the assistant can't see, e.g. a Discord webhook `https://discord.com/api/webhooks/<id>/<token>` for a channel where the assistant's bot is denied View Channel. |
| variable | `AGENT_BUS_PORT` | optional, default `8765` |
| variable | `BOT_ALERT_URL` | optional: POST alerts to a bot endpoint instead of `NOTIFY_URLS` (falls back to `NOTIFY_URLS`) |
| variable | `BUS_ACTION_TOOLS` | optional, see above |

Example Hermes `~/.hermes/config.yaml` entry (token kept in `~/.hermes/.env`):

```yaml
mcp_servers:
  unraid:
    url: "http://192.168.1.21:8765/mcp"
    headers:
      Authorization: "Bearer ${AGENT_BUS_TOKEN}"
    timeout: 180
```

## Develop

```bash
pip install -r requirements.txt pytest
python -m pytest -q
python -m unraid_agent --once   # with UNRAIDCLAW_* and STATE_PATH exported
```
