"""LLM diagnosis via OpenCode Go, using unraidclaw's read-only MCP tools plus the agent's own.

Only MCP tools that are BOTH on READ_ONLY_TOOLS and annotated readOnlyHint by the server are
offered to the model, so a server-side annotation change can't widen what the model may do.
With an Unraid API key, the agent_* tools add what unraidclaw can't see (pool disks, SMART,
trusted temperature sensors, container sizes); they are read-only queries too.
OPENCODE_MODEL must be a Chat Completions model on Go (glm-*, kimi-*, deepseek-*, ...).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from typing import Any, Callable

import requests

from .checks import number
from .config import Config
from .findings import Finding
from .graphql import GraphQLError, UnraidGraphQL
from .mcp import MCPClient, MCPError
from .state import State

log = logging.getLogger(__name__)

USER_AGENT = "unraid-health-agent/1.0"
MAX_TURNS = 15
MAX_RESULT_CHARS = 12000
SECRET_RE = re.compile(r"(?i)(api[_-]?key|apikey|token|password|passwd|secret)([\"'=:\s]+)([^\s&\"',}]+)")

READ_ONLY_TOOLS = {
    "unraid_health_check", "unraid_array_status", "unraid_parity_status", "unraid_disk_list",
    "unraid_disk_details", "unraid_docker_list", "unraid_docker_inspect", "unraid_docker_logs",
    "unraid_vm_list", "unraid_vm_inspect", "unraid_share_list", "unraid_share_details",
    "unraid_system_info", "unraid_system_metrics", "unraid_service_list", "unraid_notification_list",
    "unraid_network_info", "unraid_syslog", "unraid_plugins_list", "unraid_plugin_info",
}

VM_TOOLS = {"unraid_vm_list", "unraid_vm_inspect"}

SYSTEM_PROMPT = """You are the on-call diagnostician for a home Unraid server that runs \
Docker containers (including the *arr media stack). A rule-based monitor found the problems \
below. You have read-only tools that query the server through its unraidclaw MCP API; you cannot \
change anything.

Investigate with the tools before concluding: check the syslog around the time of the problem, \
container logs and inspect output for stopped or unhealthy containers, disk status and \
temperatures for disk issues. Common root causes: failing or overheating disks (SMART, CRC/link \
errors), a full cache or array disk, a container whose appdata or image path is missing, \
port conflicts, out-of-memory kills, and the Unraid API service (unraid-api) being down.

Your reply is sent as a push notification, so keep it under 200 words of plain text: one line per \
problem with the likely cause, then numbered concrete steps for the human (exact Unraid page, \
command, or setting). Say plainly when evidence is inconclusive rather than guessing. Never \
recommend stopping the array, rebooting, or a correcting parity check without stating the risk."""

AGENT_TOOLS_PROMPT = """

unraidclaw's disk and array tools list only array and parity disks, so on a server that keeps its \
disks only in pools (such as a ZFS pool) they return empty lists. That is not \
missing data. Use agent_disk_health for disks and SMART, agent_temperatures for CPU and board \
temperatures, and agent_container_sizes for what is filling docker.img; they read Unraid's own API."""


def _gb(v: Any) -> float | None:
    n = number(v)
    return round(n / 1e9, 2) if n is not None else None


def agent_tools(gql: UnraidGraphQL, cfg: Config) -> dict[str, tuple[dict, Callable[[], Any]]]:
    """Read-only tools backed by the agent's direct Unraid API access: name -> (spec, function)."""

    def disk_health() -> dict:
        pools = []
        for p in gql.pool_disks():
            size, used = number(p.get("fsSize")), number(p.get("fsUsed"))
            pools.append({
                "name": p.get("name"), "device": p.get("device"), "status": p.get("status"), "fsType": p.get("fsType"),
                "tempC": p.get("temp"), "usedPercent": round(used / size * 100, 1) if size and used is not None else None,
                "usageWarnPercent": p.get("warning"), "usageCritPercent": p.get("critical"), "errors": p.get("numErrors"),
            })
        physical = [{"device": d.get("device"), "model": " ".join(str(x) for x in (d.get("vendor"), d.get("name")) if x),
                     "serial": d.get("serialNum"), "smart": d.get("smartStatus"), "tempC": d.get("temperature")}
                    for d in gql.physical_disks()]
        return {"poolDisks": pools, "physicalDisks": physical,
                "notes": "Pool usage is reported on each pool's first device only. smart is OK or UNKNOWN; "
                         "Unraid reports a failing self-assessment as UNKNOWN."}

    def temperatures() -> dict:
        wanted = re.compile(cfg.temp_sensors, re.I) if cfg.temp_sensors else None
        trusted, excluded = [], 0
        for s in gql.temperature_sensors():
            name = str(s.get("name") or "")
            if s.get("type") in ("DISK", "NVME") or not wanted or not wanted.search(name):
                excluded += 1
                continue
            cur = s.get("current") or {}
            trusted.append({"name": name, "value": cur.get("value"), "unit": cur.get("unit"), "status": cur.get("status"),
                            "warning": s.get("warning"), "critical": s.get("critical")})
        return {"sensors": trusted, "excludedSensors": excluded,
                "notes": "Only CPU and board sensors the monitor trusts. Excluded: disks/NVMe (see agent_disk_health) "
                         "and Super-I/O voltage inputs, fans and unconnected AUXTIN headers that report bogus values."}

    def container_sizes() -> list[dict]:
        rows = [{"name": str((r.get("names") or ["?"])[0]).lstrip("/"), "state": r.get("state"),
                 "writableLayerGB": _gb(r.get("sizeRw")), "logGB": _gb(r.get("sizeLog")),
                 "updateAvailable": r.get("isUpdateAvailable")} for r in gql.container_sizes()]
        return sorted(rows, key=lambda r: -(r["writableLayerGB"] or 0))

    def spec(name: str, description: str) -> dict:
        return {"type": "function", "function": {
            "name": name, "description": description,
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}}

    return {
        "agent_disk_health": (spec("agent_disk_health",
                                   "Pool and array disks (status, temperature, usage %, errors) and SMART status, model "
                                   "and serial of every physical disk, from Unraid's own API."), disk_health),
        "agent_temperatures": (spec("agent_temperatures",
                                    "CPU and board temperature sensors with Unraid's warning/critical limits "
                                    "(trusted sensors only)."), temperatures),
        "agent_container_sizes": (spec("agent_container_sizes",
                                       "Per-container writable layer and log size in GB and image update availability, "
                                       "largest writable layer first."), container_sizes),
    }


def _redact(text: str) -> str:
    return SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", text)


def _fingerprint(findings: list[Finding]) -> str:
    return hashlib.sha256("|".join(sorted(f.key for f in findings)).encode()).hexdigest()[:16]


def read_only_tools(mcp_tools: list[dict], exclude: set[str] = frozenset()) -> list[dict]:
    """OpenAI function specs for the allowed read-only MCP tools."""
    specs = []
    for t in mcp_tools:
        if t.get("name") in exclude:
            continue
        if t.get("name") in READ_ONLY_TOOLS and (t.get("annotations") or {}).get("readOnlyHint") is True:
            specs.append({"type": "function", "function": {
                "name": t["name"],
                "description": (t.get("description") or "")[:1000],
                "parameters": t.get("inputSchema") or {"type": "object", "properties": {}},
            }})
    return specs


class OpenCodeGo:
    """Minimal OpenAI-compatible Chat Completions client for OpenCode Go."""

    def __init__(self, cfg: Config):
        self.url = cfg.opencode_base_url.rstrip("/") + "/chat/completions"
        self.model = cfg.opencode_model
        self.http = requests.Session()
        self.http.headers.update({
            "Authorization": f"Bearer {cfg.opencode_api_key}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            # Required by OpenCode Go: one stable id per conversation.
            "x-opencode-session": str(uuid.uuid4()),
        })

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        body = {"model": self.model, "messages": messages, "tools": tools, "tool_choice": "auto", "max_tokens": 4096}
        for attempt in range(3):
            resp = self.http.post(self.url, json=body, timeout=180)
            if (resp.status_code == 429 or resp.status_code >= 500) and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            if resp.status_code >= 400:
                raise RuntimeError(f"OpenCode Go {resp.status_code}: {resp.text[:300]}")
            return resp.json()
        raise RuntimeError("unreachable")


def run_agent(client: OpenCodeGo, mcp: MCPClient, tools: list[dict], problems: str,
              local: dict[str, Callable[[], Any]] | None = None) -> str | None:
    """`tools` holds every spec offered (MCP and agent_*); `local` maps agent_* names to their functions."""
    local = local or {}
    allowed = {t["function"]["name"] for t in tools}
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT + (AGENT_TOOLS_PROMPT if local else "")},
        {"role": "user", "content": f"Problems found this cycle:\n{problems}"},
    ]
    for _ in range(MAX_TURNS):
        choice = client.complete(messages, tools)["choices"][0]
        msg = choice["message"]
        calls = msg.get("tool_calls") or []
        # Echo the assistant turn back unchanged (some reasoning models require their reasoning field).
        messages.append({k: v for k, v in msg.items() if v is not None})
        if not calls:
            text = (msg.get("content") or "").strip()
            if choice.get("finish_reason") == "length":
                text += "\n[truncated]"
            return text or None
        for call in calls:
            name = call.get("function", {}).get("name")
            try:
                args = json.loads(call.get("function", {}).get("arguments") or "{}")
                if name not in allowed:
                    result = f"Error: tool {name} is not available"
                else:
                    data = local[name]() if name in local else mcp.call_tool(name, args)
                    result = data if isinstance(data, str) else json.dumps(data, default=str)
            except json.JSONDecodeError as exc:
                result = f"Error: invalid arguments ({exc})"
            except (MCPError, GraphQLError, requests.RequestException) as exc:
                result = f"Error: {exc}"
            if len(result) > MAX_RESULT_CHARS:
                result = result[:MAX_RESULT_CHARS] + f"\n[truncated {len(result) - MAX_RESULT_CHARS} chars]"
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": _redact(result)})
    log.warning("Diagnosis stopped after %d turns without a final answer", MAX_TURNS)
    return None


def escalate(mcp: MCPClient, state: State, cfg: Config, findings: list[Finding],
             gql: UnraidGraphQL | None = None) -> str | None:
    pending = [f for f in findings if f.escalate]
    if not pending or not cfg.escalation_enabled:
        return None
    fp = _fingerprint(pending)
    if state.within("escalated", fp, cfg.escalate_cooldown_hours):
        log.info("Escalation for this issue set already sent within %sh; skipping", cfg.escalate_cooldown_hours)
        return None

    problems = _redact(json.dumps([{"summary": f.summary, "details": f.details} for f in pending], default=str))
    try:
        tools = read_only_tools(mcp.list_tools(), exclude=set() if cfg.check_vms else VM_TOOLS)
        extra = agent_tools(gql, cfg) if gql else {}
        tools += [spec for spec, _ in extra.values()]
        text = run_agent(OpenCodeGo(cfg), mcp, tools, problems, {name: fn for name, (_, fn) in extra.items()})
    except (requests.RequestException, MCPError, RuntimeError, KeyError, IndexError, ValueError) as exc:
        log.error("Diagnosis via OpenCode Go failed: %s", exc)
        return None
    state.mark("escalated", fp)
    return text
