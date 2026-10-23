"""Entry point: python -m unraid_agent [--once]"""

from __future__ import annotations

import argparse
import logging
import os
import threading
from datetime import datetime, timezone

import requests

from .bus import Approvals, BusTool, Runtime, serve_mcp
from .checks import Checks
from .config import Config
from .escalate import READ_ONLY_TOOLS, VM_TOOLS, agent_tools, escalate
from .findings import Finding
from .graphql import UnraidGraphQL
from .mcp import MCPClient, MCPError
from .notify import Notifier
from .state import State

log = logging.getLogger("unraid_agent")

INCOMPLETE_KEYS = {"mcp:down", "mcp:degraded", "mcp:tools-failing", "mcp:permissions"}


def bus_tools(cfg: Config, runtime: Runtime) -> list[BusTool]:
    """What the Discord bot may call: status, unraidclaw's read-only tools, the agent's own Unraid
    API tools, and the configured unraidclaw actions (destructive: the bot asks before each)."""
    tools = runtime.common_tools(check_is_destructive=False)  # this agent only reads and notifies
    client = MCPClient(cfg.mcp_url, cfg.mcp_api_key, fingerprint=cfg.mcp_fingerprint, verify_tls=cfg.mcp_verify_tls)
    lock = threading.Lock()  # one bus client shared by the server threads

    def passthrough(name: str):
        def call(**args):
            with lock:
                return client.call_tool(name, args)
        return call

    try:
        listed = client.list_tools()
    except (MCPError, requests.RequestException) as exc:
        log.warning("Agent bus: unraidclaw tools unavailable (%s); serving status and Unraid API tools only", exc)
        listed = []
    hidden = set() if cfg.check_vms else VM_TOOLS
    for t in listed:
        name, ann = t.get("name"), t.get("annotations") or {}
        if name in hidden:
            continue
        if name in READ_ONLY_TOOLS and ann.get("readOnlyHint") is True:
            tools.append(BusTool(name, t.get("description") or "", t.get("inputSchema") or {}, passthrough(name)))
        elif name in cfg.bus_action_tools:
            tools.append(BusTool(name, t.get("description") or "", t.get("inputSchema") or {}, passthrough(name),
                                 read_only=False))
    if cfg.pools_enabled:
        gql = UnraidGraphQL(cfg.unraid_graphql_url, cfg.unraid_api_key)
        for name, (spec, fn) in agent_tools(gql, cfg).items():
            fn_spec = spec["function"]
            tools.append(BusTool(name, fn_spec["description"], fn_spec["parameters"], fn))
    return tools


def run_cycle(cfg: Config, mcp: MCPClient, state: State, notifier: Notifier, runtime: Runtime | None = None) -> list[Finding]:
    gql = UnraidGraphQL(cfg.unraid_graphql_url, cfg.unraid_api_key) if cfg.pools_enabled else None
    findings = Checks(mcp, state, cfg, datetime.now(timezone.utc), gql).run()
    try:
        diagnosis = escalate(mcp, state, cfg, findings, gql)
    except Exception:  # diagnosis is best-effort; never lose the notification over it
        log.exception("Escalation failed")
        diagnosis = None
    complete = not any(f.key in INCOMPLETE_KEYS for f in findings)
    notifier.send(findings, diagnosis, complete=complete)
    state.expire("seen", 24 * 30)
    state.expire("escalated", 24 * 7)
    state.save()
    if runtime:
        runtime.record(findings, diagnosis)
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Unraid health agent")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    mcp = MCPClient(cfg.mcp_url, cfg.mcp_api_key, fingerprint=cfg.mcp_fingerprint, verify_tls=cfg.mcp_verify_tls)
    state = State(cfg.state_path)
    notifier = Notifier(cfg.notify_urls, cfg.renotify_hours, state, cfg.bot_alert_url, cfg.bus_token)
    runtime = Runtime("unraid", revision=_revision())
    approvals = Approvals("unraid", cfg.approval_urls, mode=cfg.approval_mode)
    if cfg.bus_token and cfg.bus_port and not args.once:
        serve_mcp("0.0.0.0", cfg.bus_port, cfg.bus_token, bus_tools(cfg, runtime), "unraid-agent", approvals)
    log.info(
        "Starting: unraidclaw=%s pinned=%s pools=%s escalation=%s model=%s bus=%s approvals=%s/%s bot_alerts=%s interval=%smin",
        cfg.mcp_url, bool(cfg.mcp_fingerprint), cfg.pools_enabled, cfg.escalation_enabled, cfg.opencode_model,
        bool(cfg.bus_token), approvals.enabled, approvals.mode, bool(cfg.bot_alert_url), cfg.interval_minutes,
    )

    while True:
        try:
            findings = run_cycle(cfg, mcp, state, notifier, runtime)
            log.info("Cycle done: %d finding(s)", len(findings))
        except Exception:  # keep the daemon alive; next cycle may succeed
            log.exception("Cycle crashed")
            mcp = MCPClient(cfg.mcp_url, cfg.mcp_api_key, fingerprint=cfg.mcp_fingerprint, verify_tls=cfg.mcp_verify_tls)
        if args.once:
            return
        if runtime.wake.wait(cfg.interval_minutes * 60):  # the bot asked for a check now
            log.info("Check requested via the agent bus")
        runtime.wake.clear()


def _revision() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "REVISION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "dev"


if __name__ == "__main__":
    main()
