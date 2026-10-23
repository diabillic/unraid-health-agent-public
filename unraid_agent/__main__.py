"""Entry point: python -m unraid_agent [--once]"""

from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime, timezone

from .checks import Checks
from .config import Config
from .escalate import escalate
from .findings import Finding
from .graphql import UnraidGraphQL
from .mcp import MCPClient
from .notify import Notifier
from .state import State

log = logging.getLogger("unraid_agent")

INCOMPLETE_KEYS = {"mcp:down", "mcp:degraded", "mcp:tools-failing", "mcp:permissions"}


def run_cycle(cfg: Config, mcp: MCPClient, state: State, notifier: Notifier) -> list[Finding]:
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
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Unraid health agent")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    mcp = MCPClient(cfg.mcp_url, cfg.mcp_api_key, fingerprint=cfg.mcp_fingerprint, verify_tls=cfg.mcp_verify_tls)
    state = State(cfg.state_path)
    notifier = Notifier(cfg.notify_urls, cfg.renotify_hours, state)
    log.info(
        "Starting: unraidclaw=%s pinned=%s pools=%s escalation=%s model=%s interval=%smin",
        cfg.mcp_url, bool(cfg.mcp_fingerprint), cfg.pools_enabled, cfg.escalation_enabled, cfg.opencode_model,
        cfg.interval_minutes,
    )

    while True:
        try:
            findings = run_cycle(cfg, mcp, state, notifier)
            log.info("Cycle done: %d finding(s)", len(findings))
        except Exception:  # keep the daemon alive; next cycle may succeed
            log.exception("Cycle crashed")
            mcp = MCPClient(cfg.mcp_url, cfg.mcp_api_key, fingerprint=cfg.mcp_fingerprint, verify_tls=cfg.mcp_verify_tls)
        if args.once:
            return
        time.sleep(cfg.interval_minutes * 60)


if __name__ == "__main__":
    main()
