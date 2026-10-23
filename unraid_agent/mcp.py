"""Minimal MCP client for Streamable HTTP (JSON or SSE responses), with TLS fingerprint pinning."""

from __future__ import annotations

import itertools
import json
import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "unraid-health-agent", "version": "1.0"}


class MCPError(RuntimeError):
    pass


class ToolError(MCPError):
    """The tool ran but reported an error (isError=true)."""


class _PinnedAdapter(HTTPAdapter):
    """Accept exactly one certificate (self-signed is fine), identified by its SHA-256 fingerprint."""

    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint.replace(":", "").lower()
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self.fingerprint
        kwargs["cert_reqs"] = "CERT_NONE"  # chain can't validate a self-signed cert; the pin replaces it
        return super().init_poolmanager(*args, **kwargs)


class MCPClient:
    def __init__(self, url: str, api_key: str, *, fingerprint: str = "", verify_tls: bool = True, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self.http = requests.Session()
        self.http.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "x-api-key": api_key,
        })
        if fingerprint:
            self.http.mount(url.split("/", 3)[0] + "//" + url.split("/", 3)[2], _PinnedAdapter(fingerprint))
            self.http.verify = False  # verification is done by the fingerprint pin
        else:
            self.http.verify = verify_tls
        self._ids = itertools.count(1)
        self._initialized = False
        self.server_info: dict = {}

    # --- transport ---

    def _post(self, body: dict) -> dict | None:
        resp = self.http.post(self.url, json=body, timeout=self.timeout)
        if resp.status_code == 401:
            raise MCPError("unauthorized (check UNRAIDCLAW_API_KEY)")
        if resp.status_code >= 400:
            raise MCPError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        if "mcp-session-id" in resp.headers:
            self.http.headers["mcp-session-id"] = resp.headers["mcp-session-id"]
        if not resp.content:
            return None
        if "text/event-stream" in resp.headers.get("content-type", ""):
            # Use the JSON-RPC response matching our id; ignore interleaved notifications.
            for line in resp.text.splitlines():
                if line.startswith("data:") and line[5:].strip():
                    msg = json.loads(line[5:])
                    if msg.get("id") == body.get("id"):
                        return msg
            return None
        return resp.json()

    def _request(self, method: str, params: dict | None = None) -> Any:
        body = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}}
        msg = self._post(body)
        if msg is None:
            raise MCPError(f"{method}: empty response")
        if "error" in msg:
            raise MCPError(f"{method}: {msg['error'].get('message', msg['error'])}")
        return msg.get("result")

    # --- protocol ---

    def initialize(self) -> None:
        if self._initialized:
            return
        result = self._request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO})
        self.server_info = result.get("serverInfo", {})
        self.http.headers["MCP-Protocol-Version"] = result.get("protocolVersion", PROTOCOL_VERSION)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self._initialized = True

    def list_tools(self) -> list[dict]:
        self.initialize()
        tools, cursor = [], None
        while True:
            result = self._request("tools/list", {"cursor": cursor} if cursor else {})
            tools += result.get("tools", [])
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(self, name: str, arguments: dict | None = None) -> Any:
        """Call a tool; returns parsed JSON when the text content is JSON, else the text."""
        self.initialize()
        result = self._request("tools/call", {"name": name, "arguments": arguments or {}})
        if "structuredContent" in result:
            data: Any = result["structuredContent"]
        else:
            text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
            try:
                data = json.loads(text)
            except ValueError:
                data = text
        if result.get("isError"):
            raise ToolError(f"{name}: {data if isinstance(data, str) else json.dumps(data)[:300]}")
        return data
