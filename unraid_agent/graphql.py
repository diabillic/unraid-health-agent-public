"""Direct read-only queries to Unraid's own GraphQL API, for data unraidclaw doesn't expose.

unraidclaw 0.1.37 lists only array data and parity disks (array.disks / array.parities), so on a
pool-only server its disk tools return nothing. Pool devices, ZFS pools included, are
array.caches. The API has no zpool health fields; ZFS faults are caught from ZED syslog events.
A disk's `warning`/`critical` are Unraid's per-disk utilization thresholds in percent.
"""

from __future__ import annotations

from typing import Any

import requests

POOLS_QUERY = """query {
  array {
    caches { name device size temp warning critical isSpinning status color fsType fsSize fsFree fsUsed numErrors }
  }
}"""


# Physical disks with SMART. smartStatus is only OK or UNKNOWN in the API; a failing SMART
# self-assessment and an unreadable one both come back as UNKNOWN.
PHYSICAL_DISKS_QUERY = """query {
  disks { device name vendor serialNum smartStatus isSpinning temperature }
}"""


# Per-container sizes in bytes. The API has no docker.img utilization figure; a container's
# writable layer (sizeRw) and log (sizeLog) are what fill it.
CONTAINER_SIZES_QUERY = """query {
  docker { containers { names state sizeRw sizeLog isUpdateAvailable } }
}"""

# lm-sensors readings with Unraid's per-sensor thresholds. Super-I/O chips also report voltage
# inputs and unconnected headers as "temperatures", so callers must filter by sensor name.
SENSORS_QUERY = """query {
  metrics { temperature { sensors { name type current { value unit status } warning critical } } }
}"""


class GraphQLError(RuntimeError):
    pass


class UnraidGraphQL:
    def __init__(self, url: str, api_key: str, timeout: float = 20.0):
        self.url = url
        self.timeout = timeout
        self.http = requests.Session()
        # API-key auth; Unraid only demands a CSRF token from cookie (browser) sessions.
        self.http.headers.update({"Content-Type": "application/json", "x-api-key": api_key})

    def query(self, query: str, variables: dict | None = None) -> Any:
        resp = self.http.post(self.url, json={"query": query, "variables": variables or {}}, timeout=self.timeout)
        if resp.status_code >= 400:
            raise GraphQLError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        body = resp.json()
        if body.get("errors"):
            raise GraphQLError("; ".join(e.get("message", "?") for e in body["errors"])[:300])
        if body.get("data") is None:
            raise GraphQLError("no data returned")
        return body["data"]

    def pool_disks(self) -> list[dict]:
        return list(((self.query(POOLS_QUERY).get("array") or {}).get("caches")) or [])

    def physical_disks(self) -> list[dict]:
        return list(self.query(PHYSICAL_DISKS_QUERY).get("disks") or [])

    def container_sizes(self) -> list[dict]:
        return list(((self.query(CONTAINER_SIZES_QUERY).get("docker") or {}).get("containers")) or [])

    def temperature_sensors(self) -> list[dict]:
        metrics = self.query(SENSORS_QUERY).get("metrics") or {}
        return list(((metrics.get("temperature")) or {}).get("sensors") or [])
