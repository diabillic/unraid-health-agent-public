#!/usr/bin/env bash
# Lets the deployed agent read User Scripts status on Unraid, through deploy/unraid/userscripts-report.php only.
# Run from a machine with root SSH to Unraid and to the Proxmox node of the Docker host. Safe to run again.
#   UNRAID    root SSH destination for Unraid, e.g. root@unraid.local (add -i via UNRAID_SSH_OPTS)
#   PVE       Proxmox node of the Docker host's VM
#   VM        the Docker host's VM, where the agent's container runs
#   FROM      the Docker host's address: the only place the key is accepted from
# Unraid's /root/.ssh links to /boot/config/ssh/root, and the reporter lives on the flash drive, so both
# survive reboots.
set -euo pipefail
: "${UNRAID:?}" "${PVE:?}" "${VM:?}" "${FROM:?}"
here=$(cd "$(dirname "$0")" && pwd)
dest=/boot/config/unraid-agent/userscripts-report.php
# shellcheck disable=SC2086
u() { ssh ${UNRAID_SSH_OPTS:-} "$UNRAID" "$@"; }

pub=$(ssh "$PVE" "qm guest exec $VM -- docker exec unraid-agent cat /var/lib/unraid-agent/userscripts_ed25519.pub" \
  | ssh "$PVE" "python3 -c 'import json,sys; print(json.load(sys.stdin)[\"out-data\"].strip())'")
case "$pub" in ssh-ed25519\ *) ;; *) echo "Couldn't read the agent's public key: is the container running with USERSCRIPTS_HOST set?" >&2; exit 1;; esac

u "mkdir -p $(dirname $dest) && cat > $dest" < "$here/unraid/userscripts-report.php"

line="command=\"/usr/bin/php $dest\",restrict,from=\"$FROM\" $pub"
printf '%s\n' "$line" | u '
  install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
  read -r line; key=$(printf %s "$line" | awk "{print \$(NF-1)}")
  grep -vF "$key" /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.new || true
  printf "%s\n" "$line" >> /root/.ssh/authorized_keys.new
  cat /root/.ssh/authorized_keys.new > /root/.ssh/authorized_keys; rm /root/.ssh/authorized_keys.new'
echo "Installed. The agent's next cycle (within INTERVAL_MINUTES) reads it."
