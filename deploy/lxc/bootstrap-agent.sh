#!/usr/bin/env bash
# Runs INSIDE the agent LXC as root. Prepares it to receive deploys from the runner.
# Env: DEPLOY_PUBKEY (runner's deploy key), INSTALLER (path to pushed unraid-agent-install)
#
# The `deploy` user can only stage files and run the root-owned installer via sudo;
# the installer writes the systemd unit itself, so a deploy can't change what runs as root.
set -euo pipefail
: "${DEPLOY_PUBKEY:?}" "${INSTALLER:?}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv rsync sudo openssh-server ca-certificates >/dev/null
systemctl enable --now ssh >/dev/null

id unraid-agent >/dev/null 2>&1 || useradd --system --home-dir /var/lib/unraid-agent --shell /usr/sbin/nologin unraid-agent
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy

install -d -m 700 -o deploy -g deploy /home/deploy/.ssh /home/deploy/staging
echo "$DEPLOY_PUBKEY" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

install -d -m 755 /opt/unraid-agent
install -d -m 750 -g unraid-agent /etc/unraid-agent
install -m 750 -o root -g root "$INSTALLER" /usr/local/sbin/unraid-agent-install

echo 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/unraid-agent-install' > /etc/sudoers.d/unraid-agent-deploy
chmod 440 /etc/sudoers.d/unraid-agent-deploy
visudo -cf /etc/sudoers.d/unraid-agent-deploy >/dev/null

echo "agent LXC ready"
