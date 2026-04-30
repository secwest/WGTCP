#!/bin/bash
# bootstrap-client.sh — install measurement tools on a client VM.
# Idempotent. Lighter than bootstrap-server (no daemons).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
echo "==> protect modified wg userland"
if [[ -f /usr/bin/wg && ! -f /usr/local/sbin/wg.custom ]]; then
    sudo cp -a /usr/bin/wg /usr/local/sbin/wg.custom
fi
sudo apt-mark hold wireguard-tools 2>/dev/null || true

echo "==> client packages"
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update -qq
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y -qq \
    -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    iperf3 nghttp2-client curl bc gawk sysstat \
    netcat-openbsd iproute2 wireguard-tools

if [[ -f /usr/local/sbin/wg.custom ]]; then
    sudo cp -a /usr/local/sbin/wg.custom /usr/bin/wg
fi
# disable any auto-started iperf3 daemon on the client
sudo systemctl stop iperf3 2>/dev/null || true
sudo systemctl disable iperf3 2>/dev/null || true
echo "bootstrap-client OK"
