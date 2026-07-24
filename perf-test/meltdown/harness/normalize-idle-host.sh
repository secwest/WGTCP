#!/usr/bin/env bash
# Return a prepared endpoint to a carrier-free state before passive activation.
set -euo pipefail

if (( EUID != 0 )); then
    echo "normalize-idle-host.sh must run as root" >&2
    exit 2
fi

if (( $# != 0 )); then
    echo "usage: $0" >&2
    exit 2
fi

install_dir="${WGTCP_INSTALL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
"$install_dir/harness/setup-tunnels.sh" down

for unit in \
    wgtcp-meltdown-iperf-inner.service \
    wgtcp-meltdown-iperf-competitor.service \
    wgtcp-meltdown-http.service; do
    systemctl stop "$unit" 2>/dev/null || true
done
systemctl reset-failed

echo "idle normalization completed"
