#!/bin/bash
# Workload: long-transfer
# Args: $1 = peer IP, $2 = raw output dir
# Pushes 60s of iperf3 traffic to peer's iperf3 daemon (which the orchestrator
# starts on port 5201 at fleet-deploy time).
#
# Note: tunnel selection is decided one level up (run-cell.sh chose the iface
# already, and the peer IP we get is the tunnel-side address). For the UDP
# variant we run iperf3 in UDP mode with -l 1200 to fit under WG MTU.

set -euo pipefail
PEER="$1"
RAW="$2"

# Probe: is the peer listening?
timeout 5 nc -zv "$PEER" 5201 2>&1 | tee "$RAW/probe.log" || {
    echo "iperf3 server unreachable at $PEER:5201"
    exit 3
}

# TCP run
iperf3 -c "$PEER" -p 5201 -t 60 -P 4 -O 5 --json \
    > "$RAW/iperf3-tcp.json"

# UDP run (lower target to avoid 100% loss on choked links; iperf3 -b 0
# means saturate, but with MTU-fit -l 1200)
iperf3 -c "$PEER" -p 5201 -u -b 1G -l 1200 -t 60 -O 5 --json \
    > "$RAW/iperf3-udp.json" || true   # UDP can fail-non-zero on heavy loss

echo "long-transfer OK"
