#!/bin/bash
# Workload: ssh-interactive
# Measures keystroke-echo RTT through an existing ssh ControlMaster.
# Also captures 1000 ICMP RTTs over the tunnel for context.

set -euo pipefail
PEER="$1"
RAW="$2"

# 1) ping baseline (over the tunnel — peer IP is tunnel-side)
ping -i 0.05 -c 1000 -q "$PEER" 2>&1 | tee "$RAW/ping.log" \
  | tail -2 > "$RAW/ping-summary.log" || true

# 2) ssh keystroke RTT — uses a pre-established ControlMaster on socket
SOCK="/tmp/ssh-ctl-$PEER.sock"
KEY="$HOME/.ssh/wgtcp_id_ed25519"
if ! ssh -o "ControlPath=$SOCK" -O check perfuser@"$PEER" 2>/dev/null; then
  ssh -i "$KEY" -o StrictHostKeyChecking=no -M -S "$SOCK" -fN \
      perfuser@"$PEER" || { echo "ssh master failed"; exit 3; }
fi

OUT="$RAW/ssh-keystroke-rtt.tsv"
echo -e "i\trtt_ms" > "$OUT"

for i in $(seq 1 1000); do
  T0=$(date +%s%N)
  ssh -S "$SOCK" perfuser@"$PEER" "echo X" > /dev/null
  T1=$(date +%s%N)
  echo -e "$i\t$(awk "BEGIN{print ($T1-$T0)/1000000}")" >> "$OUT"
  sleep 0.05
done

ssh -S "$SOCK" -O exit perfuser@"$PEER" 2>/dev/null || true
echo "ssh-interactive OK"
