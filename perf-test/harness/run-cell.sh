#!/bin/bash
# run-cell.sh — execute one matrix cell on a (server, client) VM pair.
#
# Invoked on the CLIENT VM. The server VM must have its iperf3/nginx/sshd
# already running (started by the orchestrator at fleet-deploy time).
#
# Usage:
#   run-cell.sh \
#       --server-ip 10.20.0.4 \
#       --tunnel wireguard-tcp-base|wireguard-udp \
#       --workload short-transfer|long-transfer|web-mix|ssh-interactive \
#       --loss-pct 0.5 \
#       --run-index 1 \
#       --out-dir /var/tmp/cell-out
#
# Outputs:
#   $OUT_DIR/cell.json    — structured metrics per TESTPLAN §11
#   $OUT_DIR/raw/*        — per-tool raw outputs

set -euo pipefail
trap 'echo "FATAL: line $LINENO"' ERR

SERVER_IP=""; TUNNEL=""; WORKLOAD=""; LOSS_PCT="0"; RUN_INDEX="1"; OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-ip)  SERVER_IP="$2"; shift 2 ;;
    --tunnel)     TUNNEL="$2"; shift 2 ;;
    --workload)   WORKLOAD="$2"; shift 2 ;;
    --loss-pct)   LOSS_PCT="$2"; shift 2 ;;
    --run-index)  RUN_INDEX="$2"; shift 2 ;;
    --out-dir)    OUT_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done
[[ -n "$SERVER_IP" && -n "$TUNNEL" && -n "$WORKLOAD" && -n "$OUT_DIR" ]] \
    || { echo "missing required args"; exit 2; }

mkdir -p "$OUT_DIR/raw"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- 1. select tunnel iface
case "$TUNNEL" in
  wireguard-udp)                          WG_IFACE="wg-udp0";  OTHER_IFACE="wg-tcp0" ;;
  wireguard-tcp-base)                     WG_IFACE="wg-tcp0";  OTHER_IFACE="wg-udp0" ;;
  baseline)                               WG_IFACE="";         OTHER_IFACE="" ;;
  *) echo "unknown tunnel: $TUNNEL"; exit 2 ;;
esac

# ---- 2. reset previous netem
for ifc in wg-udp0 wg-tcp0 eth0; do
  sudo tc qdisc del dev "$ifc" root 2>/dev/null || true
done

# ---- 3. ensure only the tunnel under test is up
if [[ -n "$WG_IFACE" ]]; then
  sudo wg-quick down "$OTHER_IFACE" 2>/dev/null || true
  sudo wg-quick up   "$WG_IFACE"   2>/dev/null || true
  PEER_IP="$(sudo wg show "$WG_IFACE" peers | head -1 | xargs -I{} \
             sudo wg show "$WG_IFACE" allowed-ips | awk -v p={} '$1==p{print $2}' \
             | cut -d/ -f1)"
  # Fallback: derive from interface address
  [[ -z "$PEER_IP" ]] && PEER_IP=$(ip -4 -o addr show "$WG_IFACE" \
      | awk '{print $4}' | sed 's|/.*||;s/[0-9]*$/1/')
else
  PEER_IP="$SERVER_IP"  # baseline: hit server directly
fi

# ---- 4. apply loss
APPLY_IFACE="${WG_IFACE:-eth0}"
if [[ "$(echo "$LOSS_PCT > 0" | bc -l)" == "1" ]]; then
  sudo tc qdisc add dev "$APPLY_IFACE" root netem loss "$LOSS_PCT%"
fi

# ---- 5. snapshot pre-state
T0_EPOCH="$(date -u +%s)"
T0_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ip -s link show "$APPLY_IFACE" > "$OUT_DIR/raw/iface-pre.txt"
sudo dmesg --since "5 minutes ago" > "$OUT_DIR/raw/dmesg-pre.txt" 2>/dev/null || true

# Background CPU & ss sampling. mpstat in sysstat 12.6.1 (Ubuntu 24.04) does
# NOT accept fractional intervals — `mpstat -P ALL 0.5` exits rc=1 with a
# usage error, producing an empty log. Stick to integer 1s interval.
# Sub-second workloads (h2load on LAN) get at least one sample via the
# `sleep 2` idle pad inside web-mix.sh.
mpstat -P ALL 1 > "$OUT_DIR/raw/mpstat.log" 2>/dev/null &
MPSTAT_PID=$!
( while true; do ss -ti >> "$OUT_DIR/raw/ss-snapshots.txt" 2>/dev/null || true
  echo "--- $(date -u +%s) ---" >> "$OUT_DIR/raw/ss-snapshots.txt"
  sleep 5; done ) &
SS_PID=$!

# ---- 6. run workload (do not abort on non-zero; we capture RC instead)
set +e
"$SCRIPT_DIR/workloads/$WORKLOAD.sh" "$PEER_IP" "$OUT_DIR/raw" \
    > "$OUT_DIR/raw/workload-stdout.log" 2> "$OUT_DIR/raw/workload-stderr.log"
WORKLOAD_RC=$?
set -e

# ---- 7. snapshot post-state
T1_EPOCH="$(date -u +%s)"
T1_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ip -s link show "$APPLY_IFACE" > "$OUT_DIR/raw/iface-post.txt"
sudo dmesg --since "1 minute ago" > "$OUT_DIR/raw/dmesg-post.txt" 2>/dev/null || true
kill "$MPSTAT_PID" "$SS_PID" 2>/dev/null || true
wait 2>/dev/null || true

# ---- 8. tear down netem
sudo tc qdisc del dev "$APPLY_IFACE" root 2>/dev/null || true

# ---- 9. emit cell JSON (delegates parsing to a python sidecar)
KVER="$(uname -r)"
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in amd64) ARCH=x86_64 ;; arm64) ARCH=arm64 ;; esac

CELL_ID="$(hostname)-$TUNNEL-$WORKLOAD-loss${LOSS_PCT}-run${RUN_INDEX}"

python3 "$SCRIPT_DIR/parse-cell.py" \
    --cell-id    "$CELL_ID" \
    --workload   "$WORKLOAD" \
    --tunnel     "$TUNNEL" \
    --loss-pct   "$LOSS_PCT" \
    --run-index  "$RUN_INDEX" \
    --arch       "$ARCH" \
    --kernel     "$KVER" \
    --t0         "$T0_ISO" \
    --t1         "$T1_ISO" \
    --raw-dir    "$OUT_DIR/raw" \
    --workload-rc "$WORKLOAD_RC" \
    > "$OUT_DIR/cell.json"

echo "OK: cell $CELL_ID -> $OUT_DIR/cell.json"
