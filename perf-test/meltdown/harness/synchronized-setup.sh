#!/usr/bin/env bash
set -euo pipefail

if (( $# != 9 )); then
	echo "usage: $0 TARGET_NS PEER_PUB PEER_PHYS LOCAL_UDP PEER_UDP LOCAL_TCP PEER_TCP PEER_TUNNEL_TCP STATE_PREFIX" >&2
	exit 2
fi

target_ns=$1
peer_pub=$2
peer_phys=$3
local_udp=$4
peer_udp=$5
local_tcp=$6
peer_tcp=$7
peer_tunnel_tcp=$8
state_prefix=$9

finish() {
	rc=$?
	printf '%s\n' "$rc" > "$state_prefix.done"
}
trap finish EXIT

python3 -c '
import sys
import time

target = int(sys.argv[1])
now = time.time_ns()
if now >= target:
    raise SystemExit("synchronized setup target already passed")
time.sleep((target - now) / 1e9)
lateness = time.time_ns() - target
print(f"setup_release_lateness_ns={lateness}", flush=True)
if lateness > 100_000_000:
    raise SystemExit("synchronized setup released over 100 ms late")
' "$target_ns"

printf 'setup_started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
sudo /opt/wgtcp-meltdown/harness/setup-tunnels.sh up \
	--peer-pub "$peer_pub" \
	--peer-phys "$peer_phys" \
	--local-udp-ip "$local_udp" \
	--peer-udp-ip "$peer_udp" \
	--local-tcp-ip "$local_tcp" \
	--peer-tcp-ip "$peer_tcp" \
	--tcp-role active >/dev/null

delivered=0
for _ in $(seq 1 50); do
	if ping -q -I wg-mt-tcp -c 1 -W 1 "$peer_tunnel_tcp" >/dev/null 2>&1; then
		delivered=1
	fi
	sleep 0.1
done
(( delivered == 1 )) || {
	echo "synchronized TCP tunnel control failed" >&2
	exit 1
}

printf 'setup_completed_utc=%s\nstatus=ready\n' \
	"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
