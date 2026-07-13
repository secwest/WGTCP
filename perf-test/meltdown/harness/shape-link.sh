#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
[[ -n "$ACTION" ]] || { echo "usage: $0 apply|clear|status [options]" >&2; exit 2; }
shift

IFACE=eth0
IFB=ifb-wgmt
PEER_IP=
RATE_MBPS=50
RTT_MS=40
QUEUE_BDP=1
QUEUE_KIND=bfifo
LOSS_MODEL=none
LOSS_PCT=0
BURST_P=2
BURST_R=25
BURST_H=90
BURST_K=99
JITTER_MS=0
ECN=0
STATE_DIR=/run/wgtcp-meltdown

while (($#)); do
	case "$1" in
	--iface) IFACE="$2"; shift 2 ;;
	--ifb) IFB="$2"; shift 2 ;;
	--peer-ip) PEER_IP="$2"; shift 2 ;;
	--rate-mbps) RATE_MBPS="$2"; shift 2 ;;
	--rtt-ms) RTT_MS="$2"; shift 2 ;;
	--queue-bdp) QUEUE_BDP="$2"; shift 2 ;;
	--queue-kind) QUEUE_KIND="$2"; shift 2 ;;
	--loss-model) LOSS_MODEL="$2"; shift 2 ;;
	--loss-pct) LOSS_PCT="$2"; shift 2 ;;
	--burst-p) BURST_P="$2"; shift 2 ;;
	--burst-r) BURST_R="$2"; shift 2 ;;
	--burst-h) BURST_H="$2"; shift 2 ;;
	--burst-k) BURST_K="$2"; shift 2 ;;
	--jitter-ms) JITTER_MS="$2"; shift 2 ;;
	--ecn) ECN="$2"; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

MARKER="$STATE_DIR/${IFACE}.active"
QDISC_SIGNATURE="$STATE_DIR/${IFACE}.before-qdisc.signature"
RESTORE_FAILED="$STATE_DIR/${IFACE}.restore-failed"

qdisc_signature() {
	tc -j qdisc show dev "$IFACE" |
		python3 -c '
import json
import sys

rows = json.load(sys.stdin)
keys = ("kind", "handle", "parent", "root", "options")
normalized = [{key: row[key] for key in keys if key in row} for row in rows]
print(json.dumps(sorted(normalized, key=lambda row: json.dumps(row, sort_keys=True)),
                 sort_keys=True, separators=(",", ":")))
'
}

clear_shape() {
	if [[ -e "$MARKER" ]]; then
		tc qdisc del dev "$IFACE" root 2>/dev/null || true
		tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
		tc qdisc del dev "$IFB" root 2>/dev/null || true
		ip link delete "$IFB" type ifb 2>/dev/null || true
		rm -f "$MARKER"
		if [[ -s "$QDISC_SIGNATURE" ]] &&
			[[ "$(qdisc_signature)" != "$(cat "$QDISC_SIGNATURE")" ]]; then
			touch "$RESTORE_FAILED"
			echo "failed to restore the original qdisc configuration on $IFACE" >&2
			return 1
		fi
		rm -f "$QDISC_SIGNATURE" "$RESTORE_FAILED"
	fi
}

case "$ACTION" in
clear)
	clear_shape
	tc qdisc show dev "$IFACE"
	exit 0
	;;
status)
	tc -s qdisc show dev "$IFACE"
	tc -s class show dev "$IFACE"
	tc -s filter show dev "$IFACE" parent 1: 2>/dev/null || true
	tc -s filter show dev "$IFACE" ingress 2>/dev/null || true
	ip link show dev "$IFB" >/dev/null 2>&1 &&
		tc -s qdisc show dev "$IFB" || true
	exit 0
	;;
apply) ;;
*) echo "unknown action: $ACTION" >&2; exit 2 ;;
esac

[[ $EUID -eq 0 ]] || { echo "shape-link.sh must run as root" >&2; exit 1; }
[[ -n "$PEER_IP" ]] || { echo "--peer-ip is required" >&2; exit 2; }
[[ "$PEER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid peer IPv4 address" >&2; exit 2; }
[[ "$IFB" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { echo "invalid IFB name" >&2; exit 2; }
[[ "$RATE_MBPS" =~ ^[0-9]+([.][0-9]+)?$ && "$RTT_MS" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
	{ echo "rate and RTT must be numeric" >&2; exit 2; }
[[ "$QUEUE_BDP" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "queue BDP must be numeric" >&2; exit 2; }
[[ "$QUEUE_KIND" == bfifo || "$QUEUE_KIND" == fq_codel ]] || { echo "unsupported queue kind" >&2; exit 2; }
[[ "$LOSS_MODEL" == none || "$LOSS_MODEL" == random || "$LOSS_MODEL" == gemodel ]] ||
	{ echo "unsupported loss model" >&2; exit 2; }

mkdir -p "$STATE_DIR"
clear_shape
[[ ! -e "$RESTORE_FAILED" ]] ||
	{ echo "previous qdisc restoration failed on $IFACE" >&2; exit 1; }
root_kind="$(tc qdisc show dev "$IFACE" | awk '$0 ~ / root / {print $2; exit}')"
case "$root_kind" in
mq|fq|fq_codel|noqueue|"") ;;
*) echo "refusing to replace unexpected root qdisc '$root_kind' on $IFACE" >&2; exit 1 ;;
esac
if tc qdisc show dev "$IFACE" | grep -q ' clsact '; then
	echo "refusing to replace pre-existing clsact on $IFACE" >&2
	exit 1
fi
if ip link show dev "$IFB" >/dev/null 2>&1; then
	echo "refusing to replace pre-existing IFB $IFB" >&2
	exit 1
fi

tc -s -j qdisc show dev "$IFACE" > "$STATE_DIR/${IFACE}.before-qdisc.json"
tc -s -j filter show dev "$IFACE" ingress > "$STATE_DIR/${IFACE}.before-ingress.json" 2>/dev/null || true
qdisc_signature > "$QDISC_SIGNATURE"
queue_bytes="$(awk -v r="$RATE_MBPS" -v t="$RTT_MS" -v q="$QUEUE_BDP" \
	'BEGIN { n=r*t*125*q; if (n < 16384) n=16384; printf "%.0f", n }')"
one_way_ms="$(awk -v t="$RTT_MS" 'BEGIN { printf "%.3f", t/2 }')"

printf '{"iface":"%s","ifb":"%s","peer_ip":"%s","rate_mbps":%s,"rtt_ms":%s,"queue_bdp":%s,"queue_bytes":%s,"queue_kind":"%s","loss_model":"%s"}\n' \
	"$IFACE" "$IFB" "$PEER_IP" "$RATE_MBPS" "$RTT_MS" "$QUEUE_BDP" "$queue_bytes" "$QUEUE_KIND" "$LOSS_MODEL" > "$MARKER"

cleanup_failed_apply() {
	rc=$?
	if ((rc != 0)); then
		clear_shape || true
	fi
	exit "$rc"
}
trap cleanup_failed_apply EXIT

tc qdisc replace dev "$IFACE" root handle 1: htb default 30 r2q 1000
tc class add dev "$IFACE" parent 1: classid 1:10 htb \
	rate "${RATE_MBPS}mbit" ceil "${RATE_MBPS}mbit" burst 64k cburst 64k quantum 1514
tc class add dev "$IFACE" parent 1: classid 1:30 htb \
	rate 10gbit ceil 10gbit burst 256k cburst 256k quantum 1514
tc qdisc add dev "$IFACE" parent 1:30 handle 30: fq_codel

if [[ "$QUEUE_KIND" == bfifo ]]; then
	tc qdisc add dev "$IFACE" parent 1:10 handle 20: bfifo limit "$queue_bytes"
else
	fq_args=(limit 65535 flows 1024 quantum 1514 target 5ms interval 100ms memory_limit "$queue_bytes")
	[[ "$ECN" == 1 ]] && fq_args+=(ecn)
	tc qdisc add dev "$IFACE" parent 1:10 handle 20: fq_codel "${fq_args[@]}"
fi

modprobe ifb
ip link add "$IFB" type ifb
ip link set "$IFB" up

netem=(limit 100000)
if awk -v d="$one_way_ms" 'BEGIN { exit !(d > 0) }'; then
	if awk -v j="$JITTER_MS" 'BEGIN { exit !(j > 0) }'; then
		netem+=(delay "${one_way_ms}ms" "${JITTER_MS}ms" distribution normal)
	else
		netem+=(delay "${one_way_ms}ms")
	fi
fi
case "$LOSS_MODEL" in
random)
	netem+=(loss random "${LOSS_PCT}%")
	;;
gemodel)
	netem+=(loss gemodel "${BURST_P}%" "${BURST_R}%" "${BURST_H}%" "${BURST_K}%")
	;;
esac
tc qdisc add dev "$IFB" root handle 40: netem "${netem[@]}"
tc qdisc add dev "$IFACE" clsact

egress_prio=10
ingress_prio=10
add_test_filters() {
	local proto="$1" field="$2" port="$3"
	tc filter add dev "$IFACE" protocol ip parent 1: prio "$egress_prio" \
		flower skip_hw dst_ip "$PEER_IP" ip_proto "$proto" "$field" "$port" classid 1:10
	tc filter add dev "$IFACE" ingress protocol ip prio "$ingress_prio" \
		flower skip_hw src_ip "$PEER_IP" ip_proto "$proto" "$field" "$port" \
		action mirred egress redirect dev "$IFB"
	egress_prio=$((egress_prio + 1))
	ingress_prio=$((ingress_prio + 1))
}
add_test_filters udp dst_port 51820
add_test_filters udp src_port 51820
add_test_filters tcp dst_port 51821
add_test_filters tcp src_port 51821
add_test_filters tcp dst_port 5202
add_test_filters tcp src_port 5202

cat "$MARKER"
tc -s -j qdisc show dev "$IFACE"
tc -s -j class show dev "$IFACE"
tc -s -j filter show dev "$IFACE" parent 1:
tc -s -j filter show dev "$IFACE" ingress
tc -s -j qdisc show dev "$IFB"
trap - EXIT
