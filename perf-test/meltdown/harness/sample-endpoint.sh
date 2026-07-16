#!/usr/bin/env bash
set -euo pipefail

OUT=
DURATION=60
IFACE=eth0
IFB=ifb-wgmt
TUNNEL_IFACE=
INNER_PORT=5201
OWNER="${SUDO_USER:-azureuser}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while (($#)); do
	case "$1" in
	--out) OUT="$2"; shift 2 ;;
	--duration) DURATION="$2"; shift 2 ;;
	--iface) IFACE="$2"; shift 2 ;;
	--ifb) IFB="$2"; shift 2 ;;
	--tunnel-iface) TUNNEL_IFACE="$2"; shift 2 ;;
	--inner-port) INNER_PORT="$2"; shift 2 ;;
	--owner) OWNER="$2"; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

[[ $EUID -eq 0 ]] || { echo "sample-endpoint.sh must run as root" >&2; exit 1; }
[[ -n "$OUT" ]] || { echo "--out is required" >&2; exit 2; }
[[ -n "$TUNNEL_IFACE" ]] || { echo "--tunnel-iface is required" >&2; exit 2; }
[[ "$INNER_PORT" =~ ^[0-9]+$ ]] || { echo "--inner-port must be numeric" >&2; exit 2; }
[[ "$DURATION" =~ ^[0-9]+$ && "$DURATION" -gt 0 ]] ||
	{ echo "--duration must be a positive integer" >&2; exit 2; }
((DURATION > 1)) ||
	{ echo "--duration must leave one second for BPF quiescence" >&2; exit 2; }
[[ -d "/sys/class/net/$TUNNEL_IFACE" ]] ||
	{ echo "tunnel interface is unavailable: $TUNNEL_IFACE" >&2; exit 1; }
rm -rf "$OUT"
mkdir -p "$OUT"
START_EPOCH="$(date -u +%s)"
PIDS=()
FINISHED=0

snapshot() {
	local phase="$1"
	date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$OUT/time-${phase}.txt"
	nstat -asz > "$OUT/nstat-${phase}.txt" 2>&1 || true
	cat /proc/net/snmp > "$OUT/snmp-${phase}.txt"
	cat /proc/net/netstat > "$OUT/netstat-${phase}.txt"
	ss -tinmH > "$OUT/ss-${phase}.txt" 2>&1 || true
	tc -s -j qdisc show dev "$IFACE" > "$OUT/qdisc-${phase}.json" 2>/dev/null || true
	tc -s -j class show dev "$IFACE" > "$OUT/class-${phase}.json" 2>/dev/null || true
	tc -s -j filter show dev "$IFACE" parent 1: > "$OUT/filter-${phase}.json" 2>/dev/null || true
	tc -s -j filter show dev "$IFACE" ingress > "$OUT/ingress-${phase}.json" 2>/dev/null || true
	tc -s -j qdisc show dev "$IFB" > "$OUT/ifb-qdisc-${phase}.json" 2>/dev/null || true
	ip -s -j link show dev "$IFACE" > "$OUT/link-${phase}.json"
}

finish() {
	((FINISHED == 0)) || return 0
	FINISHED=1
	for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
	for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
	snapshot post
	journalctl -k --since "@$START_EPOCH" --no-pager > "$OUT/kernel.log" 2>/dev/null || true
	{
		timedatectl show -p NTPSynchronized -p TimeUSec 2>/dev/null || true
		printf 'EpochNs=%s\n' "$(date -u +%s%N)"
		printf 'UptimeSeconds=%s\n' "$(cut -d' ' -f1 /proc/uptime)"
		chronyc tracking 2>/dev/null || true
	} > "$OUT/clock.txt"
	uname -a > "$OUT/uname.txt"
	printf 'host=%s\nkernel=%s\nmodule_srcversion=%s\n' \
		"$(hostname)" "$(uname -r)" "$(cat /sys/module/wireguard/srcversion 2>/dev/null || echo unavailable)" \
		> "$OUT/host.env"
	touch "$OUT/done"
	chown -R "$OWNER:$OWNER" "$OUT" 2>/dev/null || true
}
trap 'finish' EXIT INT TERM

snapshot pre

timeout "$DURATION" mpstat -P ALL 1 > "$OUT/mpstat.log" 2>&1 &
PIDS+=("$!")

python3 "$SCRIPT_DIR/sample-interface.py" --iface "$TUNNEL_IFACE" \
	--duration "$DURATION" > "$OUT/interface-series.csv" 2> "$OUT/interface-series.stderr" &
PIDS+=("$!")

timeout "$DURATION" tcpdump -tt -nn -l -i "$TUNNEL_IFACE" -c 1 \
	"tcp port $INNER_PORT and greater 1000" \
	> "$OUT/first-inner-data.txt" 2> "$OUT/first-inner-data.stderr" &
PIDS+=("$!")

(
	ss_start_ns="$(date -u +%s%N)"
	end=$((SECONDS + DURATION))
	while ((SECONDS < end)); do
		printf '%s\n' "--- $(date -u +%s.%N) ---"
		ss -tinmH 2>/dev/null || true
		sleep 0.2
	done
	ss_end_ns="$(date -u +%s%N)"
	{
		printf 'exit_code=0\n'
		printf 'elapsed_ns=%s\n' "$((ss_end_ns - ss_start_ns))"
		printf 'complete=yes\n'
	} > "$OUT/ss-series.status"
) > "$OUT/ss-series.txt" &
PIDS+=("$!")

(
	end=$((SECONDS + DURATION))
	while ((SECONDS < end)); do
		qdisc_json="$(tc -s -j qdisc show dev "$IFACE" 2>/dev/null || printf '[]')"
		[[ -n "$qdisc_json" ]] || qdisc_json='[]'
		printf '{"timestamp":"%s","qdisc":%s}\n' \
			"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$qdisc_json"
		sleep 0.2
	done
) > "$OUT/qdisc-series.jsonl" &
PIDS+=("$!")

(
	end=$((SECONDS + DURATION))
	while ((SECONDS < end)); do
		query_start_ns="$(date -u +%s%N)"
		qdisc_json="$(tc -s -j qdisc show dev "$IFB" 2>/dev/null || printf '[]')"
		query_end_ns="$(date -u +%s%N)"
		[[ -n "$qdisc_json" ]] || qdisc_json='[]'
		printf '{"timestamp":"%s","query_start_ns":%s,"query_end_ns":%s,"qdisc":%s}\n' \
			"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" \
			"$query_start_ns" "$query_end_ns" "$qdisc_json"
		sleep 0.05
	done
) > "$OUT/ifb-qdisc-series.jsonl" &
PIDS+=("$!")

if ! bpftrace -l 'tracepoint:tcp:tcp_retransmit_skb' |
	grep -Fxq 'tracepoint:tcp:tcp_retransmit_skb'; then
	echo "tcp_retransmit_skb tracepoint is unavailable" >&2
	exit 1
fi
if ! bpftrace -l 'kprobe:tcp_retransmit_timer' |
	grep -Fxq 'kprobe:tcp_retransmit_timer'; then
	echo "tcp_retransmit_timer kprobe is unavailable" >&2
	exit 1
fi
if ! bpftrace -l 'tracepoint:tcp:tcp_probe' |
	grep -Fxq 'tracepoint:tcp:tcp_probe'; then
	echo "tcp_probe tracepoint is unavailable" >&2
	exit 1
fi

(
	trace_start_ns="$(date -u +%s%N)"
	capture_duration=$((DURATION - 1))
	set +e
	bpftrace -q -B line -c "sleep $DURATION" "$SCRIPT_DIR/tcp-events.bt" \
		"$capture_duration" \
		> "$OUT/tcp-events.csv" 2> "$OUT/tcp-events.stderr"
	trace_rc=$?
	set -e
	trace_end_ns="$(date -u +%s%N)"
	trace_elapsed_ns=$((trace_end_ns - trace_start_ns))
	trace_min_ns=$((DURATION * 1000000000 - 500000000))
	capture_marker_count="$(
		grep -Ec '^[0-9]+,capture,meta,[0-9]+,0,[0-9]+,0,0$' \
			"$OUT/tcp-events.csv" 2>/dev/null || true
	)"
	trace_complete=no
	if ((trace_elapsed_ns >= trace_min_ns && capture_marker_count == 1)); then
		case "$trace_rc" in
		0) trace_complete=yes ;;
		esac
	fi
	{
		printf 'exit_code=%s\n' "$trace_rc"
		printf 'elapsed_ns=%s\n' "$trace_elapsed_ns"
		printf 'complete=%s\n' "$trace_complete"
		printf 'capture_duration_s=%s\n' "$capture_duration"
		printf 'quiescence_s=1\n'
		printf 'cutoff_anchor=attached_command\n'
		printf 'capture_marker_count=%s\n' "$capture_marker_count"
	} > "$OUT/tcp-events.status.tmp"
	mv "$OUT/tcp-events.status.tmp" "$OUT/tcp-events.status"
) &
BPF_PID=$!
PIDS+=("$BPF_PID")

for _ in {1..250}; do
	if [[ "$(head -n 1 "$OUT/tcp-events.csv" 2>/dev/null)" == \
		'timestamp_ns,event,layer,sport,dport,value1,value2,value3' ]] &&
		grep -Eq '^[0-9]+,capture,meta,[0-9]+,0,[0-9]+,0,0$' \
			"$OUT/tcp-events.csv" 2>/dev/null; then
		touch "$OUT/ready"
		break
	fi
	if ! kill -0 "$BPF_PID" 2>/dev/null; then
		wait "$BPF_PID" 2>/dev/null || true
		cat "$OUT/tcp-events.stderr" >&2
		exit 1
	fi
	sleep 0.1
done
[[ -e "$OUT/ready" ]] || {
	echo "bpftrace did not report its attached capture anchor" >&2
	exit 1
}
wait "${PIDS[@]}" 2>/dev/null || true
finish
