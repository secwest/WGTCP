#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

MODE=${1:-}
case "$MODE" in
fwmark|route|source-uplink|policy-churn|ipv6|ipv6-link-local|carrier-lifetime|config-roundtrip|fault-injection) ;;
*)
	printf 'usage: %s {fwmark|route|source-uplink|policy-churn|ipv6|ipv6-link-local|carrier-lifetime|config-roundtrip|fault-injection}\n' "$0" >&2
	exit 1
	;;
esac

if (( EUID != 0 )); then
	echo "tcp-parity-netns.sh must run as root" >&2
	exit 1
fi

for command in awk cmp grep ip ping readlink sort ss stat sysctl wc; do
	command -v "$command" >/dev/null || {
		echo "missing required command: $command" >&2
		exit 1
	}
done
if [[ $MODE == policy-churn ]]; then
	command -v nft >/dev/null || {
		echo "missing required command: nft" >&2
		exit 1
	}
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WG_FORK=${WG_FORK:-$ROOT/tools/wg}
[[ -x $WG_FORK ]] || {
	echo "modified wg tool is not executable: $WG_FORK" >&2
	exit 1
}

suffix=$$
ns_a=wgtcp-pa-$suffix
ns_b=wgtcp-pb-$suffix
p0a=p0a-$suffix
p0b=p0b-$suffix
p1a=p1a-$suffix
p1b=p1b-$suffix
tmpdir=$(mktemp -d)
external_ownership=${WG_TEST_OWNERSHIP_DIR:-}
ownership_dir=${external_ownership:-$tmpdir/ownership}
if [[ -n $external_ownership ]]; then
	[[ -d $ownership_dir && -w $ownership_dir ]] || {
		echo "ownership directory is unavailable: $ownership_dir" >&2
		exit 1
	}
else
	install -d -m 0700 "$ownership_dir"
fi

namespace_exists() {
	ip netns list | awk -v target="$1" '$1 == target { found = 1 } END { exit found ? 0 : 1 }'
}

record_owned() {
	local kind=$1 name=$2
	printf '%s\n' "$name" >>"$ownership_dir/$kind"
}

cleanup() {
	local status=$? cleanup_failed=0 namespace iface
	local -a namespaces=() ifaces=()
	trap - EXIT
	set +e
	if [[ $MODE == fault-injection && -d /sys/module/wireguard/parameters ]]; then
		for parameter in write_delay_ms max_send_bytes garbage_prefix_bytes \
				queue_limit fail_next_send fail_send_netns \
				fail_send_ifindex fail_send_local_ipv4 \
				fail_send_source_port fail_send_remote_ipv4 \
				fail_send_remote_port; do
			printf '0\n' >"/sys/module/wireguard/parameters/tcp_test_$parameter" || \
				cleanup_failed=1
		done
	fi
	[[ ! -r $ownership_dir/netns ]] || mapfile -t namespaces <"$ownership_dir/netns"
	[[ ! -r $ownership_dir/extra-ifaces ]] || mapfile -t ifaces <"$ownership_dir/extra-ifaces"
	if (( status != 0 )); then
		for namespace in "${namespaces[@]}"; do
			namespace_exists "$namespace" || continue
			{
				printf '%s\n' "--- $namespace addresses ---"
				ip -n "$namespace" -brief address
				printf '%s\n' "--- $namespace IPv4 routes and rules ---"
				ip -n "$namespace" -4 route show table all
				ip -n "$namespace" -4 rule show
				printf '%s\n' "--- $namespace IPv6 routes ---"
				ip -n "$namespace" -6 route show table all
				printf '%s\n' "--- $namespace WireGuard public state ---"
				ip netns exec "$namespace" "$WG_FORK" show all listen-port
				ip netns exec "$namespace" "$WG_FORK" show all endpoints
				printf '%s\n' "--- $namespace sockets ---"
				ip netns exec "$namespace" ss -H -lntu
				ip netns exec "$namespace" ss -H -ntoe 2>/dev/null
				if command -v nft >/dev/null; then
					printf '%s\n' "--- $namespace nftables rules ---"
					ip netns exec "$namespace" nft -a list ruleset
				fi
			} >&2
		done
	fi
	for namespace in "${namespaces[@]}"; do
		if namespace_exists "$namespace"; then
			ip netns del "$namespace" >/dev/null 2>&1 || cleanup_failed=1
		fi
		namespace_exists "$namespace" && cleanup_failed=1
	done
	for iface in "${ifaces[@]}"; do
		if ip link show dev "$iface" >/dev/null 2>&1; then
			ip link del dev "$iface" >/dev/null 2>&1 || cleanup_failed=1
		fi
		ip link show dev "$iface" >/dev/null 2>&1 && cleanup_failed=1
	done
	(( cleanup_failed )) || rm -f "$ownership_dir/netns" "$ownership_dir/extra-ifaces"
	rm -rf "$tmpdir"
	if (( cleanup_failed )); then
		echo "failed to remove one or more owned network resources" >&2
		exit 1
	fi
	exit "$status"
}
trap cleanup EXIT

run() {
	local namespace=$1
	shift
	ip netns exec "$namespace" "$@"
}

ipv4_to_uint() {
	local address=$1 octet octet_value value=0
	local -a octets

	IFS=. read -r -a octets <<<"$address"
	(( ${#octets[@]} == 4 )) || return 1
	for octet in "${octets[@]}"; do
		[[ $octet =~ ^[0-9]+$ ]] || return 1
		octet_value=$(( 10#$octet ))
		(( octet_value <= 255 )) || return 1
		value=$(( (value << 8) | octet_value ))
	done
	printf '%u\n' "$value"
}

assert_quiet() {
	local output
	if ! output=$("$@" 2>&1); then
		echo "$output" >&2
		return 1
	fi
	[[ -z $output ]] || {
		echo "unexpected command output: $output" >&2
		return 1
	}
}

wait_ping() {
	local namespace=$1 iface=$2 destination=$3 family=${4:-4}
	local deadline=${5:-$(( SECONDS + 60 ))}
	while (( SECONDS < deadline )); do
		if run "$namespace" ping "-$family" -I "$iface" -c 1 -W 2 \
			"$destination" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "TCP tunnel did not reach $destination before deadline $deadline" >&2
	return 1
}

tcp_local_endpoint() {
	local namespace=$1 family=$2 remote=$3 port=$4
	run "$namespace" ss -H -tn"$family" state established | awk \
		-v target="$remote:$port" '
		{
			count = 0
			for (i = 1; i <= NF; ++i) {
				if ($i ~ /:[0-9]+$/)
					address[++count] = $i
			}
			if (count >= 2 && address[count] == target) {
				print address[count - 1]
				exit
			}
			delete address
		}
	'
}

tcp_address_pair() {
	local namespace=$1 family=$2 source=$3 remote=$4
	run "$namespace" ss -H -tn"$family" state established | awk \
		-v source="$source:" -v target="$remote:" '
		{
			count = 0
			for (i = 1; i <= NF; ++i) {
				if ($i ~ /:[0-9]+$/)
					address[++count] = $i
			}
			if (count >= 2 &&
			    index(address[count - 1], source) == 1 &&
			    index(address[count], target) == 1) {
				print address[count - 1] "->" address[count]
				exit
			}
			delete address
		}
	'
}

wait_tcp_address_pair() {
	local namespace=$1 family=$2 source=$3 remote=$4
	local deadline=${5:-$(( SECONDS + 60 ))} observed=
	while (( SECONDS < deadline )); do
		observed=$(tcp_address_pair "$namespace" "$family" "$source" "$remote")
		if [[ -n $observed ]]; then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "no established TCP stream from $source:* to $remote:* before deadline $deadline" >&2
	return 1
}

wait_tcp_endpoint() {
	local namespace=$1 family=$2 remote=$3 port=$4 prefix=$5 previous=${6:-}
	local deadline=${7:-$(( SECONDS + 60 ))} observed=none
	while (( SECONDS < deadline )); do
		observed=$(tcp_local_endpoint "$namespace" "$family" "$remote" "$port")
		if [[ $observed == "$prefix"* && ( -z $previous || $observed != "$previous" ) ]]; then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "TCP endpoint did not become ${prefix}* with a new tuple before deadline $deadline (last observed: $observed; previous: ${previous:-none})" >&2
	return 1
}

wait_tcp_remote() {
	local namespace=$1 family=$2 remote=$3 port=$4
	local deadline=$(( SECONDS + 60 )) observed
	while (( SECONDS < deadline )); do
		observed=$(tcp_local_endpoint "$namespace" "$family" "$remote" "$port")
		if [[ -n $observed ]]; then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "no established TCP stream to $remote:$port within 60 seconds" >&2
	return 1
}

wait_counter_advance() {
	local path=$1 before=$2 deadline=$3 observed=invalid
	while (( SECONDS < deadline )); do
		observed=$(<"$path")
		if [[ $observed =~ ^[0-9]+$ ]] && (( observed > before )); then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 0.25
	done
	echo "counter $path did not advance beyond $before before deadline $deadline (last observed: $observed)" >&2
	return 1
}

peer_endpoint() {
	local namespace=$1 iface=$2 public_key=$3
	run "$namespace" "$WG_FORK" show "$iface" endpoints | \
		awk -v key="$public_key" '$1 == key { print $2 }'
}

wait_peer_endpoint() {
	local namespace=$1 iface=$2 public_key=$3 expected=$4
	local deadline=${5:-$(( SECONDS + 60 ))} observed=none
	while (( SECONDS < deadline )); do
		observed=$(peer_endpoint "$namespace" "$iface" "$public_key")
		if [[ $observed == "$expected" ]]; then
			return 0
		fi
		sleep 1
	done
	echo "peer endpoint did not become $expected before deadline $deadline (last observed: $observed)" >&2
	return 1
}

wait_peer_endpoint_address() {
	local namespace=$1 iface=$2 public_key=$3 expected=$4
	local deadline=${5:-$(( SECONDS + 60 ))} observed=none
	while (( SECONDS < deadline )); do
		observed=$(peer_endpoint "$namespace" "$iface" "$public_key")
		if [[ $observed == "$expected:"* ]]; then
			return 0
		fi
		sleep 1
	done
	echo "peer endpoint address did not become $expected before deadline $deadline (last observed: $observed)" >&2
	return 1
}

wait_tcp_remote_absent() {
	local namespace=$1 family=$2 remote=$3 port=$4
	local deadline=${5:-$(( SECONDS + 60 ))} observed=unknown
	while (( SECONDS < deadline )); do
		observed=$(tcp_local_endpoint "$namespace" "$family" "$remote" "$port")
		if [[ -z $observed ]]; then
			return 0
		fi
		sleep 1
	done
	echo "obsolete TCP stream to $remote:$port remained established at $observed before deadline $deadline" >&2
	return 1
}

wait_tcp_mark() {
	local namespace=$1 remote=$2 port=$3 mark=$4
	local deadline=${5:-$(( SECONDS + 60 ))} output=
	while (( SECONDS < deadline )); do
		output=$(run "$namespace" ss -H -tn4e state established 2>/dev/null)
		if awk -v target="$remote:$port" -v expected="fwmark:$mark" '
			index($0, target) && index($0, expected) { found = 1 }
			END { exit found ? 0 : 1 }
		' <<<"$output"; then
			return 0
		fi
		sleep 1
	done
	echo "TCP stream to $remote:$port did not carry mark $mark before deadline $deadline" >&2
	[[ -z $output ]] || printf '%s\n' "$output" >&2
	return 1
}

install_policy_syn_observer() {
	local namespace=$1 remote_port=$2 mark1=$3 mark2=$4
	run "$namespace" nft add table ip wgtcp_policy
	run "$namespace" nft add counter ip wgtcp_policy syn_all
	run "$namespace" nft add counter ip wgtcp_policy syn_mark1
	run "$namespace" nft add counter ip wgtcp_policy syn_mark2
	run "$namespace" nft add chain ip wgtcp_policy output \
		'{ type filter hook output priority filter; policy accept; }'
	run "$namespace" nft add rule ip wgtcp_policy output \
		tcp dport "$remote_port" \
		'tcp flags & (fin | syn | rst | ack) == syn' \
		counter name syn_all
	run "$namespace" nft add rule ip wgtcp_policy output \
		meta mark "$mark1" tcp dport "$remote_port" \
		'tcp flags & (fin | syn | rst | ack) == syn' \
		counter name syn_mark1
	run "$namespace" nft add rule ip wgtcp_policy output \
		meta mark "$mark2" tcp dport "$remote_port" \
		'tcp flags & (fin | syn | rst | ack) == syn' \
		counter name syn_mark2
}

policy_syn_packets() {
	local namespace=$1 counter=$2
	run "$namespace" nft list counter ip wgtcp_policy "$counter" | awk '
		$1 == "packets" { print $2; found = 1; exit }
		END { if (!found) exit 1 }
	'
}

snapshot_policy_syn() {
	local namespace=$1 counter=$2 observed
	observed=$(policy_syn_packets "$namespace" "$counter")
	[[ $observed =~ ^[0-9]+$ ]] || {
		echo "could not read $namespace policy SYN counter $counter: $observed" >&2
		return 1
	}
	printf '%s\n' "$observed"
}

policy_exact_carrier() {
	local namespace=$1 remote=$2 port=$3 source=$4 mark=$5
	run "$namespace" ss -H -tn4e state established 2>/dev/null | awk \
		-v target="$remote:" -v source="$source:" \
		-v expected="fwmark:$mark" '
		{
			count = 0
			for (i = 1; i <= NF; ++i) {
				if ($i ~ /^[0-9][0-9.]*:[0-9]+$/)
					address[++count] = $i
			}
			if (count >= 2 && index(address[count], target) == 1 &&
			    index(address[count - 1], source) == 1 &&
			    index($0, expected)) {
				print address[count - 1] "->" address[count]
				exit
			}
			delete address
		}
	'
}

wait_policy_exact_carrier() {
	local namespace=$1 remote=$2 port=$3 source=$4 mark=$5
	local previous=$6 deadline=$7 observed=none
	while (( SECONDS < deadline )); do
		observed=$(policy_exact_carrier "$namespace" "$remote" "$port" \
			"$source" "$mark")
		if [[ -n $observed && $observed != "$previous" ]]; then
			return 0
		fi
		sleep 0.25
	done
	echo "$namespace did not establish a new carrier $source:*->$remote:* with mark $mark before deadline $deadline (last observed: $observed; previous: ${previous:-none})" >&2
	run "$namespace" ss -H -tn4e state established >&2 || true
	return 1
}

settle_policy_baseline() {
	local namespace=$1 remote=$2 port=$3 source=$4 mark=$5 counter=$6
	local deadline=$(( SECONDS + 60 )) quiet_seconds=3 quiet_since=-1
	local observed_all=invalid observed_proof=invalid observed_carrier=none
	local last_all=invalid last_carrier=none confirm_all confirm_proof
	local confirm_carrier
	while (( SECONDS < deadline )); do
		if ! observed_all=$(policy_syn_packets "$namespace" syn_all); then
			observed_all=invalid
		fi
		if ! observed_proof=$(policy_syn_packets "$namespace" "$counter"); then
			observed_proof=invalid
		fi
		observed_carrier=$(policy_exact_carrier "$namespace" "$remote" "$port" \
			"$source" "$mark")
		if [[ $observed_all =~ ^[0-9]+$ &&
		      $observed_proof =~ ^[0-9]+$ && -n $observed_carrier ]]; then
			if [[ $observed_all == "$last_all" &&
		      $observed_carrier == "$last_carrier" ]]; then
				(( quiet_since >= 0 )) || quiet_since=$SECONDS
				if (( SECONDS - quiet_since >= quiet_seconds )); then
					confirm_all=$(policy_syn_packets "$namespace" syn_all)
					confirm_proof=$(policy_syn_packets "$namespace" "$counter")
					confirm_carrier=$(policy_exact_carrier "$namespace" \
						"$remote" "$port" "$source" "$mark")
					if [[ $confirm_all == "$observed_all" &&
					      $confirm_proof == "$observed_proof" &&
					      $confirm_carrier == "$observed_carrier" ]]; then
						printf '%s %s\n' "$observed_proof" \
							"$observed_carrier"
						return 0
					fi
					quiet_since=$SECONDS
				fi
			else
				quiet_since=$SECONDS
			fi
		else
			quiet_since=-1
		fi
		last_all=$observed_all
		last_carrier=$observed_carrier
		sleep 0.25
	done
	echo "$namespace baseline did not hold exact carrier $source:*->$remote:$port mark $mark with a ${quiet_seconds}s all-SYN quiet interval before deadline $deadline (all=$observed_all proof=$observed_proof carrier=$observed_carrier)" >&2
	run "$namespace" ss -H -tn4e state established >&2 || true
	run "$namespace" nft -a list chain ip wgtcp_policy output >&2 || true
	return 1
}

delete_policy_route_if_present() {
	local namespace=$1 prefix=$2 routes
	routes=$(run "$namespace" ip -4 route show exact "$prefix")
	[[ -z $routes ]] || run "$namespace" ip -4 route del "$prefix"
}

wait_policy_syn_advance() {
	local namespace=$1 counter=$2 before=$3 deadline=$4
	local observed=$before
	while (( SECONDS < deadline )); do
		observed=$(policy_syn_packets "$namespace" "$counter")
		if [[ $observed =~ ^[0-9]+$ ]] && (( observed > before )); then
			return 0
		fi
		sleep 0.25
	done
	echo "$namespace policy SYN counter $counter did not advance above $before before deadline $deadline (last observed: $observed)" >&2
	run "$namespace" nft -a list chain ip wgtcp_policy output >&2 || true
	return 1
}

tcp_tuple_set() {
	local namespace=$1 family=$2
	run "$namespace" ss -H -tn"$family" state established | awk '
		{
			count = 0
			for (i = 1; i <= NF; ++i) {
				if ($i ~ /:[0-9]+$/)
					address[++count] = $i
			}
			if (count >= 2)
				print address[count - 1] "->" address[count]
			delete address
		}
	' | sort
}

wait_tcp_tuple_set() {
	local namespace=$1 family=$2 minimum=$3
	local deadline=$(( SECONDS + 60 ))
	local -a tuples=()
	while (( SECONDS < deadline )); do
		mapfile -t tuples < <(tcp_tuple_set "$namespace" "$family")
		if (( ${#tuples[@]} >= minimum )); then
			printf '%s\n' "${tuples[@]}"
			return 0
		fi
		sleep 1
	done
	echo "fewer than $minimum established TCP streams after 60 seconds" >&2
	return 1
}

listener_present() {
	local namespace=$1 protocol=$2 family=$3 port=$4
	[[ -n $(run "$namespace" ss -H -ln"$protocol""$family" "sport = :$port") ]]
}

create_topology() {
	! namespace_exists "$ns_a" || {
		echo "network namespace already exists: $ns_a" >&2
		exit 1
	}
	! namespace_exists "$ns_b" || {
		echo "network namespace already exists: $ns_b" >&2
		exit 1
	}
	record_owned netns "$ns_a"
	ip netns add "$ns_a"
	record_owned netns "$ns_b"
	ip netns add "$ns_b"
	run "$ns_a" ip link set lo up
	run "$ns_b" ip link set lo up

	for iface in "$p0a" "$p0b" "$p1a" "$p1b"; do
		! ip link show dev "$iface" >/dev/null 2>&1 || {
			echo "link already exists: $iface" >&2
			exit 1
		}
		record_owned extra-ifaces "$iface"
	done
	ip link add "$p0a" type veth peer name "$p0b"
	ip link add "$p1a" type veth peer name "$p1b"
	ip link set "$p0a" netns "$ns_a"
	ip link set "$p0b" netns "$ns_b"
	ip link set "$p1a" netns "$ns_a"
	ip link set "$p1b" netns "$ns_b"

	run "$ns_a" ip addr add 192.0.2.1/24 dev "$p0a"
	run "$ns_b" ip addr add 192.0.2.2/24 dev "$p0b"
	run "$ns_a" ip addr add 198.51.100.1/24 dev "$p1a"
	run "$ns_b" ip addr add 198.51.100.2/24 dev "$p1b"
	run "$ns_a" ip -6 addr add fd00:77:0::1/64 dev "$p0a" nodad
	run "$ns_b" ip -6 addr add fd00:77:0::2/64 dev "$p0b" nodad
	for namespace_iface in \
		"$ns_a $p0a" "$ns_b $p0b" "$ns_a $p1a" "$ns_b $p1b"; do
		read -r namespace iface <<<"$namespace_iface"
		run "$namespace" ip link set "$iface" up
	done

	umask 077
	"$WG_FORK" genkey >"$tmpdir/a.key"
	"$WG_FORK" genkey >"$tmpdir/b.key"
	a_pub=$("$WG_FORK" pubkey <"$tmpdir/a.key")
	b_pub=$("$WG_FORK" pubkey <"$tmpdir/b.key")
}

setup_ipv4_pair() {
	local port=$1 mark=${2:-off}
	local reverse_endpoint=${3:-on}
	local -a set_a
	run "$ns_b" ip addr add 203.0.113.2/32 dev lo
	run "$ns_a" ip route add 203.0.113.2/32 via 192.0.2.2 dev "$p0a" metric 10

	run "$ns_a" ip link add wga type wireguard
	run "$ns_b" ip link add wgb type wireguard
	set_a=(set wga private-key "$tmpdir/a.key" listen-port "$port" transport tcp)
	[[ $mark == off ]] || set_a+=(fwmark "$mark")
	assert_quiet run "$ns_a" "$WG_FORK" "${set_a[@]}"
	assert_quiet run "$ns_b" "$WG_FORK" set wgb private-key "$tmpdir/b.key" \
		listen-port "$port" transport tcp
	run "$ns_a" ip addr add 10.210.0.1/32 dev wga
	run "$ns_b" ip addr add 10.210.0.2/32 dev wgb
	run "$ns_a" ip link set wga up
	run "$ns_b" ip link set wgb up
	run "$ns_a" ip route add 10.210.0.2/32 dev wga
	run "$ns_b" ip route add 10.210.0.1/32 dev wgb
	assert_quiet run "$ns_a" "$WG_FORK" set wga peer "$b_pub" \
		allowed-ips 0.0.0.0/0 endpoint 203.0.113.2:"$port" persistent-keepalive 1
	if [[ $reverse_endpoint == on ]]; then
		assert_quiet run "$ns_b" "$WG_FORK" set wgb peer "$a_pub" \
			allowed-ips 10.210.0.1/32 endpoint 192.0.2.1:"$port"
	else
		assert_quiet run "$ns_b" "$WG_FORK" set wgb peer "$a_pub" \
			allowed-ips 10.210.0.1/32
	fi
}

setup_policy_churn_pair() {
	local listen_a=$1 listen_b=$2 mark_a=$3 mark_b=$4
	local next_mark_a=$5 next_mark_b=$6
	run "$ns_b" ip addr add 203.0.113.2/32 dev lo
	# Keep policy churn on one stable path so each reconnect is attributable
	# only to its FwMark mutation. Route and uplink churn have dedicated modes.
	run "$ns_a" ip route add 203.0.113.2/32 via 192.0.2.2 \
		dev "$p0a" metric 20

	# Cross-interface routing is intentional in this mode. Keep the relaxation
	# and all SYN observability inside the two owned namespaces.
	for namespace in "$ns_a" "$ns_b"; do
		run "$namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
	done
	for namespace_iface in \
		"$ns_a $p0a" "$ns_a $p1a" "$ns_b $p0b" "$ns_b $p1b"; do
		read -r namespace iface <<<"$namespace_iface"
		run "$namespace" sysctl -qw "net.ipv4.conf.$iface.rp_filter=0"
	done
	install_policy_syn_observer "$ns_a" "$listen_b" "$mark_a" "$next_mark_a"

	run "$ns_a" ip link add wga type wireguard
	run "$ns_b" ip link add wgb type wireguard
	assert_quiet run "$ns_a" "$WG_FORK" set wga private-key "$tmpdir/a.key" \
		listen-port "$listen_a" fwmark "$mark_a" transport tcp
	assert_quiet run "$ns_b" "$WG_FORK" set wgb private-key "$tmpdir/b.key" \
		listen-port "$listen_b" fwmark "$mark_b" transport tcp
	run "$ns_a" ip addr add 10.215.0.1/32 dev wga
	run "$ns_b" ip addr add 10.215.0.2/32 dev wgb
	run "$ns_a" ip link set wga up
	run "$ns_b" ip link set wgb up
	run "$ns_a" ip route add 10.215.0.2/32 dev wga
	run "$ns_b" ip route add 10.215.0.1/32 dev wgb
	assert_quiet run "$ns_a" "$WG_FORK" set wga peer "$b_pub" \
		allowed-ips 10.215.0.2/32 endpoint 203.0.113.2:"$listen_b" \
		persistent-keepalive 1
	assert_quiet run "$ns_b" "$WG_FORK" set wgb peer "$a_pub" \
		allowed-ips 10.215.0.1/32
}

assert_policy_path_activity() {
	local iface_a=$1 iface_b=$2 before_a before_b after_a after_b
	local deadline=$(( SECONDS + 60 ))
	before_a=$(run "$ns_a" cat "/sys/class/net/$iface_a/statistics/tx_packets")
	before_b=$(run "$ns_b" cat "/sys/class/net/$iface_b/statistics/tx_packets")
	wait_ping "$ns_a" wga 10.215.0.2 4 "$deadline"
	wait_ping "$ns_b" wgb 10.215.0.1 4 "$deadline"
	run "$ns_a" ping -4 -I wga -c 3 -W 2 10.215.0.2 >/dev/null
	run "$ns_b" ping -4 -I wgb -c 3 -W 2 10.215.0.1 >/dev/null
	after_a=$(run "$ns_a" cat "/sys/class/net/$iface_a/statistics/tx_packets")
	after_b=$(run "$ns_b" cat "/sys/class/net/$iface_b/statistics/tx_packets")
	[[ $before_a =~ ^[0-9]+$ && $after_a =~ ^[0-9]+$ &&
	   $before_b =~ ^[0-9]+$ && $after_b =~ ^[0-9]+$ &&
	   $after_a -gt $before_a && $after_b -gt $before_b ]] || {
		echo "bidirectional TCP tunnel traffic did not use $iface_a/$iface_b" >&2
		return 1
	}
}

assert_policy_state() {
	local remote_a=$1 source_a=$2 remote_b=$3 source_b=$4
	local mark_a=$5 mark_b=$6
	local deadline=$(( SECONDS + 60 ))
	wait_peer_endpoint "$ns_a" wga "$b_pub" "$remote_a:$port_b" "$deadline"
	wait_peer_endpoint "$ns_b" wgb "$a_pub" "$remote_b:$port_a" "$deadline"
	wait_policy_exact_carrier "$ns_a" "$remote_a" "$port_b" "$source_a" \
		"$mark_a" "" "$deadline"
	wait_policy_exact_carrier "$ns_b" "$remote_b" "$port_a" "$source_b" \
		"$mark_b" "" "$deadline"
	[[ $(run "$ns_a" "$WG_FORK" show wga listen-port) == "$port_a" ]] || {
		echo "namespace A asymmetric listen port changed" >&2
		return 1
	}
	[[ $(run "$ns_b" "$WG_FORK" show wgb listen-port) == "$port_b" ]] || {
		echo "namespace B asymmetric listen port changed" >&2
		return 1
	}
}

prove_policy_a_connect() {
	local remote=$1 source=$2 mark=$3 counter=$4 before=$5 previous=${6:-}
	local deadline=$(( SECONDS + 60 ))
	wait_policy_syn_advance "$ns_a" "$counter" "$before" "$deadline"
	wait_policy_exact_carrier "$ns_a" "$remote" "$port_b" "$source" \
		"$mark" "$previous" "$deadline"
	wait_ping "$ns_a" wga 10.215.0.2 4 "$deadline"
	wait_peer_endpoint_address "$ns_b" wgb "$a_pub" "$source" "$deadline"
}

prove_policy_b_connect() {
	local remote=$1 source=$2 mark=$3 counter=$4 before=$5 previous=${6:-}
	local deadline=$(( SECONDS + 60 ))
	wait_policy_syn_advance "$ns_b" "$counter" "$before" "$deadline"
	wait_policy_exact_carrier "$ns_b" "$remote" "$port_a" "$source" \
		"$mark" "$previous" "$deadline"
	wait_ping "$ns_b" wgb 10.215.0.1 4 "$deadline"
	wait_peer_endpoint_address "$ns_a" wga "$b_pub" "$source" "$deadline"
}

create_topology

case "$MODE" in
fwmark)
	port=52200
	mark1=0x12200
	mark2=0x22200
	setup_ipv4_pair "$port" "$mark1"
	wait_ping "$ns_a" wga 10.210.0.2
	before=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" 192.0.2.1:)
	# This focused namespace has no wg-quick nftables/conntrack mark restore.
	# Disable reverse-path filtering so the policy test measures socket marks
	# and reconnect behavior rather than host firewall integration.
	run "$ns_a" sysctl -qw net.ipv4.conf.all.rp_filter=0
	run "$ns_a" sysctl -qw "net.ipv4.conf.$p0a.rp_filter=0"
	run "$ns_a" sysctl -qw "net.ipv4.conf.$p1a.rp_filter=0"
	run "$ns_a" ip route del 10.210.0.2/32 dev wga
	run "$ns_a" ip route add default dev wga table 220
	run "$ns_a" ip rule add priority 220 from 10.210.0.1/32 lookup 220
	run "$ns_a" ip route add prohibit 192.0.2.2/32 table 221
	run "$ns_a" ip rule add priority 218 fwmark "$mark1" lookup main
	run "$ns_a" ip rule add priority 219 to 192.0.2.2/32 lookup 221

	if unmarked_route=$(run "$ns_a" ip -4 route get 192.0.2.2 2>&1); then
		echo "unmarked endpoint lookup bypassed the recursion guard: $unmarked_route" >&2
		exit 1
	fi
	marked_route=$(run "$ns_a" ip -4 route get 192.0.2.2 mark "$mark1")
	[[ $marked_route == *"dev $p0a"* && $marked_route == *"src 192.0.2.1"* ]] || {
		echo "marked endpoint lookup did not use the physical path: $marked_route" >&2
		exit 1
	}
	policy_stream=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" 192.0.2.1: "$before")
	wait_tcp_mark "$ns_a" 192.0.2.2 "$port" "$mark1"
	wait_ping "$ns_a" wga 10.210.0.2

	# Install the new policy before changing the device. The established
	# mark-1 stream is then unusable, while a new mark-2 stream can route.
	run "$ns_a" ip rule del priority 218
	run "$ns_a" ip rule add priority 218 fwmark "$mark2" lookup main
	assert_quiet run "$ns_a" "$WG_FORK" set wga fwmark "$mark2"
	after=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" 192.0.2.1: "$policy_stream")
	wait_tcp_mark "$ns_a" 192.0.2.2 "$port" "$mark2"
	wait_ping "$ns_a" wga 10.210.0.2
	[[ $(run "$ns_a" "$WG_FORK" show wga fwmark) == "$mark2" ]]
	printf 'mode=fwmark\nfull_tunnel=pass\nrecursion_guard=pass\nold_tcp_endpoint=%s\npolicy_tcp_endpoint=%s\nnew_tcp_endpoint=%s\n' \
		"$before" "$policy_stream" "$after"
	;;
route)
	port=52201
	setup_ipv4_pair "$port" off off
	wait_ping "$ns_a" wga 10.210.0.2
	before=$(wait_tcp_endpoint "$ns_a" 4 203.0.113.2 "$port" 192.0.2.1:)
	packets_before=$(run "$ns_a" cat "/sys/class/net/$p1a/statistics/tx_packets")
	run "$ns_a" ip route replace 203.0.113.2/32 via 198.51.100.2 dev "$p1a"
	wait_ping "$ns_a" wga 10.210.0.2
	run "$ns_a" ping -4 -I wga -c 5 -W 2 10.210.0.2 >/dev/null
	packets_after=$(run "$ns_a" cat "/sys/class/net/$p1a/statistics/tx_packets")
	(( packets_after > packets_before )) || {
		echo "route replacement did not move TCP tunnel traffic to path1" >&2
		exit 1
	}
	# The configured destination remains 203.0.113.2; only its gateway and
	# selected source address move to path1.
	after=$(wait_tcp_endpoint "$ns_a" 4 203.0.113.2 "$port" 198.51.100.1: "$before")
	printf 'mode=route\ntraffic_path=path1\nreconnected=true\nold_tcp_endpoint=%s\nnew_tcp_endpoint=%s\n' \
		"$before" "$after"
	;;
source-uplink)
	port=52202
	setup_ipv4_pair "$port" off off
	run "$ns_a" ip route add 203.0.113.2/32 via 198.51.100.2 \
		dev "$p1a" metric 20
	wait_ping "$ns_a" wga 10.210.0.2
	initial=$(wait_tcp_endpoint "$ns_a" 4 203.0.113.2 "$port" 192.0.2.1:)

	# Preserve the connected subnet while removing the address selected by
	# the established stream. The address notifier must reconnect via .9.
	run "$ns_a" sysctl -qw "net.ipv4.conf.$p0a.promote_secondaries=1"
	run "$ns_a" ip addr add 192.0.2.9/24 dev "$p0a"
	run "$ns_a" ip addr del 192.0.2.1/24 dev "$p0a"
	after_address=$(wait_tcp_endpoint "$ns_a" 4 203.0.113.2 "$port" \
		192.0.2.9: "$initial")
	wait_ping "$ns_a" wga 10.210.0.2

	# The lower-metric path0 route becomes unusable when its link goes down;
	# reconnect must keep the configured destination and use the path1 source.
	run "$ns_a" ip link set "$p0a" down
	after_uplink=$(wait_tcp_endpoint "$ns_a" 4 203.0.113.2 "$port" \
		198.51.100.1: "$after_address")
	wait_peer_endpoint "$ns_a" wga "$b_pub" "203.0.113.2:$port"
	wait_ping "$ns_a" wga 10.210.0.2
	printf 'mode=source-uplink\nsource_reconnect=pass\nuplink_reconnect=pass\nconfigured_dial_target_preserved=pass\ninitial_tcp_endpoint=%s\naddress_tcp_endpoint=%s\nuplink_tcp_endpoint=%s\nuplink_dial_target=%s\n' \
		"$initial" "$after_address" "$after_uplink" "203.0.113.2:$port"
	;;
policy-churn)
	port_a=52205
	port_b=52206
	mark_a1=0x152205
	mark_b1=0x252206
	mark_a2=0x352205
	mark_b2=0x452206
	transitions=0
	connect_proofs=0
	fwmark_syn_proofs=0
	setup_policy_churn_pair "$port_a" "$port_b" "$mark_a1" "$mark_b1" \
		"$mark_a2" "$mark_b2"

	assert_policy_path_activity "$p0a" "$p0b"
	read -r mark2_syn_before mark2_carrier_before < <(
		settle_policy_baseline "$ns_a" 203.0.113.2 "$port_b" \
			192.0.2.1 "$mark_a1" syn_mark2
	)
	initial_mark1_syn=$(snapshot_policy_syn "$ns_a" syn_mark1)
	(( initial_mark1_syn > 0 )) || {
		echo "initial carrier was not observed with its configured mark" >&2
		exit 1
	}

	assert_quiet run "$ns_a" "$WG_FORK" set wga fwmark "$mark_a2"
	prove_policy_a_connect 203.0.113.2 192.0.2.1 "$mark_a2" syn_mark2 \
		"$mark2_syn_before" "$mark2_carrier_before"
	transitions=$(( transitions + 1 ))
	connect_proofs=$(( connect_proofs + 1 ))
	fwmark_syn_proofs=$(( fwmark_syn_proofs + 1 ))
	assert_policy_path_activity "$p0a" "$p0b"

	read -r mark1_syn_before mark1_carrier_before < <(
		settle_policy_baseline "$ns_a" 203.0.113.2 "$port_b" \
			192.0.2.1 "$mark_a2" syn_mark1
	)
	assert_quiet run "$ns_a" "$WG_FORK" set wga fwmark "$mark_a1"
	prove_policy_a_connect 203.0.113.2 192.0.2.1 "$mark_a1" syn_mark1 \
		"$mark1_syn_before" "$mark1_carrier_before"
	transitions=$(( transitions + 1 ))
	connect_proofs=$(( connect_proofs + 1 ))
	fwmark_syn_proofs=$(( fwmark_syn_proofs + 1 ))
	assert_policy_path_activity "$p0a" "$p0b"

	read -r mark2_repeat_syn_before mark2_repeat_carrier_before < <(
		settle_policy_baseline "$ns_a" 203.0.113.2 "$port_b" \
			192.0.2.1 "$mark_a1" syn_mark2
	)
	assert_quiet run "$ns_a" "$WG_FORK" set wga fwmark "$mark_a2"
	prove_policy_a_connect 203.0.113.2 192.0.2.1 "$mark_a2" syn_mark2 \
		"$mark2_repeat_syn_before" "$mark2_repeat_carrier_before"
	transitions=$(( transitions + 1 ))
	connect_proofs=$(( connect_proofs + 1 ))
	fwmark_syn_proofs=$(( fwmark_syn_proofs + 1 ))
	assert_policy_path_activity "$p0a" "$p0b"

	(( transitions == 3 && connect_proofs == 3 && fwmark_syn_proofs == 3 )) || {
		echo "unexpected policy proof counts: transitions=$transitions connects=$connect_proofs fwmark_syns=$fwmark_syn_proofs" >&2
		exit 1
	}
	printf 'mode=policy-churn\npolicy_transitions=%s\nconnect_proofs=%s\nfwmark_syn_proofs=%s\nsyn_observability=pass\nstable_route=pass\nfwmark_socket_reconnect=pass\nfwmark_scope=socket-mark-propagation-and-reconnect\nmark_selected_full_tunnel_scope=fwmark-mode\nbidirectional_traffic=pass\nasymmetric_ports=%s,%s\nfinal_path=path0\n' \
		"$transitions" "$connect_proofs" "$fwmark_syn_proofs" \
		"$port_a" "$port_b"
	;;
carrier-lifetime)
	port=52203
	setup_ipv4_pair "$port"
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	before_a=$(wait_tcp_tuple_set "$ns_a" 4 1)
	before_b=$(wait_tcp_tuple_set "$ns_b" 4 1)
	for (( second = 0; second < 40; ++second )); do
		run "$ns_a" ping -4 -I wga -c 1 -W 2 10.210.0.2 >/dev/null
		run "$ns_b" ping -4 -I wgb -c 1 -W 2 10.210.0.1 >/dev/null
		sleep 1
	done
	after_a=$(wait_tcp_tuple_set "$ns_a" 4 1)
	after_b=$(wait_tcp_tuple_set "$ns_b" 4 1)
	[[ $after_a == "$before_a" ]] || {
		printf 'namespace A TCP tuples changed across authenticated lifetime:\nbefore:\n%s\nafter:\n%s\n' \
			"$before_a" "$after_a" >&2
		exit 1
	}
	[[ $after_b == "$before_b" ]] || {
		printf 'namespace B TCP tuples changed across authenticated lifetime:\nbefore:\n%s\nafter:\n%s\n' \
			"$before_b" "$after_b" >&2
		exit 1
	}
	printf 'mode=carrier-lifetime\nauthenticated_lifetime=pass\nduration_seconds=40\n'
	;;
config-roundtrip)
	port=52204
	setup_ipv4_pair "$port"
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1

	# showconf contains private and optional preshared keys. Keep every copy in
	# the guest-local 0700 temporary directory and never write it to stdout.
	run "$ns_a" "$WG_FORK" showconf wga >"$tmpdir/a.conf"
	run "$ns_b" "$WG_FORK" showconf wgb >"$tmpdir/b.conf"
	[[ $(stat -c '%a' "$tmpdir/a.conf") == 600 &&
	   $(stat -c '%a' "$tmpdir/b.conf") == 600 ]] || {
		echo "showconf files are not mode 0600" >&2
		exit 1
	}
	for config in "$tmpdir/a.conf" "$tmpdir/b.conf"; do
		grep -Fxq 'Transport = tcp' "$config" || {
			echo "TCP transport was omitted from showconf" >&2
			exit 1
		}
		grep -Fxq "ListenPort = $port" "$config" || {
			echo "TCP listen port was omitted from showconf" >&2
			exit 1
		}
		grep -q '^PrivateKey = ' "$config" || {
			echo "private key was omitted from showconf" >&2
			exit 1
		}
	done

	wg_quick=$(command -v wg-quick) || {
		echo "wg-quick is required for the configuration round-trip case" >&2
		exit 1
	}
	# wg-quick prepends its own directory to PATH. Run a guest-local copy
	# beside the fork shim so SaveConfig and the subsequent down/up reload use
	# the modified wg grammar without exposing secret-bearing output.
	install -d -m 0700 "$tmpdir/bin"
	install -m 0700 "$wg_quick" "$tmpdir/bin/wg-quick"
	ln -s "$WG_FORK" "$tmpdir/bin/wg"
	printf '[Interface]\nSaveConfig = true\nTable = off\n' >"$tmpdir/wga.conf"
	if ! run "$ns_a" env "PATH=$tmpdir/bin:$PATH" \
		"$tmpdir/bin/wg-quick" save \
		"$tmpdir/wga.conf" >"$tmpdir/wg-quick-save.log" 2>&1; then
		echo "wg-quick save failed" >&2
		exit 1
	fi
	[[ $(stat -c '%a' "$tmpdir/wga.conf") == 600 ]] || {
		echo "wg-quick SaveConfig file is not mode 0600" >&2
		exit 1
	}
	grep -Fxq 'Transport = tcp' "$tmpdir/wga.conf" || {
		echo "wg-quick SaveConfig omitted TCP transport" >&2
		exit 1
	}
	grep -q '^PrivateKey = ' "$tmpdir/wga.conf" || {
		echo "wg-quick SaveConfig omitted the private key" >&2
		exit 1
	}
	if ! run "$ns_a" env "PATH=$tmpdir/bin:$PATH" \
		"$tmpdir/bin/wg-quick" down \
		"$tmpdir/wga.conf" >"$tmpdir/wg-quick-down.log" 2>&1; then
		echo "wg-quick down failed" >&2
		exit 1
	fi
	if ! run "$ns_a" env "PATH=$tmpdir/bin:$PATH" \
		"$tmpdir/bin/wg-quick" up \
		"$tmpdir/wga.conf" >"$tmpdir/wg-quick-up.log" 2>&1; then
		echo "wg-quick up failed" >&2
		exit 1
	fi
	run "$ns_a" ip route replace 10.210.0.2/32 dev wga
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	run "$ns_a" "$WG_FORK" showconf wga >"$tmpdir/a.wg-quick"
	cmp -s "$tmpdir/a.conf" "$tmpdir/a.wg-quick" || {
		echo "namespace A configuration changed across wg-quick down/up" >&2
		exit 1
	}

	assert_quiet run "$ns_a" "$WG_FORK" setconf wga "$tmpdir/a.conf"
	assert_quiet run "$ns_b" "$WG_FORK" setconf wgb "$tmpdir/b.conf"
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	run "$ns_a" "$WG_FORK" showconf wga >"$tmpdir/a.setconf"
	run "$ns_b" "$WG_FORK" showconf wgb >"$tmpdir/b.setconf"
	cmp -s "$tmpdir/a.conf" "$tmpdir/a.setconf" || {
		echo "namespace A configuration changed across setconf" >&2
		exit 1
	}
	cmp -s "$tmpdir/b.conf" "$tmpdir/b.setconf" || {
		echo "namespace B configuration changed across setconf" >&2
		exit 1
	}

	# Drift both live peer sets without placing private material in command
	# arguments. syncconf must remove the extra public key, restore A's saved
	# keepalive, preserve TCP mode, and leave the tunnel usable.
	extra_pub=$("$WG_FORK" genkey | "$WG_FORK" pubkey)
	assert_quiet run "$ns_a" "$WG_FORK" set wga peer "$extra_pub" \
		allowed-ips 10.211.0.0/16
	assert_quiet run "$ns_b" "$WG_FORK" set wgb peer "$extra_pub" \
		allowed-ips 10.211.0.0/16
	assert_quiet run "$ns_a" "$WG_FORK" set wga peer "$b_pub" \
		persistent-keepalive 7
	(( $(run "$ns_a" "$WG_FORK" show wga peers | wc -l) == 2 )) || {
		echo "namespace A drift peer was not installed" >&2
		exit 1
	}
	(( $(run "$ns_b" "$WG_FORK" show wgb peers | wc -l) == 2 )) || {
		echo "namespace B drift peer was not installed" >&2
		exit 1
	}
	assert_quiet run "$ns_a" "$WG_FORK" syncconf wga "$tmpdir/a.conf"
	assert_quiet run "$ns_b" "$WG_FORK" syncconf wgb "$tmpdir/b.conf"
	[[ $(run "$ns_a" "$WG_FORK" show wga peers) == "$b_pub" ]] || {
		echo "namespace A syncconf did not remove configuration drift" >&2
		exit 1
	}
	[[ $(run "$ns_b" "$WG_FORK" show wgb peers) == "$a_pub" ]] || {
		echo "namespace B syncconf did not remove configuration drift" >&2
		exit 1
	}
	keepalive=$(run "$ns_a" "$WG_FORK" show wga persistent-keepalive | \
		awk -v key="$b_pub" '$1 == key { print $2 }')
	[[ $keepalive == 1 ]] || {
		echo "syncconf did not restore the saved persistent keepalive" >&2
		exit 1
	}
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	run "$ns_a" "$WG_FORK" showconf wga >"$tmpdir/a.syncconf"
	run "$ns_b" "$WG_FORK" showconf wgb >"$tmpdir/b.syncconf"
	cmp -s "$tmpdir/a.conf" "$tmpdir/a.syncconf" || {
		echo "namespace A configuration changed across syncconf" >&2
		exit 1
	}
	cmp -s "$tmpdir/b.conf" "$tmpdir/b.syncconf" || {
		echo "namespace B configuration changed across syncconf" >&2
		exit 1
	}
	printf 'mode=config-roundtrip\nshowconf=pass\nsetconf=pass\nsyncconf=pass\nwg_quick_roundtrip=pass\nsecrets=guest-local\ntraffic=pass\n'
	;;
fault-injection)
	parameter_root=/sys/module/wireguard/parameters
	for parameter in max_send_bytes garbage_prefix_bytes queue_limit \
			write_delay_ms fail_send_netns fail_send_ifindex \
			fail_send_local_ipv4 fail_send_source_port \
			fail_send_remote_ipv4 fail_send_remote_port fail_next_send; do
		[[ -w $parameter_root/tcp_test_$parameter ]] || {
			echo "fault control is unavailable: tcp_test_$parameter" >&2
			exit 1
		}
	done
	for counter in short_writes injected_prefixes resyncs queue_drops \
			fatal_send_errors; do
		[[ -r $parameter_root/tcp_test_$counter ]] || {
			echo "fault counter is unavailable: tcp_test_$counter" >&2
			exit 1
		}
	done

	port=52214
	setup_ipv4_pair "$port"
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	short_before=$(<"$parameter_root/tcp_test_short_writes")
	prefix_before=$(<"$parameter_root/tcp_test_injected_prefixes")
	resync_before=$(<"$parameter_root/tcp_test_resyncs")
	printf '7\n' >"$parameter_root/tcp_test_max_send_bytes"
	printf '11\n' >"$parameter_root/tcp_test_garbage_prefix_bytes"
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	short_after=$(<"$parameter_root/tcp_test_short_writes")
	prefix_after=$(<"$parameter_root/tcp_test_injected_prefixes")
	resync_after=$(<"$parameter_root/tcp_test_resyncs")
	(( short_after > short_before )) || {
		echo "forced send cap did not produce a short write" >&2
		exit 1
	}
	(( prefix_after > prefix_before )) || {
		echo "malformed prefixes were not injected" >&2
		exit 1
	}
	(( resync_after > resync_before )) || {
		echo "receiver did not resynchronize after malformed prefixes" >&2
		exit 1
	}
	printf '0\n' >"$parameter_root/tcp_test_max_send_bytes"
	printf '0\n' >"$parameter_root/tcp_test_garbage_prefix_bytes"
	wait_ping "$ns_a" wga 10.210.0.2

	queue_before=$(<"$parameter_root/tcp_test_queue_drops")
	printf '500\n' >"$parameter_root/tcp_test_write_delay_ms"
	printf '1\n' >"$parameter_root/tcp_test_queue_limit"
	pressure_pids=()
	for _ in {1..8}; do
		run "$ns_a" ping -4 -I wga -c 100 -i 0.001 -w 3 \
			10.210.0.2 >/dev/null 2>&1 &
		pressure_pids+=("$!")
	done
	for pressure_pid in "${pressure_pids[@]}"; do
		wait "$pressure_pid" || true
	done
	queue_after=$(<"$parameter_root/tcp_test_queue_drops")
	(( queue_after > queue_before )) || {
		echo "bounded writer pause did not force a queue-pressure drop" >&2
		exit 1
	}
	printf '0\n' >"$parameter_root/tcp_test_write_delay_ms"
	printf '0\n' >"$parameter_root/tcp_test_queue_limit"
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1

	# Quiesce timer-driven writes so the one-shot error is consumed by the
	# selected A-to-B carrier. The injected EPIPE leaves TCP established, so a
	# distinct replacement tuple proves worker-owned failure recovery rather
	# than an ordinary state-change callback.
	assert_quiet run "$ns_a" "$WG_FORK" set wga peer "$b_pub" \
		persistent-keepalive 0
	assert_quiet run "$ns_b" "$WG_FORK" set wgb peer "$a_pub" \
		persistent-keepalive 0
	sleep 2
	fatal_before=$(<"$parameter_root/tcp_test_fatal_send_errors")
	wait_peer_endpoint "$ns_a" wga "$b_pub" "192.0.2.2:$port"
	fatal_stream_before=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" \
		192.0.2.1:)
	fatal_netns=$(run "$ns_a" readlink /proc/self/ns/net)
	[[ $fatal_netns =~ ^net:\[([0-9]+)\]$ ]] || {
		echo "could not determine A network namespace inode: $fatal_netns" >&2
		exit 1
	}
	fatal_netns=${BASH_REMATCH[1]}
	fatal_ifindex=$(run "$ns_a" ip -o link show dev wga | \
		awk -F: 'NR == 1 { gsub(/[[:space:]]/, "", $1); print $1 }')
	fatal_local_address=${fatal_stream_before%:*}
	fatal_source_port=${fatal_stream_before##*:}
	fatal_remote_address=192.0.2.2
	fatal_remote_port=$port
	fatal_local_ipv4=$(ipv4_to_uint "$fatal_local_address") || {
		echo "invalid fatal-send local IPv4 address: $fatal_local_address" >&2
		exit 1
	}
	fatal_remote_ipv4=$(ipv4_to_uint "$fatal_remote_address") || {
		echo "invalid fatal-send remote IPv4 address: $fatal_remote_address" >&2
		exit 1
	}
	[[ $fatal_ifindex =~ ^[1-9][0-9]*$ &&
	   $fatal_source_port =~ ^[1-9][0-9]*$ &&
	   $fatal_source_port -le 65535 &&
	   $fatal_remote_port =~ ^[1-9][0-9]*$ &&
	   $fatal_remote_port -le 65535 ]] || {
		echo "invalid fatal-send target: netns=$fatal_netns ifindex=$fatal_ifindex tuple=$fatal_stream_before->$fatal_remote_address:$fatal_remote_port" >&2
		exit 1
	}
	printf '%s\n' "$fatal_netns" >"$parameter_root/tcp_test_fail_send_netns"
	printf '%s\n' "$fatal_ifindex" >"$parameter_root/tcp_test_fail_send_ifindex"
	printf '%s\n' "$fatal_local_ipv4" \
		>"$parameter_root/tcp_test_fail_send_local_ipv4"
	printf '%s\n' "$fatal_source_port" \
		>"$parameter_root/tcp_test_fail_send_source_port"
	printf '%s\n' "$fatal_remote_ipv4" \
		>"$parameter_root/tcp_test_fail_send_remote_ipv4"
	printf '%s\n' "$fatal_remote_port" \
		>"$parameter_root/tcp_test_fail_send_remote_port"
	# Arm last: the selectors form one coherent exact-carrier target before any
	# writer is allowed to consume the one-shot.
	printf '1\n' >"$parameter_root/tcp_test_fail_next_send"
	run "$ns_a" ping -4 -I wga -c 1 -W 2 10.210.0.2 >/dev/null 2>&1 || true
	fatal_after=$(wait_counter_advance \
		"$parameter_root/tcp_test_fatal_send_errors" "$fatal_before" \
		"$(( SECONDS + 30 ))")
	fatal_armed_after=$(<"$parameter_root/tcp_test_fail_next_send")
	[[ $fatal_armed_after == 0 ]] || {
		echo "targeted fatal-send fault was not consumed by A (armed=$fatal_armed_after)" >&2
		exit 1
	}
	fatal_stream_after=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" \
		192.0.2.1: "$fatal_stream_before" "$(( SECONDS + 60 ))")
	[[ $fatal_stream_after != "$fatal_stream_before" ]] || {
		echo "fatal send did not replace the exact TCP carrier" >&2
		exit 1
	}
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	printf 'mode=fault-injection\nshort_writes=%s\ninjected_prefixes=%s\nresyncs=%s\nqueue_drops=%s\nfatal_send_errors=%s\nfatal_target_netns=%s\nfatal_target_ifindex=%s\nfatal_target_local_address=%s\nfatal_target_source_port=%s\nfatal_target_remote_address=%s\nfatal_target_remote_port=%s\nfatal_target_consumed=pass\nfatal_old_tcp_endpoint=%s\nfatal_new_tcp_endpoint=%s\nfatal_recovery=pass\nrecovery=pass\n' \
		"$(( short_after - short_before ))" \
		"$(( prefix_after - prefix_before ))" \
		"$(( resync_after - resync_before ))" \
		"$(( queue_after - queue_before ))" \
		"$(( fatal_after - fatal_before ))" \
		"$fatal_netns" "$fatal_ifindex" "$fatal_local_address" \
		"$fatal_source_port" "$fatal_remote_address" "$fatal_remote_port" \
		"$fatal_stream_before" "$fatal_stream_after"
	;;
ipv6)
	port_a=52210
	port_b=52211
	run "$ns_a" ip link add wg6a type wireguard
	run "$ns_b" ip link add wg6b type wireguard
	assert_quiet run "$ns_a" "$WG_FORK" set wg6a private-key "$tmpdir/a.key" \
		listen-port "$port_a" transport tcp
	assert_quiet run "$ns_b" "$WG_FORK" set wg6b private-key "$tmpdir/b.key" \
		listen-port "$port_b" transport tcp
	run "$ns_a" ip -6 addr add fd00:210::1/128 dev wg6a nodad
	run "$ns_b" ip -6 addr add fd00:210::2/128 dev wg6b nodad
	run "$ns_a" ip link set wg6a up
	run "$ns_b" ip link set wg6b up
	run "$ns_a" ip -6 route add fd00:210::2/128 dev wg6a
	run "$ns_b" ip -6 route add fd00:210::1/128 dev wg6b
	for namespace_port in "$ns_a $port_a" "$ns_b $port_b"; do
		read -r namespace port <<<"$namespace_port"
		listener_present "$namespace" t 4 "$port" || {
			echo "IPv4 TCP listener missing on $port" >&2
			exit 1
		}
		listener_present "$namespace" t 6 "$port" || {
			echo "IPv6 TCP listener missing on $port" >&2
			exit 1
		}
		listener_present "$namespace" u 4 "$port" || {
			echo "IPv4 companion UDP listener missing on $port" >&2
			exit 1
		}
		listener_present "$namespace" u 6 "$port" || {
			echo "IPv6 companion UDP listener missing on $port" >&2
			exit 1
		}
	done
	assert_quiet run "$ns_a" "$WG_FORK" set wg6a peer "$b_pub" \
		allowed-ips fd00:210::2/128 endpoint "[fd00:77::2]:$port_b" \
		persistent-keepalive 1
	assert_quiet run "$ns_b" "$WG_FORK" set wg6b peer "$a_pub" \
		allowed-ips fd00:210::1/128 endpoint "[fd00:77::1]:$port_a"
	wait_ping "$ns_a" wg6a fd00:210::2 6
	wait_ping "$ns_b" wg6b fd00:210::1 6
	ipv6_endpoint=$(wait_tcp_endpoint "$ns_a" 6 "[fd00:77::2]" "$port_b" "[fd00:77::1]:")
	printf 'mode=ipv6\ndual_stack_listeners=pass\nipv6_tunnel=pass\nouter_tcp_endpoint=%s\nport_a=%s\nport_b=%s\n' \
		"$ipv6_endpoint" "$port_a" "$port_b"
	;;
ipv6-link-local)
	port_a=52212
	port_b=52213
	run "$ns_a" ip -6 addr flush dev "$p0a" scope link
	run "$ns_b" ip -6 addr flush dev "$p0b" scope link
	run "$ns_a" ip -6 addr add fe80::a/64 dev "$p0a" nodad
	run "$ns_b" ip -6 addr add fe80::b/64 dev "$p0b" nodad
	route_a=$(run "$ns_a" ip -6 route get fe80::b oif "$p0a")
	route_b=$(run "$ns_b" ip -6 route get fe80::a oif "$p0b")
	[[ $route_a == *"dev $p0a"* && $route_a == *"src fe80::a"* ]] || {
		echo "namespace A did not select its scoped link-local source" >&2
		exit 1
	}
	[[ $route_b == *"dev $p0b"* && $route_b == *"src fe80::b"* ]] || {
		echo "namespace B did not select its scoped link-local source" >&2
		exit 1
	}
	run "$ns_a" ip link add wglla type wireguard
	run "$ns_b" ip link add wgllb type wireguard
	assert_quiet run "$ns_a" "$WG_FORK" set wglla private-key "$tmpdir/a.key" \
		listen-port "$port_a" transport tcp
	assert_quiet run "$ns_b" "$WG_FORK" set wgllb private-key "$tmpdir/b.key" \
		listen-port "$port_b" transport tcp
	run "$ns_a" ip -6 addr add fd00:212::1/128 dev wglla nodad
	run "$ns_b" ip -6 addr add fd00:212::2/128 dev wgllb nodad
	run "$ns_a" ip link set wglla up
	run "$ns_b" ip link set wgllb up
	run "$ns_a" ip -6 route add fd00:212::2/128 dev wglla
	run "$ns_b" ip -6 route add fd00:212::1/128 dev wgllb

	expected_a="[fe80::b%$p0a]:$port_b"
	expected_b="[fe80::a%$p0b]:$port_a"
	assert_quiet run "$ns_a" "$WG_FORK" set wglla peer "$b_pub" \
		allowed-ips fd00:212::2/128 endpoint "$expected_a" \
		persistent-keepalive 1
	assert_quiet run "$ns_b" "$WG_FORK" set wgllb peer "$a_pub" \
		allowed-ips fd00:212::1/128 endpoint "$expected_b"
	configured_a=$(run "$ns_a" "$WG_FORK" show wglla endpoints | \
		awk -v key="$b_pub" '$1 == key { print $2 }')
	configured_b=$(run "$ns_b" "$WG_FORK" show wgllb endpoints | \
		awk -v key="$a_pub" '$1 == key { print $2 }')
	[[ $configured_a == "$expected_a" ]] || {
		echo "namespace A link-local endpoint lost its interface scope" >&2
		exit 1
	}
	[[ $configured_b == "$expected_b" ]] || {
		echo "namespace B link-local endpoint lost its interface scope" >&2
		exit 1
	}

	run "$ns_a" "$WG_FORK" showconf wglla >"$tmpdir/ll-a.conf"
	run "$ns_b" "$WG_FORK" showconf wgllb >"$tmpdir/ll-b.conf"
	grep -Fxq "Endpoint = $expected_a" "$tmpdir/ll-a.conf" || {
		echo "namespace A showconf lost the link-local endpoint scope" >&2
		exit 1
	}
	grep -Fxq "Endpoint = $expected_b" "$tmpdir/ll-b.conf" || {
		echo "namespace B showconf lost the link-local endpoint scope" >&2
		exit 1
	}
	wait_ping "$ns_a" wglla fd00:212::2 6
	wait_ping "$ns_b" wgllb fd00:212::1 6
	# `ss` annotates the local link-local address with its interface but omits
	# the redundant scope on the remote column. The configured/showconf checks
	# above prove the dial-target scope; these checks prove the carrier source.
	outer_a=$(wait_tcp_address_pair "$ns_a" 6 "[fe80::a]%$p0a" "[fe80::b]")
	outer_b=$(wait_tcp_address_pair "$ns_b" 6 "[fe80::b]%$p0b" "[fe80::a]")
	printf 'mode=ipv6-link-local\nscoped_endpoints=pass\nlink_local_carrier=pass\ntraffic=pass\nouter_a=%s\nouter_b=%s\n' \
		"$outer_a" "$outer_b"
	;;
esac
