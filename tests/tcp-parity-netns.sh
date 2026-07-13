#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

MODE=${1:-}
case "$MODE" in
fwmark|route|source-uplink|ipv6|carrier-lifetime) ;;
*)
	printf 'usage: %s {fwmark|route|source-uplink|ipv6|carrier-lifetime}\n' "$0" >&2
	exit 1
	;;
esac

if (( EUID != 0 )); then
	echo "tcp-parity-netns.sh must run as root" >&2
	exit 1
fi

for command in awk ip ping readlink sort ss sysctl; do
	command -v "$command" >/dev/null || {
		echo "missing required command: $command" >&2
		exit 1
	}
done

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
	local deadline=$(( SECONDS + 60 ))
	while (( SECONDS < deadline )); do
		if run "$namespace" ping "-$family" -I "$iface" -c 1 -W 2 \
			"$destination" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "TCP tunnel did not reach $destination within 60 seconds" >&2
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

wait_tcp_endpoint() {
	local namespace=$1 family=$2 remote=$3 port=$4 prefix=$5 previous=${6:-}
	local deadline=$(( SECONDS + 60 )) observed
	while (( SECONDS < deadline )); do
		observed=$(tcp_local_endpoint "$namespace" "$family" "$remote" "$port")
		if [[ $observed == "$prefix"* && ( -z $previous || $observed != "$previous" ) ]]; then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "TCP endpoint did not become ${prefix}* with a new tuple" >&2
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

wait_tcp_mark() {
	local namespace=$1 remote=$2 port=$3 mark=$4
	local deadline=$(( SECONDS + 60 )) output
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
	echo "TCP stream to $remote:$port did not carry mark $mark" >&2
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
	assert_quiet run "$ns_b" "$WG_FORK" set wgb peer "$a_pub" \
		allowed-ips 10.210.0.1/32 endpoint 192.0.2.1:"$port"
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
	setup_ipv4_pair "$port"
	wait_ping "$ns_a" wga 10.210.0.2
	before=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" 192.0.2.1:)
	packets_before=$(run "$ns_a" cat "/sys/class/net/$p1a/statistics/tx_packets")
	run "$ns_a" ip route replace 192.0.2.2/32 via 198.51.100.2 dev "$p1a"
	wait_ping "$ns_a" wga 10.210.0.2
	run "$ns_a" ping -4 -I wga -c 5 -W 2 10.210.0.2 >/dev/null
	packets_after=$(run "$ns_a" cat "/sys/class/net/$p1a/statistics/tx_packets")
	(( packets_after > packets_before )) || {
		echo "route replacement did not move TCP tunnel traffic to path1" >&2
		exit 1
	}
	after=$(wait_tcp_endpoint "$ns_a" 4 198.51.100.2 "$port" 198.51.100.1: "$before")
	printf 'mode=route\ntraffic_path=path1\nreconnected=true\nold_tcp_endpoint=%s\nnew_tcp_endpoint=%s\n' \
		"$before" "$after"
	;;
source-uplink)
	port=52202
	setup_ipv4_pair "$port"
	run "$ns_a" ip route add 192.0.2.0/24 via 198.51.100.2 dev "$p1a" metric 20
	wait_ping "$ns_a" wga 10.210.0.2
	initial=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" 192.0.2.1:)

	# Preserve the connected subnet while removing the address selected by
	# the established stream. The address notifier must reconnect via .9.
	run "$ns_a" sysctl -qw "net.ipv4.conf.$p0a.promote_secondaries=1"
	run "$ns_a" ip addr add 192.0.2.9/24 dev "$p0a"
	run "$ns_a" ip addr del 192.0.2.1/24 dev "$p0a"
	after_address=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" 192.0.2.9: "$initial")
	wait_ping "$ns_a" wga 10.210.0.2

	# The lower-metric path0 route becomes unusable when its link goes down;
	# reconnect must select the already-installed path1 route and source.
	run "$ns_a" ip link set "$p0a" down
	after_uplink=$(wait_tcp_endpoint "$ns_a" 4 192.0.2.2 "$port" 198.51.100.1: "$after_address")
	wait_ping "$ns_a" wga 10.210.0.2
	printf 'mode=source-uplink\nsource_reconnect=pass\nuplink_reconnect=pass\ninitial_tcp_endpoint=%s\naddress_tcp_endpoint=%s\nuplink_tcp_endpoint=%s\n' \
		"$initial" "$after_address" "$after_uplink"
	;;
carrier-lifetime)
	port=52203
	setup_ipv4_pair "$port"
	wait_ping "$ns_a" wga 10.210.0.2
	wait_ping "$ns_b" wgb 10.210.0.1
	before_a=$(wait_tcp_tuple_set "$ns_a" 4 2)
	before_b=$(wait_tcp_tuple_set "$ns_b" 4 2)
	for (( second = 0; second < 40; ++second )); do
		run "$ns_a" ping -4 -I wga -c 1 -W 2 10.210.0.2 >/dev/null
		run "$ns_b" ping -4 -I wgb -c 1 -W 2 10.210.0.1 >/dev/null
		sleep 1
	done
	after_a=$(wait_tcp_tuple_set "$ns_a" 4 2)
	after_b=$(wait_tcp_tuple_set "$ns_b" 4 2)
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
esac
