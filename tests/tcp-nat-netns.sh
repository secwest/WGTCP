#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

MODE=${1:-}
case "$MODE" in
dual-reachable) ;;
*)
	printf 'usage: %s {dual-reachable}\n' "$0" >&2
	exit 1
	;;
esac

if (( EUID != 0 )); then
	echo "tcp-nat-netns.sh must run as root" >&2
	exit 1
fi

for command in awk conntrack grep ip nft ping ss sysctl; do
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
ns_client=wgtcp-nc-$suffix
ns_router=wgtcp-nr-$suffix
ns_server=wgtcp-ns-$suffix
client_if=nci-$suffix
router_private_if=nri-$suffix
router_public_if=nre-$suffix
server_if=nse-$suffix
external_ownership=${WG_TEST_OWNERSHIP_DIR:-}
if [[ -n $external_ownership ]]; then
	[[ -d $external_ownership && -w $external_ownership ]] || {
		echo "ownership directory is unavailable: $external_ownership" >&2
		exit 1
	}
fi
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
ownership_dir=${external_ownership:-$tmpdir/ownership}
if [[ -z $external_ownership ]]; then
	install -d -m 0700 "$ownership_dir"
else
	ownership_dir=$external_ownership
fi

client_address=10.240.0.2
router_private_address=10.240.0.1
router_public_address=192.0.2.1
server_address=192.0.2.2
client_tunnel_address=10.212.0.1
server_tunnel_address=10.212.0.2
client_listen_port=52221
server_listen_port=52220
forwarded_port=52241
initial_snat_port=41001
rebound_snat_port=41002
initial_acquisition_timeout_seconds=90

namespace_exists() {
	ip netns list | awk -v target="$1" '$1 == target { found = 1 } END { exit found ? 0 : 1 }'
}

record_owned() {
	local kind=$1 name=$2
	printf '%s\n' "$name" >>"$ownership_dir/$kind"
}

run() {
	local namespace=$1
	shift
	ip netns exec "$namespace" "$@"
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
				printf '%s\n' "--- $namespace addresses and routes ---"
				ip -n "$namespace" -brief address
				ip -n "$namespace" -4 route show table all
				printf '%s\n' "--- $namespace public WireGuard state ---"
				run "$namespace" "$WG_FORK" show all listen-port
				run "$namespace" "$WG_FORK" show all endpoints
				printf '%s\n' "--- $namespace TCP sockets ---"
				run "$namespace" ss -H -lnt
				run "$namespace" ss -H -nto state established
			} >&2
		done
		if namespace_exists "$ns_router"; then
			{
				printf '%s\n' '--- NAT ruleset ---'
				run "$ns_router" nft -a list ruleset
				printf '%s\n' '--- NAT conntrack state ---'
				run "$ns_router" conntrack -L -p tcp
			} >&2
		fi
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
		echo "failed to remove one or more owned NAT test resources" >&2
		exit 1
	fi
	exit "$status"
}
trap cleanup EXIT

create_namespace() {
	local namespace=$1
	! namespace_exists "$namespace" || {
		echo "network namespace already exists: $namespace" >&2
		exit 1
	}
	record_owned netns "$namespace"
	ip netns add "$namespace"
	run "$namespace" ip link set lo up
}

record_link_names() {
	local iface
	for iface in "$@"; do
		! ip link show dev "$iface" >/dev/null 2>&1 || {
			echo "link already exists: $iface" >&2
			exit 1
		}
		record_owned extra-ifaces "$iface"
	done
}

wait_ping() {
	local namespace=$1 iface=$2 destination=$3
	local deadline=${4:-0} timeout_seconds=60
	if (( deadline > 0 )); then
		timeout_seconds=$(( deadline - SECONDS ))
		(( timeout_seconds > 0 )) || timeout_seconds=0
	else
		deadline=$(( SECONDS + timeout_seconds ))
	fi
	while (( SECONDS < deadline )); do
		if run "$namespace" ping -4 -I "$iface" -c 1 -W 2 \
			"$destination" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "TCP tunnel did not reach $destination within ${timeout_seconds} seconds" >&2
	return 1
}

tcp_tuple_present() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3
	run "$namespace" ss -H -tn4 state established | awk \
		-v local="$local_endpoint" -v remote="$remote_endpoint" '
		{
			local_seen = remote_seen = 0
			for (i = 1; i <= NF; ++i) {
				if ($i == local) local_seen = 1
				if ($i == remote) remote_seen = 1
			}
			if (local_seen && remote_seen) found = 1
		}
		END { exit found ? 0 : 1 }
	'
}

wait_tcp_tuple() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3
	local deadline=${4:-0} timeout_seconds=60
	if (( deadline > 0 )); then
		timeout_seconds=$(( deadline - SECONDS ))
		(( timeout_seconds > 0 )) || timeout_seconds=0
	else
		deadline=$(( SECONDS + timeout_seconds ))
	fi
	while (( SECONDS < deadline )); do
		if tcp_tuple_present "$namespace" "$local_endpoint" "$remote_endpoint"; then
			return 0
		fi
		sleep 1
	done
	echo "TCP tuple did not become established within ${timeout_seconds} seconds: $local_endpoint <-> $remote_endpoint" >&2
	return 1
}

wait_tcp_remote() {
	local namespace=$1 remote_endpoint=$2
	local deadline=${3:-0} timeout_seconds=60
	if (( deadline > 0 )); then
		timeout_seconds=$(( deadline - SECONDS ))
		(( timeout_seconds > 0 )) || timeout_seconds=0
	else
		deadline=$(( SECONDS + timeout_seconds ))
	fi
	while (( SECONDS < deadline )); do
		if run "$namespace" ss -H -tn4 state established | \
			awk -v remote="$remote_endpoint" '
			{
				for (i = 1; i <= NF; ++i)
					if ($i == remote) found = 1
			}
			END { exit found ? 0 : 1 }
		'; then
			return 0
		fi
		sleep 1
	done
	echo "no established TCP stream to $remote_endpoint within ${timeout_seconds} seconds" >&2
	return 1
}

tcp_local_endpoint() {
	local namespace=$1 remote_endpoint=$2
	run "$namespace" ss -H -tn4 state established | awk \
		-v remote="$remote_endpoint" '
		{
			count = 0
			for (i = 1; i <= NF; ++i) {
				if ($i ~ /:[0-9]+$/)
					endpoint[++count] = $i
			}
			if (count >= 2 && endpoint[count] == remote) {
				print endpoint[count - 1]
				exit
			}
			delete endpoint
		}
	'
}

peer_endpoint() {
	local namespace=$1 iface=$2 public_key=$3
	run "$namespace" "$WG_FORK" show "$iface" endpoints | \
		awk -v key="$public_key" '$1 == key { print $2 }'
}

sent_bytes() {
	local namespace=$1 iface=$2 public_key=$3
	run "$namespace" "$WG_FORK" show "$iface" transfer | \
		awk -v key="$public_key" '$1 == key { print $3 }'
}

wait_keepalive_advance() {
	local namespace=$1 iface=$2 public_key=$3 before=$4
	local deadline=$(( SECONDS + 45 )) observed
	while (( SECONDS < deadline )); do
		observed=$(sent_bytes "$namespace" "$iface" "$public_key")
		if [[ $observed =~ ^[0-9]+$ ]] && (( observed > before )); then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "persistent keepalive did not advance transfer bytes within 45 seconds" >&2
	return 1
}

nat_rule_packets() {
	local chain=$1 port=$2 action=$3
	run "$ns_router" nft -a list chain ip wgtcp_nat "$chain" | awk \
		-v port="$port" -v action="$action" '
		index($0, "dport " port) && index($0, action) {
			for (i = 1; i <= NF; ++i)
				if ($i == "packets") { print $(i + 1); exit }
		}
	'
}

install_snat_rule() {
	local translated_port=$1
	run "$ns_router" nft add rule ip wgtcp_nat postrouting \
		oifname "$router_public_if" ip saddr "$client_address" \
		ip daddr "$server_address" tcp dport "$server_listen_port" \
		counter snat to "$router_public_address:$translated_port"
}

replace_snat_rule() {
	local translated_port=$1 handle
	handle=$(run "$ns_router" nft -a list chain ip wgtcp_nat postrouting | \
		awk 'index($0, "snat") {
			for (i = 1; i <= NF; ++i)
				if ($i == "handle") { print $(i + 1); exit }
		}')
	[[ $handle =~ ^[0-9]+$ ]] || {
		echo "could not identify the owned SNAT rule handle" >&2
		exit 1
	}
	run "$ns_router" nft replace rule ip wgtcp_nat postrouting \
		handle "$handle" oifname "$router_public_if" \
		ip saddr "$client_address" ip daddr "$server_address" \
		tcp dport "$server_listen_port" counter snat to \
		"$router_public_address:$translated_port"
}

forward_syn_packets() {
	run "$ns_router" nft -a list chain ip wgtcp_nat forward | awk \
		-v port="$client_listen_port" '
		index($0, "dport " port) && index($0, "flags syn") {
			for (i = 1; i <= NF; ++i)
				if ($i == "packets") { print $(i + 1); exit }
		}
	'
}

wait_forward_syn_advance() {
	local before=$1 deadline=$(( SECONDS + 60 )) observed
	while (( SECONDS < deadline )); do
		observed=$(forward_syn_packets)
		if [[ $observed =~ ^[0-9]+$ ]] && (( observed > before )); then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "reverse reconnect did not send a new SYN through the configured forward" >&2
	return 1
}

assert_nat_state() {
	local translated_port=$1 acquisition_deadline=${2:-0}
	local expected_endpoint conntrack_state dnat_packets snat_packets
	wait_tcp_tuple "$ns_server" "$server_address:$server_listen_port" \
		"$router_public_address:$translated_port" "$acquisition_deadline"
	wait_tcp_remote "$ns_server" "$router_public_address:$forwarded_port" \
		"$acquisition_deadline"
	expected_endpoint="$router_public_address:$forwarded_port"
	[[ $(peer_endpoint "$ns_server" wgb "$client_pub") == "$expected_endpoint" ]] || {
		echo "observed NAT source port replaced configured dial target $expected_endpoint" >&2
		exit 1
	}
	[[ $(peer_endpoint "$ns_client" wga "$server_pub") == \
		"$server_address:$server_listen_port" ]] || {
		echo "client dial target changed unexpectedly" >&2
		exit 1
	}
	dnat_packets=$(nat_rule_packets prerouting "$forwarded_port" "dnat")
	snat_packets=$(nat_rule_packets postrouting "$server_listen_port" "snat")
	[[ $dnat_packets =~ ^[0-9]+$ ]] && (( dnat_packets > 0 )) || {
		echo "DNAT rule did not translate an inbound TCP carrier" >&2
		exit 1
	}
	[[ $snat_packets =~ ^[0-9]+$ ]] && (( snat_packets > 0 )) || {
		echo "SNAT rule did not translate an outbound TCP carrier" >&2
		exit 1
	}
	conntrack_state=$(run "$ns_router" conntrack -L -p tcp 2>/dev/null)
	grep -Eq "src=$client_address dst=$server_address .*dport=$server_listen_port .*dst=$router_public_address .*dport=$translated_port" \
		<<<"$conntrack_state" || {
		echo "conntrack did not contain the expected SNAT tuple" >&2
		exit 1
	}
	grep -Eq "src=$server_address dst=$router_public_address .*dport=$forwarded_port .*src=$client_address dst=$server_address .*sport=$client_listen_port" \
		<<<"$conntrack_state" || {
		echo "conntrack did not contain the expected DNAT tuple" >&2
		exit 1
	}
}

create_namespace "$ns_client"
create_namespace "$ns_router"
create_namespace "$ns_server"
record_link_names "$client_if" "$router_private_if" "$router_public_if" "$server_if"
ip link add "$client_if" type veth peer name "$router_private_if"
ip link add "$router_public_if" type veth peer name "$server_if"
ip link set "$client_if" netns "$ns_client"
ip link set "$router_private_if" netns "$ns_router"
ip link set "$router_public_if" netns "$ns_router"
ip link set "$server_if" netns "$ns_server"

run "$ns_client" ip addr add "$client_address/24" dev "$client_if"
run "$ns_router" ip addr add "$router_private_address/24" dev "$router_private_if"
run "$ns_router" ip addr add "$router_public_address/24" dev "$router_public_if"
run "$ns_server" ip addr add "$server_address/24" dev "$server_if"
for namespace_iface in \
	"$ns_client $client_if" \
	"$ns_router $router_private_if" \
	"$ns_router $router_public_if" \
	"$ns_server $server_if"; do
	read -r namespace iface <<<"$namespace_iface"
	run "$namespace" ip link set "$iface" up
done
run "$ns_client" ip route add default via "$router_private_address" dev "$client_if"
run "$ns_router" sysctl -qw net.ipv4.ip_forward=1

run "$ns_router" nft add table ip wgtcp_nat
run "$ns_router" nft add chain ip wgtcp_nat prerouting \
	'{ type nat hook prerouting priority dstnat; policy accept; }'
run "$ns_router" nft add chain ip wgtcp_nat postrouting \
	'{ type nat hook postrouting priority srcnat; policy accept; }'
run "$ns_router" nft add chain ip wgtcp_nat forward \
	'{ type filter hook forward priority filter; policy accept; }'
run "$ns_router" nft add rule ip wgtcp_nat prerouting \
	iifname "$router_public_if" ip daddr "$router_public_address" \
	tcp dport "$forwarded_port" counter dnat to \
	"$client_address:$client_listen_port"
run "$ns_router" nft add rule ip wgtcp_nat forward \
	iifname "$router_public_if" ip daddr "$client_address" \
	tcp dport "$client_listen_port" tcp flags syn counter accept
install_snat_rule "$initial_snat_port"

umask 077
"$WG_FORK" genkey >"$tmpdir/client.key"
"$WG_FORK" genkey >"$tmpdir/server.key"
client_pub=$("$WG_FORK" pubkey <"$tmpdir/client.key")
server_pub=$("$WG_FORK" pubkey <"$tmpdir/server.key")

run "$ns_client" ip link add wga type wireguard
run "$ns_server" ip link add wgb type wireguard
run "$ns_client" "$WG_FORK" set wga private-key "$tmpdir/client.key" \
	listen-port "$client_listen_port" transport tcp
run "$ns_server" "$WG_FORK" set wgb private-key "$tmpdir/server.key" \
	listen-port "$server_listen_port" transport tcp
run "$ns_client" ip addr add "$client_tunnel_address/32" dev wga
run "$ns_server" ip addr add "$server_tunnel_address/32" dev wgb
run "$ns_client" ip link set wga up
run "$ns_server" ip link set wgb up
run "$ns_client" ip route add "$server_tunnel_address/32" dev wga
run "$ns_server" ip route add "$client_tunnel_address/32" dev wgb
initial_snat_packets_before=$(nat_rule_packets postrouting \
	"$server_listen_port" "snat")
initial_dnat_packets_before=$(nat_rule_packets prerouting \
	"$forwarded_port" "dnat")
[[ $initial_snat_packets_before =~ ^[0-9]+$ && \
	$initial_dnat_packets_before =~ ^[0-9]+$ ]] || {
	echo "could not read initial NAT rule-packet baselines" >&2
	exit 1
}
initial_acquisition_started=$SECONDS
initial_acquisition_deadline=$(( SECONDS + initial_acquisition_timeout_seconds ))
run "$ns_client" "$WG_FORK" set wga peer "$server_pub" \
	allowed-ips "$server_tunnel_address/32" \
	endpoint "$server_address:$server_listen_port" persistent-keepalive 2
run "$ns_server" "$WG_FORK" set wgb peer "$client_pub" \
	allowed-ips "$client_tunnel_address/32" \
	endpoint "$router_public_address:$forwarded_port" persistent-keepalive 2

wait_ping "$ns_client" wga "$server_tunnel_address" \
	"$initial_acquisition_deadline"
wait_ping "$ns_server" wgb "$client_tunnel_address" \
	"$initial_acquisition_deadline"
assert_nat_state "$initial_snat_port" "$initial_acquisition_deadline"
initial_acquisition_seconds=$(( SECONDS - initial_acquisition_started ))
initial_snat_packets_after=$(nat_rule_packets postrouting \
	"$server_listen_port" "snat")
initial_dnat_packets_after=$(nat_rule_packets prerouting \
	"$forwarded_port" "dnat")
[[ $initial_snat_packets_after =~ ^[0-9]+$ && \
	$initial_dnat_packets_after =~ ^[0-9]+$ && \
	$initial_snat_packets_after -gt $initial_snat_packets_before && \
	$initial_dnat_packets_after -gt $initial_dnat_packets_before ]] || {
	echo "initial TCP carrier acquisition did not advance both NAT rules" >&2
	exit 1
}

client_tx_before=$(sent_bytes "$ns_client" wga "$server_pub")
server_tx_before=$(sent_bytes "$ns_server" wgb "$client_pub")
[[ $client_tx_before =~ ^[0-9]+$ && $server_tx_before =~ ^[0-9]+$ ]] || {
	echo "could not read initial WireGuard transfer counters" >&2
	exit 1
}
client_tx_after=$(wait_keepalive_advance "$ns_client" wga "$server_pub" "$client_tx_before")
server_tx_after=$(wait_keepalive_advance "$ns_server" wgb "$client_pub" "$server_tx_before")
wait_ping "$ns_client" wga "$server_tunnel_address"
wait_ping "$ns_server" wgb "$client_tunnel_address"

# Atomically replace this namespace's SNAT rule before flushing conntrack, so a
# two-second keepalive cannot recreate the old mapping in a rule-update gap.
# The next packet on the old client-originated stream is translated with a
# different source port, so the remote TCP stack rejects it and the transport's
# live error path must reconnect. The public peer must not mistake that observed
# source port for the private peer's configured forwarded listen port.
replace_snat_rule "$rebound_snat_port"
run "$ns_router" conntrack -F >/dev/null
wait_ping "$ns_client" wga "$server_tunnel_address"
wait_ping "$ns_server" wgb "$client_tunnel_address"
assert_nat_state "$rebound_snat_port"

# Prove the preserved configured target is usable for a future reverse dial,
# rather than checking only its netlink representation. A live mark change uses
# the normal reconnect owner; a namespace-local counter must observe a new SYN
# through the NAT's configured forwarded port. The local TCP port is diagnostic
# only because Linux may legally reuse a closed four-tuple.
reverse_remote="$router_public_address:$forwarded_port"
reverse_before=$(tcp_local_endpoint "$ns_server" "$reverse_remote")
[[ -n $reverse_before ]] || {
	echo "could not capture the pre-reconnect reverse carrier" >&2
	exit 1
}
reverse_syn_before=$(forward_syn_packets)
[[ $reverse_syn_before =~ ^[0-9]+$ ]] || {
	echo "could not read the reverse-dial SYN counter" >&2
	exit 1
}
run "$ns_server" "$WG_FORK" set wgb fwmark 0x52241
reverse_syn_after=$(wait_forward_syn_advance "$reverse_syn_before")
wait_tcp_remote "$ns_server" "$reverse_remote"
reverse_after=$(tcp_local_endpoint "$ns_server" "$reverse_remote")
wait_ping "$ns_client" wga "$server_tunnel_address"
wait_ping "$ns_server" wgb "$client_tunnel_address"
assert_nat_state "$rebound_snat_port"
if tcp_tuple_present "$ns_server" "$server_address:$server_listen_port" \
	"$router_public_address:$initial_snat_port"; then
	old_carrier_state=retained
else
	old_carrier_state=retired
fi

printf 'mode=dual-reachable\n'
printf 'snat=pass\ndnat=pass\nbidirectional_traffic=pass\n'
printf 'initial_acquisition_timeout_seconds=%s\n' \
	"$initial_acquisition_timeout_seconds"
printf 'initial_acquisition_seconds=%s\n' "$initial_acquisition_seconds"
printf 'initial_snat_rule_packets=%s->%s\n' \
	"$initial_snat_packets_before" "$initial_snat_packets_after"
printf 'initial_dnat_rule_packets=%s->%s\n' \
	"$initial_dnat_packets_before" "$initial_dnat_packets_after"
printf 'persistent_keepalive=pass\nkeepalive_client_tx=%s->%s\n' \
	"$client_tx_before" "$client_tx_after"
printf 'keepalive_server_tx=%s->%s\n' "$server_tx_before" "$server_tx_after"
printf 'source_port_rebind=%s->%s\n' "$initial_snat_port" "$rebound_snat_port"
printf 'configured_forward_port=%s\nconfigured_port_preserved=pass\n' "$forwarded_port"
printf 'reverse_dial_reconnect=pass\nreverse_dial_syns=%s->%s\n' \
	"$reverse_syn_before" "$reverse_syn_after"
printf 'reverse_dial_tuple=%s->%s\n' "$reverse_before" "$reverse_after"
printf 'old_accepted_carrier=%s\n' "$old_carrier_state"
