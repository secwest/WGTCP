#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

if (( EUID != 0 )); then
	echo "udp-compat-netns.sh must run as root" >&2
	exit 1
fi

for command in ip ping readlink ss; do
	command -v "$command" >/dev/null || {
		echo "missing required command: $command" >&2
		exit 1
	}
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WG_FORK=${WG_FORK:-$ROOT/tools/wg}
WG_STOCK=${WG_STOCK:-/usr/bin/wg}

[[ -x $WG_FORK ]] || {
	echo "modified wg tool is not executable: $WG_FORK" >&2
	exit 1
}
[[ -x $WG_STOCK ]] || {
	echo "stock wg tool is not executable: $WG_STOCK" >&2
	exit 1
}
[[ $(readlink -f "$WG_FORK") != $(readlink -f "$WG_STOCK") ]] || {
	echo "WG_FORK and WG_STOCK must be different binaries" >&2
	exit 1
}

suffix=$$
ns_a=wgudp-a-$suffix
ns_b=wgudp-b-$suffix
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
	local ns=$1
	shift
	ip netns exec "$ns" "$@"
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
	local ns=$1 iface=$2 destination=$3 deadline=$(( SECONDS + 60 ))
	while (( SECONDS < deadline )); do
		if run "$ns" ping -I "$iface" -c 1 -W 2 "$destination" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "TCP namespace tunnel did not reach $destination" >&2
	return 1
}

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

# Omitted ListenPort must retain stock port-zero/random-bind behavior.
run "$ns_a" ip link add wg0 type wireguard
run "$ns_a" ip link add wg1 type wireguard
[[ $(run "$ns_a" "$WG_FORK" show wg0 listen-port) == 0 ]]
[[ $(run "$ns_a" "$WG_FORK" show wg1 listen-port) == 0 ]]
# Prove that the loaded kernel implements the transport extension. The modified
# tool deliberately treats explicit UDP as a no-op on an unmodified kernel.
assert_quiet run "$ns_a" "$WG_FORK" set wg0 listen-port 51889 transport tcp
[[ $(run "$ns_a" "$WG_FORK" show wg0 transport) == tcp ]]
assert_quiet run "$ns_a" "$WG_FORK" set wg0 listen-port 0
run "$ns_a" ip link set wg0 up
isolated_tcp_port=$(run "$ns_a" "$WG_FORK" show wg0 listen-port)
(( isolated_tcp_port > 0 ))
[[ -n $(run "$ns_a" ss -H -ltn "sport = :$isolated_tcp_port") ]]
[[ -n $(run "$ns_a" ss -H -lun "sport = :$isolated_tcp_port") ]]
run "$ns_a" ip link set wg0 down
assert_quiet run "$ns_a" "$WG_FORK" set wg0 transport udp
[[ $(run "$ns_a" "$WG_FORK" show wg0 transport) == udp ]]
assert_quiet run "$ns_a" "$WG_FORK" set wg0 listen-port 0
run "$ns_a" ip link set wg0 up
run "$ns_a" ip link set wg1 up
port0=$(run "$ns_a" "$WG_FORK" show wg0 listen-port)
port1=$(run "$ns_a" "$WG_FORK" show wg1 listen-port)
(( port0 > 0 && port1 > 0 && port0 != port1 ))
assert_quiet run "$ns_a" "$WG_FORK" set wg0 listen-port 51888
[[ $(run "$ns_a" "$WG_FORK" show wg0 listen-port) == 51888 ]]
assert_quiet run "$ns_a" "$WG_FORK" set wg0 listen-port 0
(( $(run "$ns_a" "$WG_FORK" show wg0 listen-port) > 0 ))
run "$ns_a" ip link del wg0
run "$ns_a" ip link del wg1

! ip link show dev veth-a-$suffix >/dev/null 2>&1 || {
	echo "link already exists: veth-a-$suffix" >&2
	exit 1
}
! ip link show dev veth-b-$suffix >/dev/null 2>&1 || {
	echo "link already exists: veth-b-$suffix" >&2
	exit 1
}
record_owned extra-ifaces veth-a-$suffix
record_owned extra-ifaces veth-b-$suffix
ip link add veth-a-$suffix type veth peer name veth-b-$suffix
ip link set veth-a-$suffix netns "$ns_a"
ip link set veth-b-$suffix netns "$ns_b"
run "$ns_a" ip addr add 192.0.2.1/24 dev veth-a-$suffix
run "$ns_b" ip addr add 192.0.2.2/24 dev veth-b-$suffix
run "$ns_a" ip link set veth-a-$suffix up
run "$ns_b" ip link set veth-b-$suffix up

umask 077
"$WG_FORK" genkey >"$tmpdir/a.key"
"$WG_FORK" genkey >"$tmpdir/b.key"
a_pub=$("$WG_FORK" pubkey <"$tmpdir/a.key")
b_pub=$("$WG_FORK" pubkey <"$tmpdir/b.key")

run "$ns_a" ip link add wg-a type wireguard
run "$ns_b" ip link add wg-b type wireguard
assert_quiet run "$ns_a" "$WG_FORK" set wg-a private-key "$tmpdir/a.key"

assert_quiet run "$ns_b" "$WG_STOCK" set wg-b private-key "$tmpdir/b.key"

run "$ns_a" ip addr add 10.77.0.1/24 dev wg-a
run "$ns_b" ip addr add 10.77.0.2/24 dev wg-b
run "$ns_a" ip link set wg-a up
run "$ns_b" ip link set wg-b up
a_port=$(run "$ns_a" "$WG_FORK" show wg-a listen-port)
b_port=$(run "$ns_b" "$WG_FORK" show wg-b listen-port)

assert_quiet run "$ns_a" "$WG_FORK" set wg-a peer "$b_pub" \
	allowed-ips 10.77.0.2/32 endpoint 192.0.2.2:"$b_port"
assert_quiet run "$ns_b" "$WG_STOCK" set wg-b peer "$a_pub" \
	allowed-ips 10.77.0.1/32 endpoint 192.0.2.1:"$a_port"

run "$ns_a" ping -c 2 -W 2 10.77.0.2 >/dev/null
run "$ns_b" ping -c 2 -W 2 10.77.0.1 >/dev/null

[[ $(run "$ns_a" "$WG_FORK" showconf wg-a) != *Transport* ]]
[[ $(run "$ns_a" "$WG_FORK" show wg-a) != *transport:* ]]
[[ -n $(run "$ns_a" ss -H -lun "sport = :$a_port") ]]
[[ -n $(run "$ns_b" ss -H -lun "sport = :$b_port") ]]
[[ -z $(run "$ns_a" ss -H -ltn "sport = :$a_port") ]]
[[ -z $(run "$ns_b" ss -H -ltn "sport = :$b_port") ]]

[[ $(run "$ns_a" "$WG_FORK" show wg-a dump) == \
	$(run "$ns_a" "$WG_STOCK" show wg-a dump) ]]

# A TCP tunnel over namespace-only underlay addresses proves both accepted and
# outbound sockets live in the device's creation namespace. Neither address is
# routable from init_net.
run "$ns_a" ip link add wgtcp-a type wireguard
run "$ns_b" ip link add wgtcp-b type wireguard
assert_quiet run "$ns_a" "$WG_FORK" set wgtcp-a private-key "$tmpdir/a.key" \
	listen-port 0 transport tcp
assert_quiet run "$ns_b" "$WG_FORK" set wgtcp-b private-key "$tmpdir/b.key" \
	listen-port 0 transport tcp
run "$ns_a" ip addr add 10.77.1.1/24 dev wgtcp-a
run "$ns_b" ip addr add 10.77.1.2/24 dev wgtcp-b

# Bring each interface up to select its random companion UDP/TCP port. This
# mirrors the primary regression workflow, which adds peers after both
# listeners are available and then waits for the asynchronous TCP handshake.
run "$ns_a" ip link set wgtcp-a up
run "$ns_b" ip link set wgtcp-b up
tcp_a_port=$(run "$ns_a" "$WG_FORK" show wgtcp-a listen-port)
tcp_b_port=$(run "$ns_b" "$WG_FORK" show wgtcp-b listen-port)
(( tcp_a_port > 0 && tcp_b_port > 0 ))
[[ -n $(run "$ns_a" ss -H -ltn "sport = :$tcp_a_port") ]]
[[ -n $(run "$ns_b" ss -H -ltn "sport = :$tcp_b_port") ]]
assert_quiet run "$ns_a" "$WG_FORK" set wgtcp-a peer "$b_pub" \
	allowed-ips 10.77.1.2/32 endpoint 192.0.2.2:"$tcp_b_port" \
	persistent-keepalive 1
assert_quiet run "$ns_b" "$WG_FORK" set wgtcp-b peer "$a_pub" \
	allowed-ips 10.77.1.1/32 endpoint 192.0.2.1:"$tcp_a_port" \
	persistent-keepalive 1
wait_ping "$ns_a" wgtcp-a 10.77.1.2
wait_ping "$ns_b" wgtcp-b 10.77.1.1

# Exercise creation-namespace teardown independently of device lifetime. The
# interface survives in the keeper namespace, but every socket opened in its
# now-deleted creation namespace must be quiesced before that namespace exits.
ns_origin=wgorigin-$suffix
ns_keeper=wgkeeper-$suffix
! namespace_exists "$ns_origin" || {
	echo "network namespace already exists: $ns_origin" >&2
	exit 1
}
! namespace_exists "$ns_keeper" || {
	echo "network namespace already exists: $ns_keeper" >&2
	exit 1
}
record_owned netns "$ns_origin"
ip netns add "$ns_origin"
record_owned netns "$ns_keeper"
ip netns add "$ns_keeper"
run "$ns_origin" ip link set lo up
run "$ns_keeper" ip link set lo up
run "$ns_origin" ip link add wg-exit type wireguard
assert_quiet run "$ns_origin" "$WG_FORK" set wg-exit \
	listen-port 0 transport tcp
run "$ns_origin" ip link set wg-exit netns "$ns_keeper"
run "$ns_keeper" ip link set wg-exit up
exit_port=$(run "$ns_keeper" "$WG_FORK" show wg-exit listen-port)
(( exit_port > 0 ))
[[ -n $(run "$ns_origin" ss -H -ltn "sport = :$exit_port") ]]

ip netns del "$ns_origin"
! namespace_exists "$ns_origin"
run "$ns_keeper" ip link show dev wg-exit >/dev/null
[[ -z $(run "$ns_keeper" ss -H -ltn "sport = :$exit_port") ]]
run "$ns_keeper" ip link set wg-exit down
if output=$(run "$ns_keeper" ip link set wg-exit up 2>&1); then
	echo "TCP device reopened after its creation namespace exited" >&2
	exit 1
fi
[[ -n $output ]]
[[ $(run "$ns_keeper" cat /sys/class/net/wg-exit/operstate) == down ]]

echo "UDP compatibility and TCP namespace test: PASS"
