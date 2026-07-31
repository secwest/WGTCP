#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

MODE=${1:-}
case "$MODE" in
dual-router | half-open) ;;
*)
	printf 'usage: %s {dual-router|half-open}\n' "$0" >&2
	exit 1
	;;
esac

if (( EUID != 0 )); then
	echo "tcp-roaming-netns.sh must run as root" >&2
	exit 1
fi

for command in awk conntrack date grep ip nft ping sort ss sysctl tc; do
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
printf -v tag '%05d' "$(( suffix % 100000 ))"
ns_client=wgtcp-rc-$suffix
ns_old_router=wgtcp-ro-$suffix
ns_new_router=wgtcp-rn-$suffix
ns_public=wgtcp-rp-$suffix
ns_server=wgtcp-rs-$suffix

client_old_if=co$tag
old_private_if=op$tag
old_public_if=oe$tag
old_fabric_if=of$tag
client_new_if=cn$tag
new_private_if=np$tag
new_public_if=ne$tag
new_fabric_if=nf$tag
server_public_if=se$tag
server_fabric_if=sf$tag
public_bridge=br0

external_ownership=${WG_TEST_OWNERSHIP_DIR:-}
if [[ -n $external_ownership ]]; then
	[[ -d $external_ownership && -w $external_ownership ]] || {
		echo "ownership directory is unavailable: $external_ownership" >&2
		exit 1
	}
fi
tmpdir=$(mktemp -d)
ownership_dir=${external_ownership:-$tmpdir/ownership}
if [[ -z $external_ownership ]]; then
	install -d -m 0700 "$ownership_dir"
fi

client_old_address=10.240.0.2
old_private_address=10.240.0.1
old_client_subnet=10.240.0.0/24
client_new_address=10.241.0.2
new_private_address=10.241.0.1
new_client_subnet=10.241.0.0/24
old_public_address=192.0.2.1
new_public_address=192.0.2.129
server_address=192.0.2.2
client_tunnel_address=10.212.0.1
server_tunnel_address=10.212.0.2
new_client_tunnel_address=10.213.0.1
new_server_tunnel_address=10.213.0.2
client_listen_port=52221
new_client_listen_port=52222
server_listen_port=52220
forwarded_port=52241
old_snat_port=41001
new_snat_port=41002
stale_delay_seconds=110
stale_enqueue_timeout_seconds=8
pre_stage_carrier_quiet_seconds=12
pre_stage_carrier_timeout_seconds=30
route_notifier_minimum_settle_seconds=1
carrier_auth_quiet_seconds=12
carrier_auth_acquisition_timeout_seconds=60
rekey_timeout_seconds=5
quiet_window_seconds=16
quiet_acquisition_timeout_seconds=35
pre_fwmark_acquisition_timeout_seconds=45
old_key_stage_max_age_seconds=90
reject_after_time_seconds=180
stale_monitor_margin_seconds=6
forced_server_fwmark=0x52241
old_client_fwmark=0x240
new_client_fwmark=0x241
old_client_route_table=240
new_client_route_table=241

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
				printf '%s\n' "--- $namespace WireGuard state ---"
				run "$namespace" "$WG_FORK" show all listen-port
				run "$namespace" "$WG_FORK" show all endpoints
				run "$namespace" "$WG_FORK" show all transfer
				printf '%s\n' "--- $namespace TCP sockets ---"
				run "$namespace" ss -H -lnt
				run "$namespace" ss -H -nto state established
			} >&2
		done
		for namespace in "$ns_old_router" "$ns_new_router"; do
			namespace_exists "$namespace" || continue
			{
				printf '%s\n' "--- $namespace NAT ruleset ---"
				run "$namespace" nft -a list ruleset
				printf '%s\n' "--- $namespace conntrack state ---"
				run "$namespace" conntrack -L -p tcp
				printf '%s\n' "--- $namespace qdiscs ---"
				run "$namespace" tc -s qdisc show
			} >&2
		done
		if namespace_exists "$ns_public"; then
			{
				printf '%s\n' "--- $ns_public server-fabric qdisc ---"
				run "$ns_public" tc -s qdisc show dev "$server_fabric_if"
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
		echo "failed to remove one or more owned TCP roaming resources" >&2
		exit 1
	fi
	exit "$status"
}
trap cleanup EXIT

report_error() {
	local status=$?

	printf 'tcp-roaming-netns.sh failed at line %s: %s (status %s)\n' \
		"${BASH_LINENO[0]}" "$BASH_COMMAND" "$status" >&2
	return "$status"
}
trap report_error ERR

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
	local deadline=$(( SECONDS + 60 ))

	while (( SECONDS < deadline )); do
		if run "$namespace" ping -4 -I "$iface" -c 1 -W 2 \
			"$destination" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "TCP tunnel did not reach $destination within 60 seconds" >&2
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
	local deadline=$(( SECONDS + ${4:-60} ))

	while (( SECONDS < deadline )); do
		if tcp_tuple_present "$namespace" "$local_endpoint" "$remote_endpoint"; then
			return 0
		fi
		sleep 1
	done
	echo "TCP tuple did not become established: $local_endpoint <-> $remote_endpoint" >&2
	return 1
}

wait_tcp_remote() {
	local namespace=$1 remote_endpoint=$2
	local deadline=$(( SECONDS + ${3:-60} ))

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
	echo "no established TCP stream to $remote_endpoint" >&2
	return 1
}

peer_endpoint() {
	local namespace=$1 iface=$2 public_key=$3

	run "$namespace" "$WG_FORK" show "$iface" endpoints | \
		awk -v key="$public_key" '$1 == key { print $2 }'
}

wait_peer_endpoint() {
	local namespace=$1 iface=$2 public_key=$3 expected=$4
	local deadline=$(( SECONDS + ${5:-60} )) observed

	while (( SECONDS < deadline )); do
		observed=$(peer_endpoint "$namespace" "$iface" "$public_key")
		[[ $observed == "$expected" ]] && return 0
		sleep 1
	done
	echo "peer endpoint did not become $expected" >&2
	return 1
}

received_bytes() {
	local namespace=$1 iface=$2 public_key=$3

	run "$namespace" "$WG_FORK" show "$iface" transfer | \
		awk -v key="$public_key" '$1 == key { print $2 }'
}

sent_bytes() {
	local namespace=$1 iface=$2 public_key=$3

	run "$namespace" "$WG_FORK" show "$iface" transfer | \
		awk -v key="$public_key" '$1 == key { print $3 }'
}

latest_handshake() {
	local namespace=$1 iface=$2 public_key=$3

	run "$namespace" "$WG_FORK" show "$iface" latest-handshakes | \
		awk -v key="$public_key" '
			$1 == key { value = $2; found = 1 }
			END { print found ? value : 0 }
		'
}

qdisc_backlog_packets() {
	local namespace=$1 iface=$2 handle=$3

	run "$namespace" tc -s qdisc show dev "$iface" | awk \
		-v wanted="$handle" '
		$1 == "qdisc" {
			selected = ($3 == wanted)
			next
		}
		selected && $1 == "backlog" && !found {
			packets = $3
			sub(/p$/, "", packets)
			found = 1
		}
		END { if (found) print packets + 0 }
	'
}

nat_rule_packets() {
	local namespace=$1 chain=$2 port=$3 action=$4

	run "$namespace" nft -a list chain ip wgtcp_roam "$chain" | awk \
		-v port="$port" -v action="$action" '
		index($0, "dport " port) && index($0, action) {
			for (i = 1; i <= NF; ++i)
				if ($i == "packets" && !found) {
					packets = $(i + 1)
					found = 1
				}
		}
		END { if (found) print packets }
	'
}

install_server_inner_probe_counter() {
	run "$ns_server" nft add table ip wgtcp_inner
	run "$ns_server" nft add chain ip wgtcp_inner input \
		'{ type filter hook input priority -10; policy accept; }'
	run "$ns_server" nft add rule ip wgtcp_inner input \
		iifname wgb ip saddr "$client_tunnel_address" \
		ip daddr "$server_tunnel_address" \
		icmp type echo-request counter
}

server_old_echo_packets() {
	run "$ns_server" nft -a list chain ip wgtcp_inner input | awk \
		-v source="$client_tunnel_address" \
		-v destination="$server_tunnel_address" '
		index($0, "iifname \"wgb\"") &&
		index($0, "ip saddr " source) &&
		index($0, "ip daddr " destination) &&
		index($0, "icmp type echo-request") {
			for (i = 1; i <= NF; ++i)
				if ($i == "packets" && !found) {
					packets = $(i + 1)
					found = 1
				}
		}
		END { if (found) print packets }
	'
}

wait_nat_counter_advance() {
	local namespace=$1 chain=$2 port=$3 action=$4 before=$5
	local deadline=$(( SECONDS + ${6:-60} )) observed

	while (( SECONDS < deadline )); do
		observed=$(nat_rule_packets "$namespace" "$chain" "$port" "$action")
		if [[ $observed =~ ^[0-9]+$ ]] && (( observed > before )); then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "NAT $action counter for port $port did not advance" >&2
	return 1
}

install_nat() {
	local namespace=$1 public_if=$2 public_address=$3
	local private_address=$4 translated_port=$5
	local target_listen_port=${6:-$client_listen_port}

	run "$namespace" nft add table ip wgtcp_roam
	run "$namespace" nft add chain ip wgtcp_roam prerouting \
		'{ type nat hook prerouting priority dstnat; policy accept; }'
	run "$namespace" nft add chain ip wgtcp_roam postrouting \
		'{ type nat hook postrouting priority srcnat; policy accept; }'
	# A NAT chain sees the first packet of a flow. Matching SYN makes this
	# counter an explicit reverse-connect observation rather than a byte total.
	run "$namespace" nft add rule ip wgtcp_roam prerouting \
		iifname "$public_if" ip daddr "$public_address" \
		tcp dport "$forwarded_port" \
		'tcp flags & (fin | syn | rst | ack) == syn' \
		counter dnat to "$private_address:$target_listen_port"
	if [[ $translated_port == dynamic ]]; then
		run "$namespace" nft add rule ip wgtcp_roam postrouting \
			oifname "$public_if" ip saddr "$private_address" \
			ip daddr "$server_address" tcp dport "$server_listen_port" \
			counter snat to "$public_address"
	else
		run "$namespace" nft add rule ip wgtcp_roam postrouting \
			oifname "$public_if" ip saddr "$private_address" \
			ip daddr "$server_address" tcp dport "$server_listen_port" \
			counter snat to "$public_address:$translated_port"
	fi
}

assert_nat_state() {
	local namespace=$1 private_address=$2 public_address=$3 translated_port=$4
	local target_listen_port=${5:-$client_listen_port}
	local conntrack_state

	conntrack_state=$(run "$namespace" conntrack -L -p tcp 2>/dev/null)
	grep -Eq "src=$private_address dst=$server_address .*dport=$server_listen_port .*dst=$public_address .*dport=$translated_port" \
		<<<"$conntrack_state" || {
		echo "conntrack lacks SNAT $public_address:$translated_port" >&2
		return 1
	}
	grep -Eq "src=$server_address dst=$public_address .*dport=$forwarded_port .*src=$private_address dst=$server_address .*sport=$target_listen_port" \
		<<<"$conntrack_state" || {
		echo "conntrack lacks DNAT $public_address:$forwarded_port" >&2
		return 1
	}
}

tcp_remote_for_local() {
	local namespace=$1 local_endpoint=$2 remote_address=$3

	run "$namespace" ss -H -tn4 state established | awk \
		-v local="$local_endpoint" -v prefix="$remote_address:" '
		{
			local_seen = 0
			remote = ""
			for (i = 1; i <= NF; ++i) {
				if ($i == local) local_seen = 1
				if (index($i, prefix) == 1) remote = $i
			}
			if (local_seen && remote != "" && !found) {
				answer = remote
				found = 1
			}
		}
		END { if (found) print answer }
	'
}

tcp_remotes_for_local() {
	local namespace=$1 local_endpoint=$2 remote_address=$3

	run "$namespace" ss -H -tn4 state established | awk \
		-v local="$local_endpoint" -v prefix="$remote_address:" '
		{
			local_seen = 0
			remote = ""
			for (i = 1; i <= NF; ++i) {
				if ($i == local) local_seen = 1
				if (index($i, prefix) == 1) remote = $i
			}
			if (local_seen && remote != "") print remote
		}
	' | sort -u
}

wait_tcp_remote_for_local() {
	local namespace=$1 local_endpoint=$2 remote_address=$3
	local deadline=$(( SECONDS + ${4:-60} )) observed

	while (( SECONDS < deadline )); do
		observed=$(tcp_remote_for_local "$namespace" "$local_endpoint" \
			"$remote_address")
		if [[ -n $observed ]]; then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "no established TCP tuple from $remote_address to $local_endpoint" >&2
	return 1
}

wait_different_tcp_remote() {
	local namespace=$1 local_endpoint=$2 remote_address=$3 old_remote=$4
	local deadline=$(( SECONDS + ${5:-60} )) observed

	while (( SECONDS < deadline )); do
		observed=$(run "$namespace" ss -H -tn4 state established | awk \
			-v local="$local_endpoint" -v prefix="$remote_address:" \
			-v old="$old_remote" '
			{
				local_seen = 0
				remote = ""
				for (i = 1; i <= NF; ++i) {
					if ($i == local) local_seen = 1
					if (index($i, prefix) == 1 && $i != old) remote = $i
				}
				if (local_seen && remote != "" && !found) {
					answer = remote
					found = 1
				}
			}
			END { if (found) print answer }
		')
		if [[ -n $observed ]]; then
			printf '%s\n' "$observed"
			return 0
		fi
		sleep 1
	done
	echo "replacement TCP tuple did not differ from $old_remote" >&2
	return 1
}

tcp_snmp_value() {
	local namespace=$1 field=$2

	run "$namespace" awk -v wanted="$field" '
		$1 == "Tcp:" && !have_header {
			for (i = 2; i <= NF; ++i) names[i] = $i
			have_header = 1
			next
		}
		$1 == "Tcp:" && have_header {
			for (i = 2; i <= NF; ++i)
				if (names[i] == wanted) { print $i; exit }
		}
	' /proc/net/snmp
}

capture_ss_snapshot() {
	local label=$1

	run "$ns_client" ss -Htin4 >"$tmpdir/$label-client.ss"
	run "$ns_server" ss -Htin4 >"$tmpdir/$label-server.ss"
}

snapshot_lines() {
	awk 'END { print NR + 0 }' "$1"
}

nonempty_line_count() {
	awk 'NF { ++count } END { print count + 0 }'
}

server_accepted_remotes() {
	run "$ns_server" ss -H -tn4 state established | awk \
		-v local="$server_address:$server_listen_port" '
		{
			local_seen = 0
			remote = ""
			for (i = 1; i <= NF; ++i) {
				if ($i == local) local_seen = 1
				if ($i != local &&
				    $i ~ /^[0-9][0-9.]*:[0-9][0-9]*$/) remote = $i
			}
			if (local_seen && remote != "") print remote
		}
	' | sort -u
}

client_outbound_locals() {
	run "$ns_client" ss -H -tn4 state established | awk \
		-v remote="$server_address:$server_listen_port" '
		{
			remote_seen = 0
			local = ""
			for (i = 1; i <= NF; ++i) {
				if ($i == remote) remote_seen = 1
				if ($i != remote &&
				    $i ~ /^[0-9][0-9.]*:[0-9][0-9]*$/) local = $i
			}
			if (remote_seen && local != "") print local
		}
	' | sort -u
}

tcp_state_count() {
	local namespace=$1 state=$2

	run "$namespace" ss -H -tn4 state "$state" | \
		awk 'END { print NR + 0 }'
}

line_set_contains() {
	local line_set=$1 wanted=$2

	grep -Fxq -- "$wanted" <<<"$line_set"
}

conntrack_server_remote_for_client_local() {
	local client_local=$1 client_port=${1##*:}

	run "$ns_old_router" conntrack -L -p tcp 2>/dev/null | awk \
		-v client="$client_old_address" -v client_port="$client_port" \
		-v server="$server_address" -v server_port="$server_listen_port" \
		-v public="$old_public_address" '
		{
			orig_src = orig_dst = orig_sport = orig_dport = ""
			reply_src = reply_dst = reply_sport = reply_dport = ""
			src_count = dst_count = sport_count = dport_count = 0
			for (i = 1; i <= NF; ++i) {
				if ($i ~ /^src=/) {
					value = substr($i, 5)
					if (++src_count == 1) orig_src = value
					else if (src_count == 2) reply_src = value
				} else if ($i ~ /^dst=/) {
					value = substr($i, 5)
					if (++dst_count == 1) orig_dst = value
					else if (dst_count == 2) reply_dst = value
				} else if ($i ~ /^sport=/) {
					value = substr($i, 7)
					if (++sport_count == 1) orig_sport = value
					else if (sport_count == 2) reply_sport = value
				} else if ($i ~ /^dport=/) {
					value = substr($i, 7)
					if (++dport_count == 1) orig_dport = value
					else if (dport_count == 2) reply_dport = value
				}
			}
			if (orig_src == client && orig_dst == server &&
			    orig_sport == client_port && orig_dport == server_port &&
			    reply_src == server && reply_dst == public &&
			    reply_sport == server_port && reply_dport != "")
				print public ":" reply_dport
		}
	' | sort -u
}

wait_correlated_recovery_pair() {
	local excluded_clients=$1 excluded_servers=$2
	local deadline=$(( SECONDS + ${3:-60} ))
	local candidate current mapped mapped_count
	local reverse_server_locals reverse_client_remotes

	while (( SECONDS < deadline )); do
		current=$(client_outbound_locals)
		while IFS= read -r candidate; do
			[[ -n $candidate ]] || continue
			line_set_contains "$excluded_clients" "$candidate" && continue
			mapped=$(conntrack_server_remote_for_client_local "$candidate")
			mapped_count=$(nonempty_line_count <<<"$mapped")
			(( mapped_count == 1 )) || continue
			line_set_contains "$excluded_servers" "$mapped" && continue
			if tcp_tuple_present "$ns_server" \
				"$server_address:$server_listen_port" "$mapped"; then
				printf 'client %s %s\n' "$candidate" "$mapped"
				return 0
			fi
		done <<<"$current"
		reverse_server_locals=$(tcp_locals_for_remote "$ns_server" \
			"$old_public_address:$forwarded_port")
		reverse_client_remotes=$(tcp_remotes_for_local "$ns_client" \
			"$client_old_address:$client_listen_port" "$server_address")
		if (( $(nonempty_line_count <<<"$reverse_server_locals") == 1 && \
			$(nonempty_line_count <<<"$reverse_client_remotes") == 1 )) && \
		   [[ $reverse_server_locals == "$reverse_client_remotes" ]]; then
			printf 'reverse %s %s\n' \
				"$reverse_server_locals" "$reverse_client_remotes"
			return 0
		fi
		sleep 0.25
	done
	echo "no authenticated replacement carrier appeared" >&2
	return 1
}

tcp_locals_for_remote() {
	local namespace=$1 remote_endpoint=$2

	run "$namespace" ss -H -tn4 state established | awk \
		-v remote="$remote_endpoint" '
		{
			remote_seen = 0
			local = ""
			for (i = 1; i <= NF; ++i) {
				if ($i == remote) remote_seen = 1
				if ($i != remote &&
				    $i ~ /^[0-9][0-9.]*:[0-9][0-9]*$/) local = $i
			}
			if (remote_seen && local != "") print local
		}
	' | sort -u
}

tcp_locals_for_remote_address() {
	local namespace=$1 local_address=$2 remote_endpoint=$3

	tcp_locals_for_remote "$namespace" "$remote_endpoint" | \
		awk -v prefix="$local_address:" 'index($0, prefix) == 1 { print }'
}

tcp_info_for_tuple() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3

	run "$namespace" ss -Htin4 | awk \
		-v local="$local_endpoint" -v remote="$remote_endpoint" '
		{
			local_seen = remote_seen = 0
			for (i = 1; i <= NF; ++i) {
				if ($i == local) local_seen = 1
				if ($i == remote) remote_seen = 1
			}
			if (local_seen && remote_seen) {
				capture = 1
				print
				next
			}
			if (capture && $0 ~ /^[[:space:]]/) {
				print
				next
			}
			capture = 0
		}
	'
}

tcp_tuple_any_state_present() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3

	run "$namespace" ss -H -atn4 | awk \
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

wait_tcp_tuple_absent() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3
	local deadline=$(( SECONDS + ${4:-60} ))

	while (( SECONDS < deadline )); do
		if ! tcp_tuple_any_state_present "$namespace" "$local_endpoint" \
			"$remote_endpoint"; then
			return 0
		fi
		sleep 0.25
	done
	echo "old TCP tuple remained present: $local_endpoint <-> $remote_endpoint" >&2
	return 1
}

wait_tcp_established_tuple_absent() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3
	local deadline=$(( SECONDS + ${4:-60} ))

	while (( SECONDS < deadline )); do
		if ! tcp_tuple_present "$namespace" "$local_endpoint" \
			"$remote_endpoint"; then
			return 0
		fi
		sleep 0.25
	done
	echo "established TCP tuple remained present: $local_endpoint <-> $remote_endpoint" >&2
	return 1
}

tcp_info_retrans_metrics() {
	awk '
		{
			for (i = 1; i <= NF; ++i) {
				token = $i
				gsub(/,/, "", token)
				if (token ~ /^bytes_retrans:[0-9]+$/) {
					sub(/^bytes_retrans:/, "", token)
					if (token + 0 > bytes_retrans) bytes_retrans = token + 0
				} else if (token ~ /^retrans:[0-9]+\/[0-9]+$/) {
					sub(/^retrans:/, "", token)
					split(token, values, "/")
					if (values[2] + 0 > retrans_total)
						retrans_total = values[2] + 0
				}
			}
		}
		END { print bytes_retrans + 0, retrans_total + 0 }
	'
}

tcp_extended_for_tuple() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3

	run "$namespace" ss -H -tn4e state established 2>/dev/null | awk \
		-v local="$local_endpoint" -v remote="$remote_endpoint" '
		{
			local_seen = remote_seen = 0
			for (i = 1; i <= NF; ++i) {
				if ($i == local) local_seen = 1
				if ($i == remote) remote_seen = 1
			}
			if (local_seen && remote_seen) {
				capture = 1
				print
				next
			}
			if (capture && $0 ~ /^[[:space:]]/) {
				print
				next
			}
			capture = 0
		}
	'
}

tcp_tuple_has_fwmark() {
	local namespace=$1 local_endpoint=$2 remote_endpoint=$3 expected=$4
	local expected_decimal extended

	printf -v expected_decimal '%d' "$expected"
	extended=$(tcp_extended_for_tuple "$namespace" "$local_endpoint" \
		"$remote_endpoint")
	grep -Eq "(^|[[:space:]])fwmark:($expected|$expected_decimal)([[:space:]]|$)" \
		<<<"$extended"
}

dual_quiet_state_signature() {
	local endpoint old_tuple=0 new_server_locals new_server_local=
	local new_client_outbound_locals new_client_outbound_local=
	local new_client_inbound_remotes new_client_inbound_remote=
	local old_client_established_absent=0 new_mark=0 client_syns server_syns
	local old_dnat new_dnat inner_echo
	local wga_handshake wgc_handshake server_handshake
	local wga_rx wga_tx wgc_rx wgc_tx server_rx server_tx

	endpoint=$(peer_endpoint "$ns_server" wgb "$client_pub")
	if tcp_tuple_present "$ns_server" "$staged_old_server_local" \
		"$staged_old_server_remote"; then
		old_tuple=1
	fi
	new_server_locals=$(tcp_locals_for_remote "$ns_server" \
		"$new_public_address:$forwarded_port")
	if (( $(nonempty_line_count <<<"$new_server_locals") == 1 )); then
		new_server_local=$new_server_locals
	fi
	new_client_outbound_locals=$(tcp_locals_for_remote_address \
		"$ns_client" "$client_new_address" \
		"$server_address:$server_listen_port")
	if (( $(nonempty_line_count <<<"$new_client_outbound_locals") == 1 )); then
		new_client_outbound_local=$new_client_outbound_locals
	fi
	new_client_inbound_remotes=$(tcp_remotes_for_local "$ns_client" \
		"$new_client_inbound_local" "$server_address")
	if (( $(nonempty_line_count <<<"$new_client_inbound_remotes") == 1 )); then
		new_client_inbound_remote=$new_client_inbound_remotes
	fi
	if ! tcp_tuple_present "$ns_client" "$old_client_outer_local" \
		"$server_address:$server_listen_port"; then
		old_client_established_absent=1
	fi
	if tcp_tuple_has_fwmark "$ns_client" "$new_client_outbound_local" \
		"$server_address:$server_listen_port" "$new_client_fwmark" && \
	   tcp_tuple_has_fwmark "$ns_client" "$new_client_inbound_local" \
		"$new_client_inbound_remote" "$new_client_fwmark" && \
	   tcp_tuple_present "$ns_server" \
		"$server_address:$server_listen_port" \
		"$new_public_address:$new_snat_port" && \
	   tcp_tuple_present "$ns_server" "$new_server_local" \
		"$new_public_address:$forwarded_port"; then
		new_mark=1
	fi
	client_syns=$(tcp_state_count "$ns_client" syn-sent)
	server_syns=$(tcp_state_count "$ns_server" syn-sent)
	old_dnat=$(nat_rule_packets "$ns_old_router" prerouting \
		"$forwarded_port" dnat)
	new_dnat=$(nat_rule_packets "$ns_new_router" prerouting \
		"$forwarded_port" dnat)
	inner_echo=$(server_old_echo_packets)
	wga_handshake=$(latest_handshake "$ns_client" wga "$server_pub")
	wgc_handshake=$(latest_handshake "$ns_client" wgc "$server_pub")
	server_handshake=$(latest_handshake "$ns_server" wgb "$client_pub")
	wga_rx=$(received_bytes "$ns_client" wga "$server_pub")
	wga_tx=$(sent_bytes "$ns_client" wga "$server_pub")
	wgc_rx=$(received_bytes "$ns_client" wgc "$server_pub")
	wgc_tx=$(sent_bytes "$ns_client" wgc "$server_pub")
	server_rx=$(received_bytes "$ns_server" wgb "$client_pub")
	server_tx=$(sent_bytes "$ns_server" wgb "$client_pub")
	printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
		"$endpoint" "$old_tuple" "$new_server_local" \
		"$new_client_outbound_local" "$new_client_inbound_remote" \
		"$old_client_established_absent" "$new_mark" "$client_syns" "$server_syns" \
		"$old_dnat" "$new_dnat" "$inner_echo" \
		"$wga_handshake" "$wgc_handshake" "$server_handshake" \
		"$wga_rx" "$wga_tx" "$wgc_rx" "$wgc_tx" \
		"$server_rx" "$server_tx"
}

dual_quiet_signature_valid() {
	local signature=$1 endpoint old_tuple new_server_local
	local new_client_outbound_local new_client_inbound_remote
	local old_client_established_absent new_mark
	local client_syns server_syns old_dnat new_dnat inner_echo
	local wga_handshake wgc_handshake server_handshake
	local wga_rx wga_tx wgc_rx wgc_tx server_rx server_tx value

	IFS='|' read -r endpoint old_tuple new_server_local \
		new_client_outbound_local new_client_inbound_remote \
		old_client_established_absent new_mark \
		client_syns server_syns old_dnat new_dnat inner_echo \
		wga_handshake wgc_handshake server_handshake wga_rx wga_tx \
		wgc_rx wgc_tx server_rx server_tx <<<"$signature"
	[[ $endpoint == "$moved_endpoint" && -n $new_server_local && \
		-n $new_client_outbound_local && -n $new_client_inbound_remote && \
		$old_tuple =~ ^[01]$ && $old_client_established_absent == 1 && \
		$new_mark == 1 && $client_syns == 0 && $server_syns == 0 ]] || \
		return 1
	for value in "$old_dnat" "$new_dnat" "$inner_echo" \
		"$wga_handshake" "$wgc_handshake" "$server_handshake" \
		"$wga_rx" "$wga_tx" "$wgc_rx" "$wgc_tx" \
		"$server_rx" "$server_tx"; do
		[[ $value =~ ^[0-9]+$ ]] || return 1
	done
	(( wga_handshake > 0 && wgc_handshake > 0 && server_handshake > 0 ))
}

acquire_dual_quiet_window() {
	local label=$1 required_seconds=${2:-$quiet_window_seconds}
	local timeout_seconds=${3:-$quiet_acquisition_timeout_seconds}
	local deadline=$(( SECONDS + timeout_seconds ))
	local stable_started=-1 candidate= signature duration
	local first_valid= previous_valid= last_valid= last_invalid=
	local valid_samples=0 invalid_samples=0 resets=0 longest=0

	while (( SECONDS < deadline )); do
		signature=$(dual_quiet_state_signature)
		if dual_quiet_signature_valid "$signature"; then
			(( ++valid_samples ))
			[[ -n $first_valid ]] || first_valid=$signature
			last_valid=$signature
			if (( stable_started < 0 )) || [[ $signature != "$candidate" ]]; then
				if (( stable_started >= 0 )); then
					duration=$(( SECONDS - stable_started ))
					(( duration > longest )) && longest=$duration
					previous_valid=$candidate
				fi
				(( ++resets ))
				candidate=$signature
				stable_started=$SECONDS
			else
				duration=$(( SECONDS - stable_started ))
				if (( duration >= required_seconds )); then
					printf '%s %s\n' "$duration" "$candidate"
					return 0
				fi
			fi
		else
			(( ++invalid_samples ))
			last_invalid=$signature
			if (( stable_started >= 0 )); then
				duration=$(( SECONDS - stable_started ))
				(( duration > longest )) && longest=$duration
			fi
			stable_started=-1
			candidate=
		fi
		sleep 0.25
	done
	if (( stable_started >= 0 )); then
		duration=$(( SECONDS - stable_started ))
		(( duration > longest )) && longest=$duration
	fi
	echo "$label did not acquire a continuous ${required_seconds}s quiet window within ${timeout_seconds}s (valid=$valid_samples invalid=$invalid_samples resets=$resets longest=${longest}s)" >&2
	echo "$label first-valid=$first_valid" >&2
	echo "$label previous-valid=$previous_valid" >&2
	echo "$label last-valid=$last_valid" >&2
	echo "$label last-invalid=$last_invalid" >&2
	return 1
}

sanitize_tcp_info() {
	awk '
		{
			line = $0
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
			gsub(/[[:space:]]+/, " ", line)
			if (line != "") {
				if (wrote) printf " | "
				printf "%s", line
				wrote = 1
			}
		}
		END { print "" }
	'
}

sanitize_line_set() {
	awk 'NF { if (wrote++) printf ","; printf "%s", $0 } END { print "" }'
}

install_half_open_blackhole() {
	run "$ns_old_router" nft add table ip wgtcp_halfopen
	run "$ns_old_router" nft add chain ip wgtcp_halfopen forward \
		'{ type filter hook forward priority -10; policy accept; }'
	# Count only a new client-side connect attempt. The following rules then
	# silently discard all forwarded TCP in both directions; no active response
	# is generated, so the endpoints must detect loss through TCP retransmission.
	run "$ns_old_router" nft add rule ip wgtcp_halfopen forward \
		iifname "$old_private_if" ip saddr "$client_old_address" \
		ip daddr "$server_address" tcp dport "$server_listen_port" \
		'tcp flags & (fin | syn | rst | ack) == syn' counter drop
	run "$ns_old_router" nft add rule ip wgtcp_halfopen forward \
		iifname "$old_private_if" ip protocol tcp counter drop
	run "$ns_old_router" nft add rule ip wgtcp_halfopen forward \
		iifname "$old_public_if" ip protocol tcp counter drop
}

half_open_syn_packets() {
	run "$ns_old_router" nft -a list chain ip wgtcp_halfopen forward | awk \
		-v port="$server_listen_port" '
		index($0, "dport " port) && index($0, "tcp flags") &&
		index($0, "drop") {
			for (i = 1; i <= NF; ++i)
				if ($i == "packets" && !found) {
					packets = $(i + 1)
					found = 1
				}
		}
		END { if (found) print packets }
	'
}

create_namespace "$ns_client"
create_namespace "$ns_old_router"
create_namespace "$ns_new_router"
create_namespace "$ns_public"
create_namespace "$ns_server"
record_link_names \
	"$client_old_if" "$old_private_if" \
	"$client_new_if" "$new_private_if" \
	"$old_public_if" "$old_fabric_if" \
	"$new_public_if" "$new_fabric_if" \
	"$server_public_if" "$server_fabric_if"

ip link add "$client_old_if" type veth peer name "$old_private_if"
ip link add "$client_new_if" type veth peer name "$new_private_if"
ip link add "$old_public_if" type veth peer name "$old_fabric_if"
ip link add "$new_public_if" type veth peer name "$new_fabric_if"
ip link add "$server_public_if" type veth peer name "$server_fabric_if"

ip link set "$client_old_if" netns "$ns_client"
ip link set "$old_private_if" netns "$ns_old_router"
ip link set "$client_new_if" netns "$ns_client"
ip link set "$new_private_if" netns "$ns_new_router"
ip link set "$old_public_if" netns "$ns_old_router"
ip link set "$old_fabric_if" netns "$ns_public"
ip link set "$new_public_if" netns "$ns_new_router"
ip link set "$new_fabric_if" netns "$ns_public"
ip link set "$server_public_if" netns "$ns_server"
ip link set "$server_fabric_if" netns "$ns_public"

run "$ns_public" ip link add "$public_bridge" type bridge
run "$ns_public" ip link set "$public_bridge" type bridge stp_state 0
run "$ns_public" ip link set "$old_fabric_if" master "$public_bridge"
run "$ns_public" ip link set "$new_fabric_if" master "$public_bridge"
run "$ns_public" ip link set "$server_fabric_if" master "$public_bridge"
run "$ns_public" ip link set "$public_bridge" up
run "$ns_public" ip link set "$old_fabric_if" up
run "$ns_public" ip link set "$new_fabric_if" up
run "$ns_public" ip link set "$server_fabric_if" up

run "$ns_client" ip addr add "$client_old_address/24" dev "$client_old_if"
run "$ns_client" ip addr add "$client_new_address/24" dev "$client_new_if"
run "$ns_old_router" ip addr add "$old_private_address/24" dev "$old_private_if"
run "$ns_old_router" ip addr add "$old_public_address/24" dev "$old_public_if"
run "$ns_new_router" ip addr add "$new_private_address/24" dev "$new_private_if"
run "$ns_new_router" ip addr add "$new_public_address/24" dev "$new_public_if"
run "$ns_server" ip addr add "$server_address/24" dev "$server_public_if"
for namespace_iface in \
	"$ns_client $client_old_if" \
	"$ns_client $client_new_if" \
	"$ns_old_router $old_private_if" \
	"$ns_old_router $old_public_if" \
	"$ns_new_router $new_private_if" \
	"$ns_new_router $new_public_if" \
	"$ns_server $server_public_if"; do
	read -r namespace iface <<<"$namespace_iface"
	run "$namespace" ip link set "$iface" up
done
if [[ $MODE == half-open ]]; then
	run "$ns_client" ip route add "$server_address/32" \
		via "$old_private_address" dev "$client_old_if"
else
	# Install both outer paths before either peer can create a TCP socket. Each
	# client WireGuard device later supplies the mark selecting its fixed path.
	run "$ns_client" sysctl -qw net.ipv4.conf.all.src_valid_mark=1
	run "$ns_client" sysctl -qw net.ipv4.conf.default.src_valid_mark=1
	run "$ns_client" sysctl -qw net.ipv4.conf.all.rp_filter=0
	run "$ns_client" sysctl -qw net.ipv4.conf.default.rp_filter=0
	run "$ns_client" sysctl -qw \
		"net.ipv4.conf.$client_old_if.rp_filter=0"
	run "$ns_client" sysctl -qw \
		"net.ipv4.conf.$client_new_if.rp_filter=0"
	run "$ns_client" ip route add table "$old_client_route_table" \
		"$old_client_subnet" dev "$client_old_if" \
		src "$client_old_address"
	run "$ns_client" ip route add table "$old_client_route_table" \
		"$server_address/32" via "$old_private_address" \
		dev "$client_old_if" src "$client_old_address"
	run "$ns_client" ip route add table "$new_client_route_table" \
		"$new_client_subnet" dev "$client_new_if" \
		src "$client_new_address"
	run "$ns_client" ip route add table "$new_client_route_table" \
		"$server_address/32" via "$new_private_address" \
		dev "$client_new_if" src "$client_new_address"
	run "$ns_client" ip rule add priority 100 \
		fwmark "$old_client_fwmark" lookup "$old_client_route_table"
	run "$ns_client" ip rule add priority 101 \
		fwmark "$new_client_fwmark" lookup "$new_client_route_table"
	old_policy_route=$(run "$ns_client" ip -4 route get "$server_address" \
		mark "$old_client_fwmark")
	new_policy_route=$(run "$ns_client" ip -4 route get "$server_address" \
		mark "$new_client_fwmark")
	grep -Eq "via $old_private_address dev $client_old_if .*src $client_old_address" \
		<<<"$old_policy_route" || {
		echo "old client mark does not select the old router" >&2
		exit 1
	}
	grep -Eq "via $new_private_address dev $client_new_if .*src $client_new_address" \
		<<<"$new_policy_route" || {
		echo "new client mark does not select the new router" >&2
		exit 1
	}
fi
run "$ns_old_router" sysctl -qw net.ipv4.ip_forward=1
run "$ns_new_router" sysctl -qw net.ipv4.ip_forward=1

if [[ $MODE == half-open ]]; then
	# These knobs belong to the disposable endpoint namespaces. tcp_retries2
	# accelerates failure detection for an established carrier; tcp_syn_retries
	# bounds failed reconnect attempts. Neither setting demonstrates production
	# Linux failure-detection timing.
	run "$ns_client" sysctl -qw net.ipv4.tcp_retries2=5
	run "$ns_server" sysctl -qw net.ipv4.tcp_retries2=5
	run "$ns_client" sysctl -qw net.ipv4.tcp_syn_retries=3
	run "$ns_server" sysctl -qw net.ipv4.tcp_syn_retries=3
	old_translation=dynamic
	new_translation=dynamic
	new_nat_listen_port=$client_listen_port
	keepalive_interval=1
else
	old_translation=$old_snat_port
	new_translation=$new_snat_port
	new_nat_listen_port=$new_client_listen_port
	keepalive_interval=2
fi

install_nat "$ns_old_router" "$old_public_if" "$old_public_address" \
	"$client_old_address" "$old_translation" "$client_listen_port"
install_nat "$ns_new_router" "$new_public_if" "$new_public_address" \
	"$client_new_address" "$new_translation" "$new_nat_listen_port"

umask 077
"$WG_FORK" genkey >"$tmpdir/client.key"
"$WG_FORK" genkey >"$tmpdir/server.key"
client_pub=$("$WG_FORK" pubkey <"$tmpdir/client.key")
server_pub=$("$WG_FORK" pubkey <"$tmpdir/server.key")
if [[ $MODE == half-open ]] && ! python3 -c '
import base64
import sys
sys.exit(0 if base64.b64decode(sys.argv[1], validate=True) <
            base64.b64decode(sys.argv[2], validate=True) else 1)
' "$client_pub" "$server_pub"; then
	mv "$tmpdir/client.key" "$tmpdir/key.swap"
	mv "$tmpdir/server.key" "$tmpdir/client.key"
	mv "$tmpdir/key.swap" "$tmpdir/server.key"
	temporary_pub=$client_pub
	client_pub=$server_pub
	server_pub=$temporary_pub
fi
if [[ $MODE == dual-router ]] && ! python3 -c '
import base64
import sys
sys.exit(0 if base64.b64decode(sys.argv[1], validate=True) <
            base64.b64decode(sys.argv[2], validate=True) else 1)
' "$server_pub" "$client_pub"; then
	mv "$tmpdir/client.key" "$tmpdir/key.swap"
	mv "$tmpdir/server.key" "$tmpdir/client.key"
	mv "$tmpdir/key.swap" "$tmpdir/server.key"
	temporary_pub=$client_pub
	client_pub=$server_pub
	server_pub=$temporary_pub
fi
if [[ $MODE == half-open ]]; then
	python3 -c '
import base64
import sys
sys.exit(0 if base64.b64decode(sys.argv[1], validate=True) <
            base64.b64decode(sys.argv[2], validate=True) else 1)
' "$client_pub" "$server_pub" || {
		echo "could not order static keys for the half-open client-initiator setup" >&2
		exit 1
	}
fi
if [[ $MODE == dual-router ]]; then
	python3 -c '
import base64
import sys
sys.exit(0 if base64.b64decode(sys.argv[1], validate=True) <
            base64.b64decode(sys.argv[2], validate=True) else 1)
' "$server_pub" "$client_pub" || {
		echo "could not order static keys for the Noise initiation tie-break setup" >&2
		exit 1
	}
fi

if [[ $MODE == half-open ]]; then
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
	run "$ns_client" "$WG_FORK" set wga peer "$server_pub" \
		allowed-ips "$server_tunnel_address/32" \
		endpoint "$server_address:$server_listen_port" \
		persistent-keepalive "$keepalive_interval"
	run "$ns_server" "$WG_FORK" set wgb peer "$client_pub" \
		allowed-ips "$client_tunnel_address/32" \
		persistent-keepalive "$keepalive_interval"
	wait_ping "$ns_client" wga "$server_tunnel_address"
	wait_ping "$ns_server" wgb "$client_tunnel_address"
else
	# Preplumb both inner routes before activating either peer. Linux removes a
	# device route when its interface is taken administratively down, so leave
	# wgc up but keyless and peerless until the staged old record is queued.
	run "$ns_client" ip link add wga type wireguard
	run "$ns_client" ip link add wgc type wireguard
	run "$ns_server" ip link add wgb type wireguard
	run "$ns_client" "$WG_FORK" set wga private-key "$tmpdir/client.key" \
		listen-port "$client_listen_port" fwmark "$old_client_fwmark" \
		transport tcp
	run "$ns_client" "$WG_FORK" set wgc \
		listen-port "$new_client_listen_port" fwmark "$new_client_fwmark" \
		transport tcp
	run "$ns_server" "$WG_FORK" set wgb private-key "$tmpdir/server.key" \
		listen-port "$server_listen_port" transport tcp
	run "$ns_client" ip addr add "$client_tunnel_address/32" dev wga
	run "$ns_client" ip addr add "$new_client_tunnel_address/32" dev wgc
	run "$ns_server" ip addr add "$server_tunnel_address/32" dev wgb
	run "$ns_server" ip addr add "$new_server_tunnel_address/32" dev wgb
	run "$ns_client" ip link set wga up
	run "$ns_client" ip link set wgc up
	run "$ns_client" ip route add "$new_server_tunnel_address/32" dev wgc \
		src "$new_client_tunnel_address"
	run "$ns_server" ip link set wgb up
	install_server_inner_probe_counter
	run "$ns_client" ip route add "$server_tunnel_address/32" dev wga \
		src "$client_tunnel_address"
	run "$ns_server" ip route add "$client_tunnel_address/32" dev wgb \
		src "$server_tunnel_address"
	run "$ns_server" ip route add "$new_client_tunnel_address/32" dev wgb \
		src "$new_server_tunnel_address"
	# Address and FIB notifiers coalesce TCP reconnect work for 100 ms. This is
	# a minimum debounce interval, not a userspace workqueue flush; the exact
	# 12-second reset-on-change carrier gate below is the observable barrier.
	sleep "$route_notifier_minimum_settle_seconds"
	run "$ns_server" "$WG_FORK" set wgb peer "$client_pub" \
		allowed-ips "$client_tunnel_address/32,$new_client_tunnel_address/32" \
		endpoint "$old_public_address:$forwarded_port" \
		persistent-keepalive "$keepalive_interval"
	run "$ns_client" "$WG_FORK" set wga peer "$server_pub" \
		allowed-ips "$server_tunnel_address/32" \
		endpoint "$server_address:$server_listen_port" \
		persistent-keepalive "$keepalive_interval"
	wait_ping "$ns_client" wga "$server_tunnel_address"
	wait_ping "$ns_server" wgb "$client_tunnel_address"
fi
initial_endpoint="$old_public_address:$forwarded_port"
old_reverse_syns=0
if [[ $MODE == dual-router ]]; then
	[[ $(peer_endpoint "$ns_server" wgb "$client_pub") == "$initial_endpoint" ]] || {
		echo "server did not retain the initial forwarded endpoint" >&2
		exit 1
	}
	wait_tcp_remote "$ns_server" "$old_public_address:$forwarded_port"
	old_reverse_syns=$(nat_rule_packets "$ns_old_router" prerouting \
		"$forwarded_port" "dnat")
	[[ $old_reverse_syns =~ ^[0-9]+$ ]] && (( old_reverse_syns > 0 )) || {
		echo "old router did not observe the initial reverse SYN" >&2
		exit 1
	}
fi

if [[ $MODE == half-open ]]; then
	# Require a continuous healthy interval with stable accepted/outbound sets and
	# no connect attempt already in SYN-SENT. Those complete sets are exclusions
	# for the recovery proof rather than a single conveniently selected socket.
	quiet_window_seconds=4
	quiet_deadline=$(( SECONDS + 30 ))
	quiet_started=-1
	quiet_server_remotes=
	quiet_client_locals=
	while (( SECONDS < quiet_deadline )); do
		current_server_remotes=$(server_accepted_remotes)
		current_client_locals=$(client_outbound_locals)
		client_syn_sent=$(tcp_state_count "$ns_client" syn-sent)
		server_syn_sent=$(tcp_state_count "$ns_server" syn-sent)
		server_remote_count=$(nonempty_line_count <<<"$current_server_remotes")
		client_local_count=$(nonempty_line_count <<<"$current_client_locals")
		if (( client_syn_sent == 0 && server_syn_sent == 0 && \
			server_remote_count > 0 && client_local_count > 0 )); then
			if (( quiet_started < 0 )) || \
			   [[ $current_server_remotes != "$quiet_server_remotes" || \
				$current_client_locals != "$quiet_client_locals" ]]; then
				quiet_server_remotes=$current_server_remotes
				quiet_client_locals=$current_client_locals
				quiet_started=$SECONDS
			elif (( SECONDS - quiet_started >= quiet_window_seconds )); then
				break
			fi
		else
			quiet_started=-1
			quiet_server_remotes=
			quiet_client_locals=
		fi
		sleep 0.25
	done
	(( quiet_started >= 0 && \
		SECONDS - quiet_started >= quiet_window_seconds )) || {
		echo "TCP carriers did not reach a stable SYN-SENT-free window" >&2
		exit 1
	}
	pre_blackhole_server_remotes=$quiet_server_remotes
	pre_blackhole_client_locals=$quiet_client_locals
	old_client_local_count=$(nonempty_line_count \
		<<<"$pre_blackhole_client_locals")
	(( old_client_local_count == 1 )) || {
		echo "expected exactly one healthy client outbound carrier" >&2
		exit 1
	}
	old_client_local=$pre_blackhole_client_locals
	old_remote=$(awk 'NR == 1 { print; exit }' \
		<<<"$pre_blackhole_server_remotes")
	old_established_tuple="$server_address:$server_listen_port<->$old_remote"
	old_client_outbound_tuple="$old_client_local<->$server_address:$server_listen_port"
	capture_ss_snapshot before
	tcp_info_for_tuple "$ns_client" "$old_client_local" \
		"$server_address:$server_listen_port" \
		>"$tmpdir/before-old-client.ss"
	[[ -s $tmpdir/before-old-client.ss ]] || {
		echo "ss did not capture the exact old client carrier" >&2
		exit 1
	}
	read -r old_bytes_retrans_before old_retrans_total_before \
		<<<"$(tcp_info_retrans_metrics <"$tmpdir/before-old-client.ss")"
	[[ $(server_accepted_remotes) == "$pre_blackhole_server_remotes" && \
		$(client_outbound_locals) == "$pre_blackhole_client_locals" && \
		$(tcp_state_count "$ns_client" syn-sent) == 0 && \
		$(tcp_state_count "$ns_server" syn-sent) == 0 ]] || {
		echo "healthy carrier sets changed before blackhole installation" >&2
		exit 1
	}
	tcp_retrans_before=$(tcp_snmp_value "$ns_client" RetransSegs)
	[[ $tcp_retrans_before =~ ^[0-9]+$ ]] || {
		echo "could not read client RetransSegs before blackhole" >&2
		exit 1
	}

	install_half_open_blackhole
	bare_reconnect_syns=$(half_open_syn_packets)
	[[ $bare_reconnect_syns == 0 ]] || {
		echo "half-open SYN counter was not zero at installation" >&2
		exit 1
	}
	detection_started=$SECONDS
	detection_deadline=$(( SECONDS + 90 ))
	tcp_retrans_after=$tcp_retrans_before
	old_bytes_retrans_after=$old_bytes_retrans_before
	old_retrans_total_after=$old_retrans_total_before
	old_carrier_retrans_metric_advanced=false
	while (( SECONDS < detection_deadline )); do
		old_tcp_info_now=$(tcp_info_for_tuple "$ns_client" \
			"$old_client_local" "$server_address:$server_listen_port")
		if [[ -n $old_tcp_info_now ]]; then
			read -r old_bytes_retrans_now old_retrans_total_now \
				<<<"$(tcp_info_retrans_metrics <<<"$old_tcp_info_now")"
			if [[ $old_carrier_retrans_metric_advanced == false ]] && \
			   (( old_bytes_retrans_now > old_bytes_retrans_before || \
				old_retrans_total_now > old_retrans_total_before )); then
				old_bytes_retrans_after=$old_bytes_retrans_now
				old_retrans_total_after=$old_retrans_total_now
				printf '%s\n' "$old_tcp_info_now" \
					>"$tmpdir/during-old-client.ss"
				capture_ss_snapshot during
				old_carrier_retrans_metric_advanced=true
			fi
		fi
		tcp_retrans_now=$(tcp_snmp_value "$ns_client" RetransSegs)
		if [[ $tcp_retrans_now =~ ^[0-9]+$ ]] && \
		   (( tcp_retrans_now > tcp_retrans_after )); then
			tcp_retrans_after=$tcp_retrans_now
		fi
		bare_reconnect_syns=$(half_open_syn_packets)
		if [[ $bare_reconnect_syns =~ ^[0-9]+$ ]] && \
		   (( bare_reconnect_syns > 0 )) && \
		   [[ $old_carrier_retrans_metric_advanced == true ]] && \
		   (( tcp_retrans_after > tcp_retrans_before )); then
			break
		fi
		sleep 0.25
	done
	[[ $bare_reconnect_syns =~ ^[0-9]+$ ]] && \
		(( bare_reconnect_syns > 0 )) || {
		echo "no bare reconnect SYN was observed within 90 seconds" >&2
		exit 1
	}
	[[ $old_carrier_retrans_metric_advanced == true ]] || {
		echo "exact old client carrier retransmission metric did not advance" >&2
		exit 1
	}
	(( tcp_retrans_after > tcp_retrans_before )) || {
		echo "client RetransSegs did not corroborate carrier loss" >&2
		exit 1
	}
	detection_duration=$(( SECONDS - detection_started ))

	# Delete exactly the table installed above. NAT state and every other
	# namespace rule remain untouched during recovery.
	run "$ns_old_router" nft delete table ip wgtcp_halfopen
	if run "$ns_old_router" nft list table ip wgtcp_halfopen \
		>/dev/null 2>&1; then
		echo "owned half-open table still exists after deletion" >&2
		exit 1
	fi
	recovery_started=$SECONDS
	recovered_pair=$(wait_correlated_recovery_pair \
		"$pre_blackhole_client_locals" \
		"$pre_blackhole_server_remotes" 60)
	read -r recovery_direction new_client_local new_remote <<<"$recovered_pair"
	if [[ $recovery_direction == client ]]; then
		line_set_contains "$pre_blackhole_server_remotes" "$new_remote" && {
			echo "recovered server tuple was present before the blackhole" >&2
			exit 1
		}
		line_set_contains "$pre_blackhole_client_locals" "$new_client_local" && {
			echo "recovered client tuple was present before the blackhole" >&2
			exit 1
		}
		[[ $(conntrack_server_remote_for_client_local "$new_client_local") == \
			"$new_remote" ]] || {
			echo "recovered client/server tuples lost their conntrack correlation" >&2
			exit 1
		}
		new_established_tuple="$server_address:$server_listen_port<->$new_remote"
		new_client_outbound_tuple="$new_client_local<->$server_address:$server_listen_port"
		wait_tcp_tuple "$ns_server" "$server_address:$server_listen_port" \
			"$new_remote" 10
		wait_tcp_tuple "$ns_client" "$new_client_local" \
			"$server_address:$server_listen_port" 10
	else
		new_established_tuple="$new_client_local<->$old_public_address:$forwarded_port"
		new_client_outbound_tuple="$client_old_address:$client_listen_port<->$new_remote"
		wait_tcp_tuple "$ns_server" "$new_client_local" \
			"$old_public_address:$forwarded_port" 10
		wait_tcp_tuple "$ns_client" "$client_old_address:$client_listen_port" \
			"$new_remote" 10
	fi
	wait_tcp_tuple_absent "$ns_client" "$old_client_local" \
		"$server_address:$server_listen_port" 60

	# Stop keepalives before the transfer baselines so each counter advance is
	# attributable to the explicit ping sent in that direction.
	run "$ns_client" "$WG_FORK" set wga peer "$server_pub" \
		persistent-keepalive 0
	run "$ns_server" "$WG_FORK" set wgb peer "$client_pub" \
		persistent-keepalive 0
	sleep 2
	if [[ $recovery_direction == client ]]; then
		recovery_carrier_present() {
			tcp_tuple_present "$ns_server" \
				"$server_address:$server_listen_port" "$new_remote" && \
			tcp_tuple_present "$ns_client" "$new_client_local" \
				"$server_address:$server_listen_port"
		}
	else
		recovery_carrier_present() {
			tcp_tuple_present "$ns_server" "$new_client_local" \
				"$old_public_address:$forwarded_port" && \
			tcp_tuple_present "$ns_client" \
				"$client_old_address:$client_listen_port" "$new_remote"
		}
	fi
	recovery_carrier_present || {
		echo "new TCP tuple did not survive transfer-baseline quiescence" >&2
		exit 1
	}

	server_rx_before_client_ping=$(received_bytes "$ns_server" wgb "$client_pub")
	[[ $server_rx_before_client_ping =~ ^[0-9]+$ ]] || {
		echo "could not read server RX baseline" >&2
		exit 1
	}
	wait_ping "$ns_client" wga "$server_tunnel_address"
	server_rx_after_client_ping=$(received_bytes "$ns_server" wgb "$client_pub")
	[[ $server_rx_after_client_ping =~ ^[0-9]+$ ]] && \
		(( server_rx_after_client_ping > server_rx_before_client_ping )) || {
		echo "client ping did not advance the server peer RX counter" >&2
		exit 1
	}
	recovery_carrier_present || {
		echo "new TCP tuple changed after the client-to-server ping" >&2
		exit 1
	}

	client_rx_before_server_ping=$(received_bytes "$ns_client" wga "$server_pub")
	[[ $client_rx_before_server_ping =~ ^[0-9]+$ ]] || {
		echo "could not read client RX baseline" >&2
		exit 1
	}
	wait_ping "$ns_server" wgb "$client_tunnel_address"
	client_rx_after_server_ping=$(received_bytes "$ns_client" wga "$server_pub")
	[[ $client_rx_after_server_ping =~ ^[0-9]+$ ]] && \
		(( client_rx_after_server_ping > client_rx_before_server_ping )) || {
		echo "server ping did not advance the client peer RX counter" >&2
		exit 1
	}
	recovery_carrier_present || {
		echo "new TCP tuple changed after the server-to-client ping" >&2
		exit 1
	}
	! tcp_tuple_any_state_present "$ns_client" "$old_client_local" \
		"$server_address:$server_listen_port" || {
		echo "old client outbound carrier returned after recovery" >&2
		exit 1
	}
	if [[ $recovery_direction == client ]]; then
		[[ $(conntrack_server_remote_for_client_local "$new_client_local") == \
			"$new_remote" ]] || {
			echo "recovered tuple pair no longer matches old-router conntrack" >&2
			exit 1
		}
	fi
	recovery_duration=$(( SECONDS - recovery_started ))
	capture_ss_snapshot after
	pre_blackhole_server_remotes_output=$(sanitize_line_set \
		<<<"$pre_blackhole_server_remotes")
	pre_blackhole_client_locals_output=$(sanitize_line_set \
		<<<"$pre_blackhole_client_locals")
	old_client_tcp_info_before=$(sanitize_tcp_info \
		<"$tmpdir/before-old-client.ss")
	old_client_tcp_info_during=$(sanitize_tcp_info \
		<"$tmpdir/during-old-client.ss")

	printf 'mode=half-open\n'
	printf 'accelerated_tcp_policy=true\n'
	printf 'timing_scope=namespace-accelerated-not-production-default\n'
	printf 'tcp_retries2=5\ntcp_syn_retries=3\n'
	printf 'tcp_retries2_effect=accelerates-established-carrier-failure-detection\n'
	printf 'tcp_syn_retries_effect=bounds-failed-reconnect-attempts\n'
	printf 'production_timing_proof=false\n'
	printf 'persistent_keepalive_seconds=%s\n' "$keepalive_interval"
	printf 'transfer_proof_keepalives=off\n'
	printf 'pre_blackhole_quiet_seconds=%s\n' "$quiet_window_seconds"
	printf 'pre_blackhole_syn_sent=0\n'
	printf 'pre_blackhole_server_accepted_remotes=%s\n' \
		"$pre_blackhole_server_remotes_output"
	printf 'pre_blackhole_client_outbound_locals=%s\n' \
		"$pre_blackhole_client_locals_output"
	printf 'old_established_tuple=%s\n' "$old_established_tuple"
	printf 'old_client_outbound_tuple=%s\n' "$old_client_outbound_tuple"
	printf 'new_established_tuple=%s\n' "$new_established_tuple"
	printf 'new_client_outbound_tuple=%s\n' "$new_client_outbound_tuple"
	printf 'new_tuples_outside_pre_blackhole_sets=pass\n'
	printf 'recovery_carrier_direction=%s\n' "$recovery_direction"
	printf 'recovered_tuple_correlation=%s\n' \
		"$([[ $recovery_direction == client ]] && \
			printf old-router-conntrack || printf reverse-dnat-tuple)"
	printf 'old_client_outbound_absent=pass\n'
	printf 'tcp_retrans_segs=%s->%s\n' \
		"$tcp_retrans_before" "$tcp_retrans_after"
	printf 'tcp_retrans_segs_delta=%s\n' \
		"$(( tcp_retrans_after - tcp_retrans_before ))"
	printf 'old_client_carrier_tcp_info_loss=pass\n'
	printf 'old_client_carrier_retrans_metric=pass\n'
	printf 'old_client_bytes_retrans=%s->%s\n' \
		"$old_bytes_retrans_before" "$old_bytes_retrans_after"
	printf 'old_client_retrans_total=%s->%s\n' \
		"$old_retrans_total_before" "$old_retrans_total_after"
	printf 'old_client_tcp_info_before=%s\n' "$old_client_tcp_info_before"
	printf 'old_client_tcp_info_during=%s\n' "$old_client_tcp_info_during"
	printf 'bare_reconnect_syns=%s\n' "$bare_reconnect_syns"
	printf 'blackhole_drop_only=true\n'
	printf 'half_open_detection=pass\n'
	printf 'detection_duration_seconds=%s\n' "$detection_duration"
	printf 'half_open_recovery=pass\n'
	printf 'recovery_duration_seconds=%s\n' "$recovery_duration"
	printf 'client_ping_server_rx=%s->%s\n' \
		"$server_rx_before_client_ping" "$server_rx_after_client_ping"
	printf 'server_ping_client_rx=%s->%s\n' \
		"$client_rx_before_server_ping" "$client_rx_after_server_ping"
	printf 'bidirectional_recovery=pass\n'
	printf 'ss_before_client_lines=%s\n' \
		"$(snapshot_lines "$tmpdir/before-client.ss")"
	printf 'ss_before_server_lines=%s\n' \
		"$(snapshot_lines "$tmpdir/before-server.ss")"
	printf 'ss_during_client_lines=%s\n' \
		"$(snapshot_lines "$tmpdir/during-client.ss")"
	printf 'ss_during_server_lines=%s\n' \
		"$(snapshot_lines "$tmpdir/during-server.ss")"
	printf 'ss_after_client_lines=%s\n' \
		"$(snapshot_lines "$tmpdir/after-client.ss")"
	printf 'ss_after_server_lines=%s\n' \
		"$(snapshot_lines "$tmpdir/after-server.ss")"
	exit 0
fi

wait_tcp_tuple "$ns_server" "$server_address:$server_listen_port" \
	"$old_public_address:$old_snat_port"
wgc_flags_before_stale=$(run "$ns_client" cat /sys/class/net/wgc/flags)
wgc_route_before_stale=$(run "$ns_client" ip -4 route get \
	"$new_server_tunnel_address" oif wgc)
[[ -z $(run "$ns_client" "$WG_FORK" show wgc peers) && \
	$(run "$ns_client" "$WG_FORK" show wgc public-key) != "$client_pub" && \
	$(( wgc_flags_before_stale & 1 )) == 1 && \
	$wgc_route_before_stale == *"dev wgc"* && \
	$wgc_route_before_stale == *"src $new_client_tunnel_address"* ]] || {
	echo "wgc was not up, routed, keyless, and peerless before stale-record staging" >&2
	exit 1
}
new_reverse_syns_before=$(nat_rule_packets "$ns_new_router" prerouting \
	"$forwarded_port" "dnat")
[[ $new_reverse_syns_before =~ ^[0-9]+$ ]] || {
	echo "could not read the new-router DNAT counter" >&2
	exit 1
}
assert_nat_state "$ns_old_router" "$client_old_address" \
	"$old_public_address" "$old_snat_port"

# Disable background keepalives, refresh the old key and data path explicitly,
# then reacquire the exact carrier after that refresh. This is an anti-churn
# staging gate; the later post-FwMark gate isolates automatic carrier
# authentication without explicit tunnel traffic.
run "$ns_client" "$WG_FORK" set wga peer "$server_pub" persistent-keepalive 0
run "$ns_server" "$WG_FORK" set wgb peer "$client_pub" persistent-keepalive 0
wait_ping "$ns_client" wga "$server_tunnel_address"
wait_ping "$ns_server" wgb "$client_tunnel_address"
pre_stage_carrier_deadline=$(( SECONDS + pre_stage_carrier_timeout_seconds ))
pre_stage_carrier_started=-1
pre_stage_carrier_resets=0
pre_stage_carrier_candidate=
pre_stage_carrier_previous=
pre_stage_carrier_last=
pre_stage_carrier_valid_samples=0
while (( SECONDS < pre_stage_carrier_deadline )); do
	current_server_remotes=$(server_accepted_remotes)
	current_client_locals=$(client_outbound_locals)
	client_syn_sent=$(tcp_state_count "$ns_client" syn-sent)
	server_syn_sent=$(tcp_state_count "$ns_server" syn-sent)
	server_remote_count=$(nonempty_line_count <<<"$current_server_remotes")
	client_local_count=$(nonempty_line_count <<<"$current_client_locals")
	pre_stage_carrier_last="$current_server_remotes|$current_client_locals|client-syn=$client_syn_sent|server-syn=$server_syn_sent"
	if (( client_syn_sent == 0 && server_syn_sent == 0 && \
		server_remote_count == 1 && client_local_count == 1 )) && \
		[[ $current_server_remotes == "$old_public_address:$old_snat_port" && \
		$current_client_locals == "$client_old_address:"* ]]; then
		(( ++pre_stage_carrier_valid_samples ))
		pre_stage_carrier_signature="$current_server_remotes|$current_client_locals"
		if (( pre_stage_carrier_started < 0 )) || \
		   [[ $pre_stage_carrier_signature != "$pre_stage_carrier_candidate" ]]; then
			if (( pre_stage_carrier_started >= 0 )); then
				pre_stage_carrier_previous=$pre_stage_carrier_candidate
				(( ++pre_stage_carrier_resets ))
			fi
			pre_stage_carrier_candidate=$pre_stage_carrier_signature
			pre_stage_carrier_started=$SECONDS
		elif (( SECONDS - pre_stage_carrier_started >= \
			pre_stage_carrier_quiet_seconds )); then
			break
		fi
	else
		if (( pre_stage_carrier_started >= 0 )); then
			pre_stage_carrier_previous=$pre_stage_carrier_candidate
			(( ++pre_stage_carrier_resets ))
		fi
		pre_stage_carrier_candidate=
		pre_stage_carrier_started=-1
	fi
	sleep 0.25
done
(( pre_stage_carrier_started >= 0 && \
	SECONDS - pre_stage_carrier_started >= \
	pre_stage_carrier_quiet_seconds )) || {
	echo "old carrier did not acquire a continuous ${pre_stage_carrier_quiet_seconds}s exact-tuple window within ${pre_stage_carrier_timeout_seconds}s (valid=$pre_stage_carrier_valid_samples resets=$pre_stage_carrier_resets previous=$pre_stage_carrier_previous last=$pre_stage_carrier_last)" >&2
	exit 1
}
pre_stage_carrier_duration=$(( SECONDS - pre_stage_carrier_started ))
IFS='|' read -r staged_old_server_remote old_client_outer_local \
	<<<"$pre_stage_carrier_candidate"
staged_old_server_local="$server_address:$server_listen_port"
tcp_tuple_has_fwmark "$ns_client" "$old_client_outer_local" \
	"$server_address:$server_listen_port" "$old_client_fwmark" || {
	echo "stable exact wga TCP tuple does not carry the old policy mark" >&2
	exit 1
}
tcp_tuple_present "$ns_server" "$staged_old_server_local" \
	"$staged_old_server_remote" || {
	echo "stable exact old accepted tuple disappeared before netem setup" >&2
	exit 1
}

# Delay only packets carrying the old router's translated source as they leave
# the public bridge for the server. The old record and its later FIN/RST remain
# ordered in one queue, while the new router's translated source bypasses it.
# The new carrier can therefore authenticate before the old record is released.
run "$ns_public" tc qdisc add dev "$server_fabric_if" root handle 1: \
	prio bands 3
run "$ns_public" tc qdisc add dev "$server_fabric_if" parent 1:1 \
	handle 10: netem delay "${stale_delay_seconds}s" limit 1000
run "$ns_public" tc filter add dev "$server_fabric_if" protocol ip \
	parent 1: priority 1 u32 match ip src "$old_public_address/32" \
	flowid 1:1
tcp_tuple_present "$ns_client" "$old_client_outer_local" \
	"$server_address:$server_listen_port" && \
	tcp_tuple_present "$ns_server" "$staged_old_server_local" \
	"$staged_old_server_remote" && \
	(( $(tcp_state_count "$ns_client" syn-sent) == 0 && \
	$(tcp_state_count "$ns_server" syn-sent) == 0 )) || {
	echo "stable exact old carrier changed while netem was installed" >&2
	exit 1
}
post_netem_old_carrier_revalidated=1
wga_tx_before_stale=$(sent_bytes "$ns_client" wga "$server_pub")
qdisc_backlog_before_stale=$(qdisc_backlog_packets "$ns_public" \
	"$server_fabric_if" 10:)
old_inner_echo_before_stale=$(server_old_echo_packets)
[[ $wga_tx_before_stale =~ ^[0-9]+$ && \
	$qdisc_backlog_before_stale =~ ^[0-9]+$ && \
	$qdisc_backlog_before_stale -eq 0 && \
	$old_inner_echo_before_stale =~ ^[0-9]+$ && \
	$old_inner_echo_before_stale -gt 0 ]] || {
	echo "could not snapshot TX, backlog, and inner-data accounting before staging" >&2
	exit 1
}
pre_stage_old_handshake=$(latest_handshake "$ns_client" wga "$server_pub")
pre_stage_server_handshake=$(latest_handshake "$ns_server" wgb "$client_pub")
pre_stage_epoch=$(date +%s)
[[ $pre_stage_old_handshake =~ ^[0-9]+$ && \
	$pre_stage_old_handshake -gt 0 && \
	$pre_stage_server_handshake =~ ^[0-9]+$ && \
	$pre_stage_server_handshake -gt 0 && \
	$pre_stage_epoch -ge $pre_stage_old_handshake && \
	$pre_stage_epoch -ge $pre_stage_server_handshake ]] || {
	echo "could not establish the old key age before stale staging" >&2
	exit 1
}
pre_stage_client_key_age_seconds=$(( pre_stage_epoch - pre_stage_old_handshake ))
pre_stage_server_key_age_seconds=$(( pre_stage_epoch - pre_stage_server_handshake ))
if (( pre_stage_client_key_age_seconds > pre_stage_server_key_age_seconds )); then
	pre_stage_old_key_age_seconds=$pre_stage_client_key_age_seconds
else
	pre_stage_old_key_age_seconds=$pre_stage_server_key_age_seconds
fi
(( pre_stage_old_key_age_seconds < old_key_stage_max_age_seconds )) || {
	echo "old key was not comfortably younger than REJECT_AFTER_TIME before staging" >&2
	exit 1
}
(( pre_stage_old_key_age_seconds + stale_enqueue_timeout_seconds + \
	stale_delay_seconds + \
	stale_monitor_margin_seconds < reject_after_time_seconds )) || {
	echo "old key age plus enqueue, delay, and monitor bounds reached REJECT_AFTER_TIME" >&2
	exit 1
}
stale_enqueue_before_at=$SECONDS
stale_enqueue_packets=1
run "$ns_client" ping -4 -I wga -c 1 -W 1 \
	"$server_tunnel_address" >/dev/null 2>&1 || true
wga_tx_after_stale=$(sent_bytes "$ns_client" wga "$server_pub")
qdisc_backlog_after_stale=$(qdisc_backlog_packets "$ns_public" \
	"$server_fabric_if" 10:)
stale_enqueue_deadline=$(( SECONDS + stale_enqueue_timeout_seconds ))
stale_enqueue_polls=0
while (( SECONDS < stale_enqueue_deadline )) && \
	! (( wga_tx_after_stale > wga_tx_before_stale && \
		qdisc_backlog_after_stale > qdisc_backlog_before_stale )); do
	(( ++stale_enqueue_polls ))
	sleep 0.25
	wga_tx_after_stale=$(sent_bytes "$ns_client" wga "$server_pub")
	qdisc_backlog_after_stale=$(qdisc_backlog_packets "$ns_public" \
		"$server_fabric_if" 10:)
done
stale_enqueue_after_at=$SECONDS
[[ $wga_tx_after_stale =~ ^[0-9]+$ && \
	$qdisc_backlog_after_stale =~ ^[0-9]+$ ]] && \
	(( wga_tx_after_stale > wga_tx_before_stale && \
	qdisc_backlog_after_stale > qdisc_backlog_before_stale )) || {
	echo "single staged record did not advance both wga TX and netem backlog after $stale_enqueue_polls polls (wga=$wga_tx_before_stale->$wga_tx_after_stale netem=$qdisc_backlog_before_stale->$qdisc_backlog_after_stale)" >&2
	exit 1
}
qdisc_state=$(run "$ns_public" tc -s qdisc show dev "$server_fabric_if")
grep -Eq 'backlog [1-9][0-9]*[[:alpha:]]* [1-9][0-9]*p' \
	<<<"$qdisc_state" || {
	echo "old-path stale probe was not queued by netem" >&2
	exit 1
}

# Model the old uplink disappearing once the one data record is queued. The
# resulting close remains ordered behind that record in netem, so the server's
# accepted socket stays alive while the old client can no longer generate new
# handshake retries that would be newer than the staged record.
run "$ns_client" ip link set wga down
wga_flags_after_stale=$(run "$ns_client" cat /sys/class/net/wga/flags)
(( (wga_flags_after_stale & 1) == 0 )) || {
	echo "wga remained administratively up after stale-record staging" >&2
	exit 1
}
wait_tcp_established_tuple_absent "$ns_client" "$old_client_outer_local" \
	"$server_address:$server_listen_port" 5
old_client_cutoff_at=$SECONDS
stale_release_earliest_at=$(( stale_enqueue_before_at + stale_delay_seconds ))
stale_release_latest_at=$(( stale_enqueue_after_at + stale_delay_seconds ))
minimum_stale_age_at_earliest_release_seconds=$(( \
	stale_release_earliest_at - stale_enqueue_after_at ))
(( stale_enqueue_after_at >= stale_enqueue_before_at && \
	minimum_stale_age_at_earliest_release_seconds > rekey_timeout_seconds )) || {
	echo "stale enqueue bounds did not preserve a post-confirmation REKEY_TIMEOUT margin" >&2
	exit 1
}
[[ $(server_old_echo_packets) == "$old_inner_echo_before_stale" ]] || {
	echo "staged inner echo request reached the server before netem release" >&2
	exit 1
}
tcp_tuple_present "$ns_server" "$staged_old_server_local" \
	"$staged_old_server_remote" || {
	echo "exact old accepted tuple vanished while staging the record" >&2
	exit 1
}

# Install the second identity and peer only after the old-source record is
# queued. The already-up device has its listener, mark, address, and routes
# preinstalled, but cannot authenticate or create a carrier while keyless.
initial_bootstrap_endpoint_before=$(peer_endpoint "$ns_server" wgb "$client_pub")
initial_bootstrap_server_rx_before=$(received_bytes "$ns_server" wgb "$client_pub")
initial_bootstrap_server_tx_before=$(sent_bytes "$ns_server" wgb "$client_pub")
initial_bootstrap_old_dnat_before=$(nat_rule_packets "$ns_old_router" \
	prerouting "$forwarded_port" dnat)
initial_bootstrap_new_dnat_before=$(nat_rule_packets "$ns_new_router" \
	prerouting "$forwarded_port" dnat)
initial_bootstrap_inner_echo_before=$(server_old_echo_packets)
initial_bootstrap_backlog_before=$(qdisc_backlog_packets "$ns_public" \
	"$server_fabric_if" 10:)
[[ $initial_bootstrap_endpoint_before == "$initial_endpoint" && \
	$initial_bootstrap_server_rx_before =~ ^[0-9]+$ && \
	$initial_bootstrap_server_tx_before =~ ^[0-9]+$ && \
	$initial_bootstrap_old_dnat_before =~ ^[0-9]+$ && \
	$initial_bootstrap_new_dnat_before == "$new_reverse_syns_before" && \
	$initial_bootstrap_inner_echo_before == "$old_inner_echo_before_stale" && \
	$initial_bootstrap_backlog_before =~ ^[0-9]+$ && \
	$initial_bootstrap_backlog_before -gt 0 ]] || {
	echo "could not establish the keyless pre-bootstrap accounting baseline" >&2
	exit 1
}
run "$ns_client" "$WG_FORK" set wgc private-key "$tmpdir/client.key"
run "$ns_client" "$WG_FORK" set wgc peer "$server_pub" \
	allowed-ips "$new_server_tunnel_address/32" \
	endpoint "$server_address:$server_listen_port" \
	persistent-keepalive 0
[[ $(run "$ns_client" "$WG_FORK" show wga public-key) == "$client_pub" && \
	$(run "$ns_client" "$WG_FORK" show wgc public-key) == "$client_pub" ]] || {
	echo "dual client devices do not share the configured identity" >&2
	exit 1
}
[[ $(run "$ns_client" "$WG_FORK" show wga listen-port) == \
	"$client_listen_port" && \
	$(run "$ns_client" "$WG_FORK" show wgc listen-port) == \
	"$new_client_listen_port" && \
	$(run "$ns_client" "$WG_FORK" show wga fwmark) == \
	"$old_client_fwmark" && \
	$(run "$ns_client" "$WG_FORK" show wgc fwmark) == \
	"$new_client_fwmark" ]] || {
	echo "dual client listener or policy-mark configuration diverged" >&2
	exit 1
}
moved_endpoint="$new_public_address:$forwarded_port"
wait_tcp_tuple "$ns_server" "$server_address:$server_listen_port" \
	"$new_public_address:$new_snat_port" 25
wait_peer_endpoint "$ns_server" wgb "$client_pub" "$moved_endpoint" 25
wait_tcp_remote "$ns_server" "$new_public_address:$forwarded_port" 25
new_reverse_syns_first_advance=$(wait_nat_counter_advance "$ns_new_router" \
	prerouting "$forwarded_port" "dnat" "$new_reverse_syns_before" 25)
new_client_inbound_local="$client_new_address:$new_client_listen_port"
new_client_stream_model=independent-outbound-pair
# A failed provisional candidate can enter the production 30-second fallback
# retry. The authentication gate below is the only acquisition deadline: it
# discovers both directions dynamically, pins their marks and exact tuples, and
# then requires an unchanged state for twelve continuous seconds.
! tcp_tuple_present "$ns_client" "$old_client_outer_local" \
	"$server_address:$server_listen_port" || {
	echo "retired wga TCP tuple returned to ESTABLISHED after new-path activation" >&2
	exit 1
}
assert_nat_state "$ns_new_router" "$client_new_address" \
	"$new_public_address" "$new_snat_port" "$new_client_listen_port"
[[ $(peer_endpoint "$ns_server" wgb "$client_pub") == "$moved_endpoint" ]] || {
	echo "observed SNAT source port replaced the configured forwarded port" >&2
	exit 1
}
tcp_tuple_present "$ns_server" "$server_address:$server_listen_port" \
	"$old_public_address:$old_snat_port" || {
	echo "old accepted carrier retired before the staged rollback probe" >&2
	exit 1
}

# Peer configuration establishes the new TCP carrier and must authenticate it
# without help from test traffic. Require one exact state for more than twice
# the provisional idle timeout before sending an explicit tunnel packet.
initial_bootstrap_acquisition=$(acquire_dual_quiet_window initial-bootstrap \
	"$carrier_auth_quiet_seconds" \
	"$carrier_auth_acquisition_timeout_seconds")
read -r initial_bootstrap_duration initial_bootstrap_signature \
	<<<"$initial_bootstrap_acquisition"
IFS='|' read -r initial_bootstrap_endpoint initial_bootstrap_old_tuple \
	initial_bootstrap_new_server_local \
	initial_bootstrap_new_client_outbound_local \
	initial_bootstrap_new_client_inbound_remote \
	initial_bootstrap_old_client_established_absent initial_bootstrap_new_mark \
	initial_bootstrap_client_syns initial_bootstrap_server_syns \
	initial_bootstrap_old_dnat initial_bootstrap_new_dnat \
	initial_bootstrap_inner_echo initial_bootstrap_wga_handshake \
	initial_bootstrap_wgc_handshake initial_bootstrap_server_handshake \
	initial_bootstrap_wga_rx initial_bootstrap_wga_tx \
	initial_bootstrap_wgc_rx initial_bootstrap_wgc_tx \
	initial_bootstrap_server_rx initial_bootstrap_server_tx \
	<<<"$initial_bootstrap_signature"
[[ $initial_bootstrap_endpoint == "$moved_endpoint" && \
	$initial_bootstrap_old_tuple == 1 && \
	-n $initial_bootstrap_new_server_local && \
	-n $initial_bootstrap_new_client_outbound_local && \
	-n $initial_bootstrap_new_client_inbound_remote && \
	$initial_bootstrap_old_client_established_absent == 1 && \
	$initial_bootstrap_new_mark == 1 && \
	$initial_bootstrap_client_syns == 0 && \
	$initial_bootstrap_server_syns == 0 && \
	$initial_bootstrap_old_dnat == "$initial_bootstrap_old_dnat_before" && \
	$initial_bootstrap_new_dnat -ge $new_reverse_syns_first_advance && \
	$initial_bootstrap_inner_echo == "$initial_bootstrap_inner_echo_before" ]] || {
	echo "initial automatic carrier-bootstrap state changed before explicit traffic" >&2
	exit 1
}
(( initial_bootstrap_wgc_handshake > 0 && \
	initial_bootstrap_wgc_rx > 0 && initial_bootstrap_wgc_tx > 0 && \
	initial_bootstrap_server_rx > initial_bootstrap_server_rx_before && \
	initial_bootstrap_server_tx > initial_bootstrap_server_tx_before && \
	initial_bootstrap_new_dnat > initial_bootstrap_new_dnat_before && \
	initial_bootstrap_duration >= carrier_auth_quiet_seconds )) || {
	echo "initial carrier did not prove automatic Noise authentication and stability" >&2
	exit 1
}
initial_server_outbound_local=$initial_bootstrap_new_server_local
new_client_outbound_local=$initial_bootstrap_new_client_outbound_local
new_client_inbound_remote=$initial_bootstrap_new_client_inbound_remote
new_reverse_syns_after=$initial_bootstrap_new_dnat
initial_bootstrap_backlog_after=$(qdisc_backlog_packets "$ns_public" \
	"$server_fabric_if" 10:)
[[ $initial_bootstrap_backlog_after =~ ^[0-9]+$ && \
	$initial_bootstrap_backlog_after -ge $initial_bootstrap_backlog_before ]] || {
	echo "old-path delayed backlog drained during automatic new-carrier activation" >&2
	exit 1
}
wgc_handshake_before=$initial_bootstrap_wgc_handshake
wgc_rx_before=$initial_bootstrap_wgc_rx
wgc_tx_before=$initial_bootstrap_wgc_tx

# Exercise both directions only after automatic carrier authentication is
# proven. The bootstrap may already have established the same Noise session, so
# explicit traffic must advance transfer counters without requiring a newer
# handshake timestamp.
wait_ping "$ns_client" wgc "$new_server_tunnel_address"
wait_ping "$ns_server" wgb "$new_client_tunnel_address"
wgc_handshake_after=$(latest_handshake "$ns_client" wgc "$server_pub")
wgc_rx_after=$(received_bytes "$ns_client" wgc "$server_pub")
wgc_tx_after=$(sent_bytes "$ns_client" wgc "$server_pub")
server_rx_after_activation=$(received_bytes "$ns_server" wgb "$client_pub")
server_tx_after_activation=$(sent_bytes "$ns_server" wgb "$client_pub")
[[ $wgc_handshake_after =~ ^[0-9]+$ && \
	$wgc_rx_after =~ ^[0-9]+$ && $wgc_tx_after =~ ^[0-9]+$ && \
	$server_rx_after_activation =~ ^[0-9]+$ && \
	$server_tx_after_activation =~ ^[0-9]+$ ]] && \
	(( wgc_handshake_after >= wgc_handshake_before && \
	wgc_rx_after > wgc_rx_before && wgc_tx_after > wgc_tx_before && \
	server_rx_after_activation > initial_bootstrap_server_rx && \
	server_tx_after_activation > initial_bootstrap_server_tx )) || {
	echo "wgc did not prove explicit bidirectional transfer after automatic authentication" >&2
	exit 1
}

# Let the explicit new-path probes reach accounting, then acquire sixteen
# continuous seconds of one exact state signature. Any invalid sample or change
# resets the candidate window; the outer deadline keeps the test bounded.
sleep 2
quiet_acquisition=$(acquire_dual_quiet_window pre-release \
	"$quiet_window_seconds" "$quiet_acquisition_timeout_seconds")
read -r quiet_barrier_duration quiet_signature <<<"$quiet_acquisition"
IFS='|' read -r quiet_endpoint quiet_old_tuple quiet_new_server_local \
	quiet_new_client_outbound_local quiet_new_client_inbound_remote \
	quiet_old_client_established_absent quiet_new_mark quiet_client_syns quiet_server_syns \
	quiet_old_syns quiet_new_syns quiet_inner_echo quiet_wga_handshake \
	quiet_wgc_handshake quiet_server_handshake quiet_wga_rx quiet_wga_tx \
	quiet_wgc_rx quiet_wgc_tx quiet_server_rx quiet_server_tx \
	<<<"$quiet_signature"
[[ $quiet_old_tuple == 1 && $quiet_old_client_established_absent == 1 && \
	$quiet_new_mark == 1 && \
	$quiet_new_server_local == "$initial_server_outbound_local" && \
	$quiet_new_client_outbound_local == "$new_client_outbound_local" && \
	$quiet_new_client_inbound_remote == "$new_client_inbound_remote" && \
	$quiet_wga_handshake == "$pre_stage_old_handshake" && \
	$quiet_inner_echo == "$old_inner_echo_before_stale" ]] || {
	echo "pre-release quiet state lost an exact tuple, mark, or inner-data baseline" >&2
	exit 1
}
(( quiet_barrier_duration >= quiet_window_seconds && \
	quiet_barrier_duration > rekey_timeout_seconds )) || {
	echo "quiet acquisition did not exceed REKEY_TIMEOUT" >&2
	exit 1
}
quiet_new_server_tuple="$quiet_new_server_local<->$new_public_address:$forwarded_port"
server_rx_before=$quiet_server_rx
minimum_stale_age_at_baseline_seconds=$(( SECONDS - stale_enqueue_after_at ))
current_epoch=$(date +%s)
old_key_age_seconds=$(( current_epoch - quiet_wga_handshake ))
(( minimum_stale_age_at_baseline_seconds > rekey_timeout_seconds && \
	old_key_age_seconds > rekey_timeout_seconds )) || {
	echo "staged record or old handshake was not older than REKEY_TIMEOUT" >&2
	exit 1
}
baseline_lead_seconds=$(( stale_release_earliest_at - SECONDS ))
(( baseline_lead_seconds >= 10 )) || {
	echo "new-path assertions left less than 10 seconds before earliest stale release" >&2
	exit 1
}

# Keep that acquired signature stable until immediately before the earliest
# possible release. This rejects any hidden traffic between qualification and
# the delayed-data observation.
old_syn_snapshot_at=$(( stale_release_earliest_at - 1 ))
while (( SECONDS < old_syn_snapshot_at )); do
	[[ $(dual_quiet_state_signature) == "$quiet_signature" ]] || {
		echo "pre-release endpoint, tuple, SYN, mark, DNAT, or WireGuard state changed" >&2
		exit 1
	}
	sleep 0.5
done
tcp_tuple_present "$ns_server" "$staged_old_server_local" \
	"$staged_old_server_remote" || {
	echo "exact old accepted tuple was absent immediately before release" >&2
	exit 1
}
old_reverse_syns_before_release=$(nat_rule_packets "$ns_old_router" \
	prerouting "$forwarded_port" dnat)
new_reverse_syns_before_release=$(nat_rule_packets "$ns_new_router" \
	prerouting "$forwarded_port" dnat)
old_inner_echo_before_release=$(server_old_echo_packets)
[[ $old_reverse_syns_before_release == "$quiet_old_syns" && \
	$new_reverse_syns_before_release == "$quiet_new_syns" && \
	$old_inner_echo_before_release == "$quiet_inner_echo" && \
	$(dual_quiet_state_signature) == "$quiet_signature" ]] || {
	echo "acquired quiet signature changed immediately before release" >&2
	exit 1
}

monitor_deadline=$(( stale_release_latest_at + stale_monitor_margin_seconds ))
server_rx_after=$server_rx_before
old_inner_echo_after_release=$old_inner_echo_before_release
while (( SECONDS < monitor_deadline )); do
	observed_endpoint=$(peer_endpoint "$ns_server" wgb "$client_pub")
	[[ $observed_endpoint == "$moved_endpoint" ]] || {
		echo "stale old carrier rolled the dial target back to $observed_endpoint" >&2
		exit 1
	}
	observed_old_syns=$(nat_rule_packets "$ns_old_router" prerouting \
		"$forwarded_port" dnat)
	observed_new_syns=$(nat_rule_packets "$ns_new_router" prerouting \
		"$forwarded_port" dnat)
	[[ $observed_old_syns == "$old_reverse_syns_before_release" && \
		$observed_new_syns == "$new_reverse_syns_before_release" && \
		$(tcp_state_count "$ns_client" syn-sent) == 0 && \
		$(tcp_state_count "$ns_server" syn-sent) == 0 ]] || {
		echo "stale delivery coincided with a reconnect or DNAT counter change" >&2
		exit 1
	}
	observed_rx=$(received_bytes "$ns_server" wgb "$client_pub")
	observed_inner_echo=$(server_old_echo_packets)
	observed_wgc_tx=$(sent_bytes "$ns_client" wgc "$server_pub")
	observed_wga_tx=$(sent_bytes "$ns_client" wga "$server_pub")
	observed_wga_handshake=$(latest_handshake "$ns_client" wga "$server_pub")
	observed_wgc_handshake=$(latest_handshake "$ns_client" wgc "$server_pub")
	observed_server_handshake=$(latest_handshake "$ns_server" wgb "$client_pub")
	[[ $observed_rx =~ ^[0-9]+$ && $observed_inner_echo =~ ^[0-9]+$ && \
		$observed_wgc_tx == "$quiet_wgc_tx" && \
		$observed_wga_tx == "$quiet_wga_tx" && \
		$observed_wga_handshake == "$quiet_wga_handshake" && \
		$observed_wgc_handshake == "$quiet_wgc_handshake" && \
		$observed_server_handshake == "$quiet_server_handshake" ]] || {
		echo "client transmit or handshake state changed during stale release" >&2
		exit 1
	}
	if (( observed_rx <= server_rx_before )); then
		observed_wgc_rx=$(received_bytes "$ns_client" wgc "$server_pub")
		observed_server_tx=$(sent_bytes "$ns_server" wgb "$client_pub")
		# The delayed packet can arrive between the first server-RX sample and
		# these later counter reads. Recheck the causal counter before treating
		# a response-side advance as independent new-path traffic.
		observed_rx_recheck=$(received_bytes "$ns_server" wgb "$client_pub")
		if (( observed_rx_recheck > observed_rx )); then
			observed_rx=$observed_rx_recheck
		fi
		if (( observed_rx <= server_rx_before )); then
			[[ $observed_wgc_rx == "$quiet_wgc_rx" && \
				$observed_server_tx == "$quiet_server_tx" ]] || {
				echo "new path moved counters before the delayed server RX" >&2
				exit 1
			}
		fi
	fi
	if (( observed_rx > server_rx_after )); then
		server_rx_after=$observed_rx
	fi
	if (( observed_inner_echo > old_inner_echo_after_release )); then
		old_inner_echo_after_release=$observed_inner_echo
	fi
	sleep 0.25
done
(( server_rx_after > server_rx_before && \
	old_inner_echo_after_release > old_inner_echo_before_release )) || {
	echo "delayed old-path inner echo did not reach authenticated data delivery" >&2
	exit 1
}
wgc_tx_after_release=$(sent_bytes "$ns_client" wgc "$server_pub")
[[ $wgc_tx_after_release == "$quiet_wgc_tx" ]] || {
	echo "new-client TX changed across the delayed old-record proof" >&2
	exit 1
}
old_reverse_syns_after_release=$(nat_rule_packets "$ns_old_router" \
	prerouting "$forwarded_port" dnat)
[[ $old_reverse_syns_after_release == "$old_reverse_syns_before_release" ]] || {
	echo "old-router reverse SYN counter advanced after stale release" >&2
	exit 1
}
run "$ns_public" tc qdisc del dev "$server_fabric_if" root
[[ $(peer_endpoint "$ns_server" wgb "$client_pub") == "$moved_endpoint" ]] || {
	echo "new authenticated dial target was not stable after the stale probe" >&2
	exit 1
}

# A live FwMark change forces the server to replace its stream. First acquire
# the same complete, reset-on-change signature after delayed delivery has
# settled. Which router then sees the replacement SYN is external proof of the
# retained dial target, including a rollback too brief for endpoint polling.
sleep 2
pre_fwmark_acquisition=$(acquire_dual_quiet_window pre-fwmark \
	"$quiet_window_seconds" "$pre_fwmark_acquisition_timeout_seconds")
read -r pre_fwmark_settle_duration pre_fwmark_signature \
	<<<"$pre_fwmark_acquisition"
IFS='|' read -r pre_fwmark_endpoint pre_fwmark_old_tuple \
	pre_fwmark_new_server_local pre_fwmark_new_client_outbound_local \
	pre_fwmark_new_client_inbound_remote \
	pre_fwmark_old_client_established_absent pre_fwmark_new_mark \
	pre_fwmark_client_syns pre_fwmark_server_syns pre_fwmark_old_syns \
	pre_fwmark_new_syns pre_fwmark_inner_echo pre_fwmark_wga_handshake \
	pre_fwmark_wgc_handshake pre_fwmark_server_handshake \
	pre_fwmark_wga_rx pre_fwmark_wga_tx pre_fwmark_wgc_rx \
	pre_fwmark_wgc_tx pre_fwmark_server_rx pre_fwmark_server_tx \
	<<<"$pre_fwmark_signature"
if [[ $pre_fwmark_old_tuple == 1 ]]; then
	old_carrier_after=retained
else
	old_carrier_after=retired
fi
[[ $pre_fwmark_old_client_established_absent == 1 && \
	$pre_fwmark_new_mark == 1 && \
	$pre_fwmark_old_syns == "$old_reverse_syns_before_release" && \
	$pre_fwmark_inner_echo == "$old_inner_echo_after_release" ]] || {
	echo "pre-FwMark quiet state lost its tuple, mark, DNAT, or data baseline" >&2
	exit 1
}
(( pre_fwmark_settle_duration >= quiet_window_seconds )) || {
	echo "pre-FwMark quiet acquisition was too short" >&2
	exit 1
}
initial_server_outbound_local=$pre_fwmark_new_server_local
new_client_outbound_local=$pre_fwmark_new_client_outbound_local
new_client_inbound_remote=$pre_fwmark_new_client_inbound_remote
forced_reconnect_remote="$new_public_address:$forwarded_port"
forced_reconnect_old_local=$pre_fwmark_new_server_local
forced_reconnect_old_tuple="$forced_reconnect_old_local<->$forced_reconnect_remote"
tcp_tuple_present "$ns_server" "$forced_reconnect_old_local" \
	"$forced_reconnect_remote" || {
	echo "pre-FwMark server outbound tuple was not established" >&2
	exit 1
}
new_reverse_syns_before_forced=$pre_fwmark_new_syns
run "$ns_server" "$WG_FORK" set wgb fwmark "$forced_server_fwmark"
[[ $(run "$ns_server" "$WG_FORK" show wgb fwmark) == "$forced_server_fwmark" ]] || {
	echo "server FwMark change was not applied" >&2
	exit 1
}

forced_reconnect_deadline=$(( SECONDS + 25 ))
new_reverse_syns_after_forced=
forced_reconnect_new_local=
while (( SECONDS < forced_reconnect_deadline )); do
	observed_old_syns=$(nat_rule_packets "$ns_old_router" prerouting \
		"$forwarded_port" "dnat")
	[[ $observed_old_syns =~ ^[0-9]+$ && \
		$observed_old_syns -eq $old_reverse_syns_before_release ]] || {
		echo "forced reconnect used the stale old-router dial target" >&2
		exit 1
	}
	observed_new_syns=$(nat_rule_packets "$ns_new_router" prerouting \
		"$forwarded_port" "dnat")
	if [[ $observed_new_syns =~ ^[0-9]+$ ]] && \
		(( observed_new_syns > new_reverse_syns_before_forced )); then
		new_reverse_syns_after_forced=$observed_new_syns
	fi
	forced_reconnect_current_locals=$(tcp_locals_for_remote "$ns_server" \
		"$forced_reconnect_remote")
	while IFS= read -r forced_reconnect_candidate; do
		[[ -n $forced_reconnect_candidate && \
			$forced_reconnect_candidate != "$forced_reconnect_old_local" ]] || \
			continue
		if tcp_tuple_has_fwmark "$ns_server" "$forced_reconnect_candidate" \
			"$forced_reconnect_remote" "$forced_server_fwmark"; then
			forced_reconnect_new_local=$forced_reconnect_candidate
			break
		fi
	done <<<"$forced_reconnect_current_locals"
	if [[ -n $new_reverse_syns_after_forced && \
		-n $forced_reconnect_new_local ]] && \
	   ! tcp_tuple_present "$ns_server" \
		"$forced_reconnect_old_local" "$forced_reconnect_remote"; then
		break
	fi
	sleep 0.25
done
[[ -n $new_reverse_syns_after_forced ]] || {
	echo "forced reconnect did not reach the new-router DNAT" >&2
	exit 1
}
[[ -n $forced_reconnect_new_local && \
	$forced_reconnect_new_local != "$forced_reconnect_old_local" ]] || {
	echo "FwMark change did not create a different server outbound tuple" >&2
	exit 1
}
forced_reconnect_new_tuple="$forced_reconnect_new_local<->$forced_reconnect_remote"
tcp_tuple_present "$ns_server" "$forced_reconnect_new_local" \
	"$forced_reconnect_remote" || {
	echo "new marked server outbound tuple was not established" >&2
	exit 1
}
tcp_tuple_has_fwmark "$ns_server" "$forced_reconnect_new_local" \
	"$forced_reconnect_remote" "$forced_server_fwmark" || {
	echo "replacement server outbound tuple does not carry the new FwMark" >&2
	exit 1
}
! tcp_tuple_present "$ns_server" "$forced_reconnect_old_local" \
	"$forced_reconnect_remote" || {
	echo "pre-FwMark server outbound tuple remained ESTABLISHED" >&2
	exit 1
}
if tcp_tuple_any_state_present "$ns_server" "$forced_reconnect_old_local" \
	"$forced_reconnect_remote"; then
	forced_reconnect_old_residual_state=present
else
	forced_reconnect_old_residual_state=absent
fi
forced_reconnect_old_client_inbound_remote=$pre_fwmark_new_client_inbound_remote
wait_tcp_tuple "$ns_client" "$new_client_inbound_local" \
	"$forced_reconnect_new_local" 25
wait_tcp_established_tuple_absent "$ns_client" "$new_client_inbound_local" \
	"$forced_reconnect_old_client_inbound_remote" 25
new_client_inbound_remote=$forced_reconnect_new_local
tcp_tuple_has_fwmark "$ns_client" "$new_client_inbound_local" \
	"$new_client_inbound_remote" "$new_client_fwmark" || {
	echo "client accepted half of the marked replacement pair has the wrong FwMark" >&2
	exit 1
}

# Do not send tunnel traffic yet. Let bootstrap accounting settle, then require
# more than twice the provisional idle timeout with one identical tuple/SYN/
# DNAT/handshake/transfer signature. Without a valid Noise record on the new
# carrier, the accepted half is reaped and this reset-on-change gate cannot pass.
carrier_auth_acquisition=$(acquire_dual_quiet_window post-fwmark-bootstrap \
	"$carrier_auth_quiet_seconds" \
	"$carrier_auth_acquisition_timeout_seconds")
read -r carrier_auth_duration carrier_auth_signature \
	<<<"$carrier_auth_acquisition"
IFS='|' read -r carrier_auth_endpoint carrier_auth_old_tuple \
	carrier_auth_new_server_local carrier_auth_new_client_outbound_local \
	carrier_auth_new_client_inbound_remote \
	carrier_auth_old_client_established_absent \
	carrier_auth_new_mark carrier_auth_client_syns carrier_auth_server_syns \
	carrier_auth_old_dnat carrier_auth_new_dnat carrier_auth_inner_echo \
	carrier_auth_wga_handshake carrier_auth_wgc_handshake \
	carrier_auth_server_handshake carrier_auth_wga_rx carrier_auth_wga_tx \
	carrier_auth_wgc_rx carrier_auth_wgc_tx carrier_auth_server_rx \
	carrier_auth_server_tx <<<"$carrier_auth_signature"
[[ $carrier_auth_endpoint == "$moved_endpoint" && \
	$carrier_auth_new_server_local == "$forced_reconnect_new_local" && \
	$carrier_auth_new_client_outbound_local == "$pre_fwmark_new_client_outbound_local" && \
	$carrier_auth_new_client_inbound_remote == "$forced_reconnect_new_local" && \
	$carrier_auth_old_client_established_absent == 1 && \
	$carrier_auth_new_mark == 1 && $carrier_auth_client_syns == 0 && \
	$carrier_auth_server_syns == 0 && \
	$carrier_auth_old_dnat == "$old_reverse_syns_before_release" && \
	$carrier_auth_new_dnat == "$new_reverse_syns_after_forced" && \
	$carrier_auth_inner_echo == "$old_inner_echo_after_release" ]] || {
	echo "post-FwMark carrier-authentication quiet state changed" >&2
	exit 1
}
(( carrier_auth_server_tx > pre_fwmark_server_tx && \
	carrier_auth_wgc_rx > pre_fwmark_wgc_rx )) || {
	echo "post-FwMark carrier bootstrap did not advance authenticated transfer counters" >&2
	exit 1
}
(( carrier_auth_duration >= carrier_auth_quiet_seconds )) || {
	echo "post-FwMark carrier-authentication quiet window was too short" >&2
	exit 1
}
tcp_tuple_present "$ns_server" "$forced_reconnect_new_local" \
	"$forced_reconnect_remote" && \
	tcp_tuple_has_fwmark "$ns_server" "$forced_reconnect_new_local" \
		"$forced_reconnect_remote" "$forced_server_fwmark" || {
	echo "marked replacement carrier did not survive the no-traffic authentication gate" >&2
	exit 1
}

# Exercise the tunnel only after replacement, mark propagation, old-tuple
# retirement, and automatic carrier authentication have all been proven.
wait_ping "$ns_client" wgc "$new_server_tunnel_address"
wait_ping "$ns_server" wgb "$new_client_tunnel_address"
tcp_tuple_present "$ns_server" "$forced_reconnect_new_local" \
	"$forced_reconnect_remote" && \
	tcp_tuple_has_fwmark "$ns_server" "$forced_reconnect_new_local" \
		"$forced_reconnect_remote" "$forced_server_fwmark" || {
	echo "marked replacement tuple did not survive recovery traffic" >&2
	exit 1
}
old_reverse_syns_after_forced=$(nat_rule_packets "$ns_old_router" \
	prerouting "$forwarded_port" "dnat")
[[ $old_reverse_syns_after_forced =~ ^[0-9]+$ && \
	$old_reverse_syns_after_forced -eq $old_reverse_syns_before_release ]] || {
	echo "old-router reverse SYN counter advanced after forced reconnect" >&2
	exit 1
}
[[ $(peer_endpoint "$ns_server" wgb "$client_pub") == "$moved_endpoint" ]] || {
	echo "forced reconnect did not preserve the authenticated dial target" >&2
	exit 1
}

initial_new_reverse_syn_delta=$(( new_reverse_syns_after - new_reverse_syns_before ))
forced_new_reverse_syn_delta=$(( new_reverse_syns_after_forced - new_reverse_syns_before_forced ))
new_reverse_syn_delta=$(( new_reverse_syns_after_forced - new_reverse_syns_before ))

printf 'mode=dual-router\n'
printf 'test_scope=same_identity_two_carrier_surrogate\n'
printf 'same_device_movement_owner=policy-churn\n'
printf 'same_private_key_two_devices=pass\n'
printf 'outer_policy_preinstalled_before_peer_activation=pass\n'
printf 'inner_route_preinstalled_before_peer_activation=pass\n'
printf 'new_identity_peer_activated_after_stale_queue=pass\n'
printf 'old_device_deactivated_after_stale_queue=pass\n'
printf 'old_client_established_socket_retired_before_new_activation=pass\n'
printf 'pre_stage_bidirectional_key_refresh=pass\n'
printf 'wgc_keyless_before_stale_queue=pass\n'
printf 'wgc_admin_up_before_stale_queue=pass\n'
printf 'wgc_keyless_route_preplumb=persistent-up\n'
printf 'inner_route_preferred_sources=path-specific\n'
printf 'shared_peer_allowed_ips=%s/32,%s/32\n' \
	"$client_tunnel_address" "$new_client_tunnel_address"
printf 'shared_client_public_key=%s\n' "$client_pub"
printf 'shared_public_forwarded_port=%s\n' "$forwarded_port"
printf 'client_policy_sysctls=src_valid_mark-1,rp_filter-0\n'
printf 'old_client_device=wga\nnew_client_device=wgc\n'
printf 'old_client_inner=%s\nnew_client_inner=%s\n' \
	"$client_tunnel_address" "$new_client_tunnel_address"
printf 'old_server_inner=%s\nnew_server_inner=%s\n' \
	"$server_tunnel_address" "$new_server_tunnel_address"
printf 'old_client_listen_port=%s\nnew_client_listen_port=%s\n' \
	"$client_listen_port" "$new_client_listen_port"
printf 'old_client_fwmark=%s\nnew_client_fwmark=%s\n' \
	"$old_client_fwmark" "$new_client_fwmark"
printf 'old_client_outer_tuple=%s<->%s:%s\n' \
	"$old_client_outer_local" "$server_address" "$server_listen_port"
printf 'new_client_outbound_tuple=%s<->%s:%s\n' \
	"$new_client_outbound_local" "$server_address" "$server_listen_port"
printf 'new_client_inbound_tuple=%s<->%s\n' \
	"$new_client_inbound_local" "$new_client_inbound_remote"
printf 'new_server_outbound_tuple=%s<->%s\n' \
	"$initial_server_outbound_local" "$moved_endpoint"
printf 'tcp_stream_model=%s\n' "$new_client_stream_model"
printf 'simultaneous_noise_key_order=server-lower-than-client\n'
printf 'simultaneous_noise_branch_runtime_observed=not-instrumented\n'
printf 'exact_client_socket_marks=pass\n'
printf 'pre_stage_carrier_quiet_required_seconds=%s\n' \
	"$pre_stage_carrier_quiet_seconds"
printf 'pre_stage_carrier_gate_scope=post-refresh-anti-churn\n'
printf 'pre_peer_route_notifier_minimum_settle_seconds=%s\n' \
	"$route_notifier_minimum_settle_seconds"
printf 'pre_stage_carrier_quiet_seconds=%s\n' \
	"$pre_stage_carrier_duration"
printf 'pre_stage_carrier_quiet_resets=%s\n' \
	"$pre_stage_carrier_resets"
printf 'pre_stage_carrier_valid_samples=%s\n' \
	"$pre_stage_carrier_valid_samples"
printf 'post_netem_old_carrier_revalidated=%s\n' \
	"$post_netem_old_carrier_revalidated"
printf 'wga_stale_tx=%s->%s\n' \
	"$wga_tx_before_stale" "$wga_tx_after_stale"
printf 'netem_backlog_packets=%s->%s\n' \
	"$qdisc_backlog_before_stale" "$qdisc_backlog_after_stale"
printf 'staged_old_server_tuple=%s<->%s\n' \
	"$staged_old_server_local" "$staged_old_server_remote"
printf 'initial_carrier_bootstrap_authentication=pass\n'
printf 'initial_carrier_bootstrap_no_explicit_tunnel_traffic=pass\n'
printf 'initial_carrier_bootstrap_quiet_required_seconds=%s\n' \
	"$carrier_auth_quiet_seconds"
printf 'initial_carrier_bootstrap_quiet_seconds=%s\n' \
	"$initial_bootstrap_duration"
printf 'initial_carrier_bootstrap_server_tuple=%s<->%s\n' \
	"$initial_bootstrap_new_server_local" "$moved_endpoint"
printf 'initial_carrier_bootstrap_wgc_handshake=%s\n' \
	"$initial_bootstrap_wgc_handshake"
printf 'initial_carrier_bootstrap_wgc_receive_bytes=%s\n' \
	"$initial_bootstrap_wgc_rx"
printf 'initial_carrier_bootstrap_wgc_transmit_bytes=%s\n' \
	"$initial_bootstrap_wgc_tx"
printf 'initial_carrier_bootstrap_server_receive_bytes=%s->%s\n' \
	"$initial_bootstrap_server_rx_before" "$initial_bootstrap_server_rx"
printf 'initial_carrier_bootstrap_server_transmit_bytes=%s->%s\n' \
	"$initial_bootstrap_server_tx_before" "$initial_bootstrap_server_tx"
printf 'initial_carrier_bootstrap_new_dnat=%s->%s\n' \
	"$initial_bootstrap_new_dnat_before" "$initial_bootstrap_new_dnat"
printf 'initial_carrier_bootstrap_old_dnat=%s->%s\n' \
	"$initial_bootstrap_old_dnat_before" "$initial_bootstrap_old_dnat"
printf 'initial_carrier_bootstrap_delayed_backlog=%s->%s\n' \
	"$initial_bootstrap_backlog_before" "$initial_bootstrap_backlog_after"
printf 'wgc_handshake=%s->%s\n' \
	"$wgc_handshake_before" "$wgc_handshake_after"
printf 'wgc_receive_bytes=%s->%s\n' "$wgc_rx_before" "$wgc_rx_after"
printf 'wgc_transmit_bytes=%s->%s\n' "$wgc_tx_before" "$wgc_tx_after"
printf 'server_receive_bytes_after_explicit_transfer=%s->%s\n' \
	"$initial_bootstrap_server_rx" "$server_rx_after_activation"
printf 'server_transmit_bytes_after_explicit_transfer=%s->%s\n' \
	"$initial_bootstrap_server_tx" "$server_tx_after_activation"
printf 'explicit_bidirectional_transfer_after_bootstrap=pass\n'
printf 'rekey_timeout_seconds=%s\n' "$rekey_timeout_seconds"
printf 'quiet_window_required_seconds=%s\n' "$quiet_window_seconds"
printf 'quiet_barrier_seconds=%s\n' "$quiet_barrier_duration"
printf 'quiet_exact_new_server_tuple=%s\n' "$quiet_new_server_tuple"
printf 'pre_release_quiet_handshakes_and_counters=pass\n'
printf 'stale_enqueue_before_monotonic_seconds=%s\n' \
	"$stale_enqueue_before_at"
printf 'stale_enqueue_after_monotonic_seconds=%s\n' \
	"$stale_enqueue_after_at"
printf 'stale_release_earliest_monotonic_seconds=%s\n' \
	"$stale_release_earliest_at"
printf 'stale_release_latest_monotonic_seconds=%s\n' \
	"$stale_release_latest_at"
printf 'minimum_stale_age_at_earliest_release_seconds=%s\n' \
	"$minimum_stale_age_at_earliest_release_seconds"
printf 'stale_enqueue_packets=%s\n' "$stale_enqueue_packets"
printf 'stale_enqueue_polls=%s\n' "$stale_enqueue_polls"
printf 'old_client_cutoff_at=%s\n' "$old_client_cutoff_at"
printf 'minimum_stale_age_at_baseline_seconds=%s\n' \
	"$minimum_stale_age_at_baseline_seconds"
printf 'pre_stage_old_key_age_seconds=%s\n' \
	"$pre_stage_old_key_age_seconds"
printf 'pre_stage_client_key_age_seconds=%s\n' \
	"$pre_stage_client_key_age_seconds"
printf 'pre_stage_server_key_age_seconds=%s\n' \
	"$pre_stage_server_key_age_seconds"
printf 'pre_stage_old_key_age_max_seconds=%s\n' \
	"$old_key_stage_max_age_seconds"
printf 'reject_after_time_seconds=%s\n' "$reject_after_time_seconds"
printf 'pre_stage_age_delay_monitor_total_seconds=%s\n' \
	"$(( pre_stage_old_key_age_seconds + stale_delay_seconds + stale_monitor_margin_seconds ))"
printf 'old_key_age_at_baseline_seconds=%s\n' "$old_key_age_seconds"
printf 'release_margin_seconds=%s\n' "$baseline_lead_seconds"
printf 'new_client_tx_during_release=%s->%s\n' \
	"$quiet_wgc_tx" "$wgc_tx_after_release"
printf 'delayed_rx_source_isolation=pass\n'
printf 'server_old_inner_echo_requests=%s->%s\n' \
	"$old_inner_echo_before_stale" "$old_inner_echo_after_release"
printf 'delayed_inner_echo_request=pass\n'
printf 'exact_old_tuple_immediately_before_release=pass\n'
printf 'pre_fwmark_quiet_window_seconds=%s\n' "$pre_fwmark_settle_duration"
printf 'pre_fwmark_syn_sent=0\n'
printf 'pre_fwmark_quiet_counters_and_handshakes=pass\n'
printf 'pre_fwmark_old_accepted_tuple_present=%s\n' "$pre_fwmark_old_tuple"
printf 'pre_fwmark_old_client_established_socket_absent=%s\n' \
	"$pre_fwmark_old_client_established_absent"
printf 'initial_endpoint=%s\nmoved_endpoint=%s\n' \
	"$initial_endpoint" "$moved_endpoint"
printf 'old_snat_source=%s:%s\nnew_snat_source=%s:%s\n' \
	"$old_public_address" "$old_snat_port" \
	"$new_public_address" "$new_snat_port"
printf 'authenticated_address_change=pass\n'
printf 'configured_forward_port=%s\nconfigured_port_preserved=pass\n' \
	"$forwarded_port"
printf 'reverse_syn_new_dnat=%s\nreverse_dnat=pass\n' \
	"$new_reverse_syn_delta"
printf 'initial_move_reverse_syn_new_dnat=%s\n' \
	"$initial_new_reverse_syn_delta"
printf 'forced_reconnect_fwmark=%s\n' "$forced_server_fwmark"
printf 'forced_reconnect_old_tuple=%s\n' "$forced_reconnect_old_tuple"
printf 'forced_reconnect_new_tuple=%s\n' "$forced_reconnect_new_tuple"
printf 'forced_reconnect_old_client_inbound_tuple=%s<->%s\n' \
	"$new_client_inbound_local" "$forced_reconnect_old_client_inbound_remote"
printf 'forced_reconnect_new_client_inbound_tuple=%s<->%s\n' \
	"$new_client_inbound_local" "$new_client_inbound_remote"
printf 'forced_reconnect_new_socket_mark=%s\n' "$forced_server_fwmark"
printf 'carrier_bootstrap_authentication=pass\n'
printf 'carrier_bootstrap_no_explicit_tunnel_traffic=pass\n'
printf 'carrier_bootstrap_quiet_required_seconds=%s\n' \
	"$carrier_auth_quiet_seconds"
printf 'carrier_bootstrap_quiet_seconds=%s\n' "$carrier_auth_duration"
printf 'carrier_bootstrap_replacement_tuple=%s\n' \
	"$forced_reconnect_new_tuple"
printf 'carrier_bootstrap_server_tx_before=%s\n' "$pre_fwmark_server_tx"
printf 'carrier_bootstrap_server_tx_after=%s\n' "$carrier_auth_server_tx"
printf 'carrier_bootstrap_server_tx_delta=%s\n' \
	"$(( carrier_auth_server_tx - pre_fwmark_server_tx ))"
printf 'carrier_bootstrap_wgc_rx_before=%s\n' "$pre_fwmark_wgc_rx"
printf 'carrier_bootstrap_wgc_rx_after=%s\n' "$carrier_auth_wgc_rx"
printf 'carrier_bootstrap_wgc_rx_delta=%s\n' \
	"$(( carrier_auth_wgc_rx - pre_fwmark_wgc_rx ))"
printf 'carrier_bootstrap_counter_delta=pass\n'
printf 'carrier_bootstrap_counter_stability=pass\n'
printf 'carrier_bootstrap_handshakes=%s,%s,%s\n' \
	"$carrier_auth_wga_handshake" "$carrier_auth_wgc_handshake" \
	"$carrier_auth_server_handshake"
printf 'carrier_bootstrap_transfers=%s/%s,%s/%s,%s/%s\n' \
	"$carrier_auth_wga_rx" "$carrier_auth_wga_tx" \
	"$carrier_auth_wgc_rx" "$carrier_auth_wgc_tx" \
	"$carrier_auth_server_rx" "$carrier_auth_server_tx"
printf 'forced_reconnect_old_residual_tcp_state=%s\n' \
	"$forced_reconnect_old_residual_state"
printf 'forced_reconnect_old_established_retired=pass\n'
printf 'forced_reconnect_reverse_syn_new_dnat=%s\n' \
	"$forced_new_reverse_syn_delta"
printf 'old_reverse_syn_before_release=%s\n' \
	"$old_reverse_syns_before_release"
printf 'old_reverse_syn_after_release=%s\n' \
	"$old_reverse_syns_after_release"
printf 'old_reverse_syn_after_forced_reconnect=%s\n' \
	"$old_reverse_syns_after_forced"
printf 'baseline_lead_seconds=%s\n' "$baseline_lead_seconds"
printf 'bidirectional_recovery=pass\n'
printf 'stale_probe_rx=%s->%s\n' "$server_rx_before" "$server_rx_after"
printf 'stale_old_carrier_rollback=blocked\n'
printf 'transient_rollback_syn_guard=pass\n'
printf 'old_accepted_carrier_after_probe=%s\n' "$old_carrier_after"
