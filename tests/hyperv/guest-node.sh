#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

ACTION=${1:-}
shift || true

STATE_ROOT=${WG_TEST_RUNTIME_ROOT:-/run/wireguardtcp-tests}
ARTIFACT_ROOT=${WG_TEST_STATE_ROOT:-/var/lib/wireguardtcp}/artifacts
WG_STOCK=$ARTIFACT_ROOT/bin/wg-stock
WG_FORK=$ARTIFACT_ROOT/bin/wg-fork

die() {
	printf 'guest-node: %s\n' "$*" >&2
	exit 1
}

(( EUID == 0 )) || die "run as root"

valid_token() {
	[[ $1 =~ ^[A-Za-z0-9_.-]+$ ]]
}

valid_iface() {
	valid_token "$1" && (( ${#1} <= 15 ))
}

valid_ipv4() {
	[[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

tool_path() {
	case "$1" in
	stock) printf '%s\n' "$WG_STOCK" ;;
	fork) printf '%s\n' "$WG_FORK" ;;
	*) die "unknown tool variant: $1" ;;
	esac
}

state_dir() {
	valid_token "$1" && valid_token "$2" || die "unsafe run or case identifier"
	printf '%s/%s/%s\n' "$STATE_ROOT" "$1" "$2"
}

owned_state_dir() {
	local run_id=$1 case_id=$2 iface=$3 dir
	dir=$(state_dir "$run_id" "$case_id")
	[[ -r $dir/iface && $(<"$dir/iface") == "$iface" ]] || \
		die "interface is not owned by this case"
	printf '%s\n' "$dir"
}

require_tool() {
	[[ -x $1 ]] || die "tool is not executable: $1"
}

new_interface_state() {
	local run_id=$1 case_id=$2 iface=$3 dir
	valid_iface "$iface" || die "unsafe interface name: $iface"
	dir=$(state_dir "$run_id" "$case_id")
	[[ ! -e $dir ]] || die "state already exists: $dir"
	install -d -m 0700 "$dir"
	printf '%s\n' "$iface" >"$dir/iface"
	printf '%s\n' "$dir"
}

new_auxiliary_state() {
	local run_id=$1 case_id=$2 dir
	dir=$(state_dir "$run_id" "$case_id")
	[[ ! -e $dir ]] || die "state already exists: $dir"
	install -d -m 0700 "$dir"
	printf 'owned\n' >"$dir/auxiliary"
	printf '%s\n' "$dir"
}

record_extra_iface() {
	local dir=$1 iface=$2
	valid_iface "$iface" || die "unsafe owned interface name: $iface"
	printf '%s\n' "$iface" >>"$dir/extra-ifaces"
}

expect_error_line() {
	local expected=$1 output first_line
	shift
	if output=$(LC_ALL=C "$@" 2>&1); then
		die "command unexpectedly succeeded; expected: $expected"
	fi
	first_line=${output%%$'\n'*}
	[[ $first_line == "$expected" ]] || \
		die "unexpected error message: $first_line (expected: $expected)"
}

netns_exists() {
	ip netns list | awk -v target="$1" '$1 == target { found = 1 } END { exit found ? 0 : 1 }'
}

case "$ACTION" in
prepare)
	(( $# == 7 )) || die "prepare RUN CASE IFACE TOOL TRANSPORT ADDRESS LISTEN_PORT|omit"
	run_id=$1 case_id=$2 iface=$3 tool_variant=$4 transport=$5 address=$6 listen_port=$7
	valid_iface "$iface" || die "unsafe interface name: $iface"
	tool=$(tool_path "$tool_variant")
	require_tool "$tool"
	if [[ $tool_variant == fork ]]; then
		[[ $transport == udp || $transport == tcp ]] || die "invalid transport: $transport"
	elif [[ $transport != udp ]]; then
		die "stock tool cannot configure transport $transport"
	fi
	dir=$(state_dir "$run_id" "$case_id")
	[[ ! -e $dir ]] || die "state already exists: $dir"
	if ip link show dev "$iface" >/dev/null 2>&1; then
		owners=()
		while IFS= read -r marker; do
			[[ -r $marker && $(<"$marker") == "$iface" ]] || continue
			relative=${marker#"$STATE_ROOT"/}
			owners+=("${relative%/iface}")
		done < <(find "$STATE_ROOT" -mindepth 3 -maxdepth 3 -type f -name iface -print 2>/dev/null)
		if (( ${#owners[@]} )); then
			die "refusing to replace existing link $iface; owned by run/case: ${owners[*]}"
		fi
		die "refusing to replace unowned existing link: $iface"
	fi
	install -d -m 0700 "$dir"
	umask 077
	printf '%s\n' "$iface" >"$dir/iface"
	created=0
	rollback() {
		status=$?
		trap - ERR EXIT
		(( created )) && ip link del dev "$iface" 2>/dev/null || true
		if (( created )) && ip link show dev "$iface" >/dev/null 2>&1; then
			printf 'guest-node: rollback could not remove owned interface %s; ownership state retained\n' "$iface" >&2
			exit 1
		fi
		rm -f "$dir/key" "$dir/iface" || true
		rmdir "$dir" 2>/dev/null || true
		exit "$status"
	}
	trap rollback ERR EXIT
	"$tool" genkey >"$dir/key"
	public_key=$("$tool" pubkey <"$dir/key")
	ip link add dev "$iface" type wireguard
	created=1
	set_args=(set "$iface" private-key "$dir/key")
	[[ $listen_port == omit ]] || set_args+=(listen-port "$listen_port")
	if [[ $tool_variant == fork ]]; then
		set_args+=(transport "$transport")
	fi
	"$tool" "${set_args[@]}"
	ip address add "$address" dev "$iface"
	ip link set dev "$iface" up
	listen_port=$("$tool" show "$iface" listen-port)
	[[ $listen_port =~ ^[0-9]+$ ]] && (( listen_port > 0 )) || die "invalid bound port: $listen_port"
	trap - ERR EXIT
	printf 'public_key=%s\nlisten_port=%s\n' "$public_key" "$listen_port"
	;;
peer)
	(( $# == 7 )) || die "peer RUN CASE IFACE TOOL PUBLIC_KEY ALLOWED_IP ENDPOINT"
	run_id=$1 case_id=$2 iface=$3 tool_variant=$4 public_key=$5 allowed_ip=$6 endpoint=$7
	dir=$(owned_state_dir "$run_id" "$case_id" "$iface")
	tool=$(tool_path "$tool_variant")
	"$tool" set "$iface" peer "$public_key" allowed-ips "$allowed_ip" endpoint "$endpoint"
	;;
endpoint)
	(( $# == 6 )) || die "endpoint RUN CASE IFACE TOOL PUBLIC_KEY ENDPOINT"
	run_id=$1 case_id=$2 iface=$3 tool_variant=$4 public_key=$5 endpoint=$6
	dir=$(owned_state_dir "$run_id" "$case_id" "$iface")
	"$(tool_path "$tool_variant")" set "$iface" peer "$public_key" endpoint "$endpoint"
	;;
stock-tcp-management)
	(( $# == 4 )) || die "stock-tcp-management RUN CASE IFACE PEER_PUBLIC_KEY"
	run_id=$1 case_id=$2 iface=$3 public_key=$4
	owned_state_dir "$run_id" "$case_id" "$iface" >/dev/null
	require_tool "$WG_STOCK"
	require_tool "$WG_FORK"
	[[ $("$WG_FORK" show "$iface" transport) == tcp ]] || die "interface is not in TCP mode"
	stock_public=$("$WG_STOCK" show "$iface" public-key)
	fork_public=$("$WG_FORK" show "$iface" public-key)
	[[ -n $stock_public && $stock_public == "$fork_public" ]] || die "stock tool could not inspect the TCP interface identity"
	stock_port=$("$WG_STOCK" show "$iface" listen-port)
	fork_port=$("$WG_FORK" show "$iface" listen-port)
	[[ $stock_port =~ ^[0-9]+$ && $stock_port == "$fork_port" ]] || die "stock tool reported the wrong TCP listen port"
	"$WG_STOCK" show "$iface" peers | grep -Fxq "$public_key" || die "stock tool could not inspect the TCP peer"
	"$WG_STOCK" set "$iface" peer "$public_key" persistent-keepalive 11
	keepalive=$("$WG_STOCK" show "$iface" persistent-keepalive | \
		awk -v key="$public_key" '$1 == key { print $2 }')
	[[ $keepalive == 11 ]] || die "stock tool did not update ordinary TCP peer configuration"
	[[ $("$WG_FORK" show "$iface" transport) == tcp ]] || die "stock management changed TCP transport selection"
	printf 'stock_identity=pass\nstock_listen_port=%s\nstock_peer_management=pass\ntransport=tcp\n' "$stock_port"
	;;
get-endpoint)
	(( $# == 3 )) || die "get-endpoint IFACE TOOL PUBLIC_KEY"
	iface=$1 tool_variant=$2 public_key=$3
	endpoint=$("$(tool_path "$tool_variant")" show "$iface" endpoints | \
		awk -v key="$public_key" '$1 == key { print $2 }')
	[[ -n $endpoint ]] || die "peer endpoint not found"
	printf 'endpoint=%s\n' "$endpoint"
	;;
ping)
	(( $# == 2 )) || die "ping IFACE DESTINATION"
	ping -I "$1" -c 3 -W 3 "$2"
	;;
wait-ping)
	(( $# == 3 )) || die "wait-ping IFACE DESTINATION TIMEOUT_SECONDS"
	iface=$1 destination=$2 timeout=$3
	[[ $timeout =~ ^[0-9]+$ ]] && (( timeout > 0 && timeout <= 600 )) || die "invalid wait-ping timeout"
	deadline=$(( SECONDS + timeout ))
	while (( SECONDS < deadline )); do
		if ping -I "$iface" -c 1 -W 2 "$destination" >/dev/null 2>&1; then
			printf 'ping=%s\n' "$destination"
			exit 0
		fi
		sleep 1
	done
	die "tunnel did not recover connectivity to $destination within ${timeout}s"
	;;
link-state)
	(( $# == 4 )) || die "link-state RUN CASE IFACE {up|down}"
	run_id=$1 case_id=$2 iface=$3 state=$4
	owned_state_dir "$run_id" "$case_id" "$iface" >/dev/null
	[[ $state == up || $state == down ]] || die "invalid link state: $state"
	ip link set dev "$iface" "$state"
	printf 'link=%s\nstate=%s\n' "$iface" "$state"
	;;
underlay-state)
	(( $# == 4 )) || die "underlay-state RUN CASE ADDRESS {up|down}"
	run_id=$1 case_id=$2 address=$3 state=$4
	valid_ipv4 "$address" || die "invalid IPv4 underlay address: $address"
	dir=$(state_dir "$run_id" "$case_id")
	[[ -r $dir/iface ]] || die "case has no ownership state"
	case "$state" in
	down)
		[[ ! -e $dir/underlay-iface ]] || die "case already owns an underlay transition"
		underlay_iface=$(ip -o -4 address show | awk -v target="$address" '
			{ split($4, field, "/"); if (field[1] == target) { print $2; exit } }')
		valid_iface "$underlay_iface" || die "could not resolve a safe interface for $address"
		printf '%s\n' "$underlay_iface" >"$dir/underlay-iface"
		ip link set dev "$underlay_iface" down
		;;
	up)
		[[ -r $dir/underlay-iface ]] || die "case does not own a disabled underlay"
		underlay_iface=$(<"$dir/underlay-iface")
		valid_iface "$underlay_iface" || die "unsafe saved underlay interface"
		ip link set dev "$underlay_iface" up
		rm -f "$dir/underlay-iface"
		;;
	*) die "invalid underlay state: $state" ;;
	esac
	printf 'underlay_interface=%s\nstate=%s\n' "$underlay_iface" "$state"
	;;
tcp-path)
	(( $# == 3 )) || die "tcp-path LOCAL_ADDRESS REMOTE_ADDRESS WIREGUARD_PORT"
	local_address=$1 remote_address=$2 port=$3
	valid_ipv4 "$local_address" && valid_ipv4 "$remote_address" || die "tcp-path requires IPv4 addresses"
	[[ $port =~ ^[0-9]+$ ]] && (( port > 0 && port <= 65535 )) || die "invalid WireGuard TCP port: $port"
	connections=$(ss -H -tn4 state established)
	printf '%s\n' "$connections" | awk \
		-v local="$local_address:" -v remote="$remote_address:" -v wg_port=":$port" '
		{
			local_seen = 0
			remote_seen = 0
			port_seen = 0
			for (i = 1; i <= NF; ++i) {
				if (index($i, local) == 1) local_seen = 1
				if (index($i, remote) == 1) remote_seen = 1
				if ((index($i, local) == 1 || index($i, remote) == 1) &&
				    substr($i, length($i) - length(wg_port) + 1) == wg_port)
					port_seen = 1
			}
			if (local_seen && remote_seen && port_seen) found = 1
		}
		END { exit found ? 0 : 1 }
	' || die "no established TCP connection between $local_address and $remote_address on WireGuard port $port"
	printf 'tcp_path=%s->%s\ntcp_port=%s\n' "$local_address" "$remote_address" "$port"
	;;
tcp-asymmetric-path)
	(( $# == 4 )) || die "tcp-asymmetric-path LOCAL_ADDRESS REMOTE_ADDRESS LOCAL_LISTEN_PORT REMOTE_LISTEN_PORT"
	local_address=$1 remote_address=$2 local_port=$3 remote_port=$4
	valid_ipv4 "$local_address" && valid_ipv4 "$remote_address" || \
		die "tcp-asymmetric-path requires IPv4 addresses"
	for port in "$local_port" "$remote_port"; do
		[[ $port =~ ^[0-9]+$ ]] && (( port > 0 && port <= 65535 )) || \
			die "invalid WireGuard TCP port: $port"
	done
	tuple=$(ss -H -tn4 state established | awk \
		-v local_address="$local_address" -v remote_address="$remote_address" \
		-v local_port="$local_port" -v remote_port="$remote_port" '
		{
			local_endpoint = remote_endpoint = ""
			for (i = 1; i <= NF; ++i) {
				if (index($i, local_address ":") == 1)
					local_endpoint = $i
				if (index($i, remote_address ":") == 1)
					remote_endpoint = $i
			}
			if (local_endpoint == "" || remote_endpoint == "")
				next
			observed_local = local_endpoint
			observed_remote = remote_endpoint
			sub(/^.*:/, "", observed_local)
			sub(/^.*:/, "", observed_remote)
			if (observed_local == local_port || observed_remote == remote_port) {
				print local_endpoint "->" remote_endpoint
				exit
			}
		}
	')
	[[ -n $tuple ]] || die "no established TCP connection uses either configured asymmetric listen port"
	printf 'tcp_path=%s\nlocal_listen_port=%s\nremote_listen_port=%s\n' \
		"$tuple" "$local_port" "$remote_port"
	;;
output-parity)
	(( $# == 1 )) || die "output-parity IFACE"
	iface=$1
	require_tool "$WG_STOCK"
	require_tool "$WG_FORK"
	tmp=$(mktemp -d)
	cleanup_tmp() { rm -f "$tmp"/*; rmdir "$tmp"; }
	trap cleanup_tmp EXIT
	for command in dump showconf show; do
		case "$command" in
		dump)
			"$WG_STOCK" show "$iface" dump >"$tmp/stock"
			"$WG_FORK" show "$iface" dump >"$tmp/fork"
			;;
		showconf)
			"$WG_STOCK" showconf "$iface" >"$tmp/stock"
			"$WG_FORK" showconf "$iface" >"$tmp/fork"
			;;
		show)
			"$WG_STOCK" show "$iface" >"$tmp/stock"
			"$WG_FORK" show "$iface" >"$tmp/fork"
			;;
		esac
		cmp -s "$tmp/stock" "$tmp/fork" || die "$command output differs (content withheld because it may contain keys)"
	done
	! grep -q 'Transport' "$tmp/fork" || die "UDP output unexpectedly contains Transport"
	! grep -qi 'transport:' "$tmp/fork" || die "UDP pretty output unexpectedly contains transport"
	printf 'output-parity=pass\n'
	;;
random-ports)
	(( $# == 3 )) || die "random-ports RUN CASE TOOL"
	run_id=$1 case_id=$2 tool_variant=$3
	tool=$(tool_path "$tool_variant")
	require_tool "$tool"
	dir=$(owned_state_dir "$run_id" "$case_id" wgt0)
	a=wgrandoma b=wgrandomb
	! ip link show dev "$a" >/dev/null 2>&1 || die "link already exists: $a"
	! ip link show dev "$b" >/dev/null 2>&1 || die "link already exists: $b"
	record_extra_iface "$dir" "$a"
	record_extra_iface "$dir" "$b"
	ip link add dev "$a" type wireguard
	ip link add dev "$b" type wireguard
	if [[ $tool_variant == fork ]]; then
		"$tool" set "$a" transport udp
		"$tool" set "$b" transport udp
	fi
	ip link set dev "$a" up
	ip link set dev "$b" up
	port_a=$("$tool" show "$a" listen-port)
	port_b=$("$tool" show "$b" listen-port)
	(( port_a > 0 && port_b > 0 && port_a != port_b )) || \
		die "expected distinct random ports, got $port_a and $port_b"
	printf 'port_a=%s\nport_b=%s\n' "$port_a" "$port_b"
	;;
mode-rejection)
	(( $# == 3 )) || die "mode-rejection RUN CASE IFACE"
	run_id=$1 case_id=$2 iface=$3
	require_tool "$WG_FORK"
	! ip link show dev "$iface" >/dev/null 2>&1 || die "link already exists: $iface"
	dir=$(new_interface_state "$run_id" "$case_id" "$iface")
	ip link add dev "$iface" type wireguard
	"$WG_FORK" set "$iface" listen-port 51990 transport udp
	ip link set dev "$iface" up
	expect_error_line "Unable to modify interface: Device or resource busy" \
		"$WG_FORK" set "$iface" transport tcp
	[[ $("$WG_FORK" show "$iface" transport) == udp ]] || \
		die "EBUSY while up changed the transport state"
	ip link set dev "$iface" down
	peer_key=$("$WG_FORK" genkey | "$WG_FORK" pubkey)
	"$WG_FORK" set "$iface" peer "$peer_key" allowed-ips 10.254.0.2/32
	expect_error_line "Unable to modify interface: Device or resource busy" \
		"$WG_FORK" set "$iface" transport tcp
	[[ $("$WG_FORK" show "$iface" transport) == udp ]] || \
		die "EBUSY with an existing peer changed the transport state"
	"$WG_FORK" set "$iface" peer "$peer_key" remove
	"$WG_FORK" set "$iface" transport tcp
	[[ $("$WG_FORK" show "$iface" transport) == tcp ]] || die "transport did not change after guards cleared"
	ip link set dev "$iface" up
	tcp_port=$("$WG_FORK" show "$iface" listen-port)
	expect_error_line "Unable to modify interface: Device or resource busy" \
		"$WG_FORK" set "$iface" listen-port 51992
	[[ $("$WG_FORK" show "$iface" listen-port) == "$tcp_port" ]] || \
		die "rejected live TCP port change altered the active port"
	ss -H -ltn "sport = :$tcp_port" | grep -q . || \
		die "TCP listener disappeared after rejected live port change"
	ss -H -lun "sport = :$tcp_port" | grep -q . || \
		die "companion UDP listener disappeared after rejected live port change"
	ip link set dev "$iface" down
	"$WG_FORK" set "$iface" listen-port 0
	ip link set dev "$iface" up
	random_tcp_port=$("$WG_FORK" show "$iface" listen-port)
	[[ $random_tcp_port =~ ^[0-9]+$ ]] && (( random_tcp_port > 0 )) || \
		die "TCP random port selection failed: $random_tcp_port"
	ss -H -ltn "sport = :$random_tcp_port" | grep -q . || \
		die "random TCP listener missing on $random_tcp_port"
	ss -H -lun "sport = :$random_tcp_port" | grep -q . || \
		die "random companion UDP listener missing on $random_tcp_port"
	ip link set dev "$iface" down
	"$WG_FORK" set "$iface" transport udp
	[[ $("$WG_FORK" show "$iface" transport) == udp ]] || die "transport did not return to UDP"
	printf 'mode-rejection=pass\nlive_tcp_port=%s\nrandom_tcp_port=%s\n' \
		"$tcp_port" "$random_tcp_port"
	;;
stock-capability)
	(( $# == 3 )) || die "stock-capability RUN CASE IFACE"
	run_id=$1 case_id=$2 iface=$3
	require_tool "$WG_FORK"
	! ip link show dev "$iface" >/dev/null 2>&1 || die "link already exists: $iface"
	dir=$(new_interface_state "$run_id" "$case_id" "$iface")
	ip link add dev "$iface" type wireguard
	"$WG_FORK" set "$iface" transport udp
	expect_error_line "Unable to modify interface: Operation not supported" \
		"$WG_FORK" set "$iface" listen-port 51991 transport tcp
	[[ $("$WG_FORK" show "$iface" transport) == udp ]] || \
		die "EOPNOTSUPP changed the stock kernel transport state"
	[[ $("$WG_FORK" show "$iface" listen-port) == 0 ]] || \
		die "EOPNOTSUPP partially applied the requested listen port"
	printf 'stock-capability=pass\n'
	;;
listener)
	(( $# == 2 )) || die "listener IFACE {udp|tcp}"
	iface=$1 transport=$2
	port=$("$WG_FORK" show "$iface" listen-port)
	case "$transport" in
	udp)
		ss -H -lun "sport = :$port" | grep -q . || die "UDP listener missing on $port"
		! ss -H -ltn "sport = :$port" | grep -q . || die "unexpected TCP listener on $port"
		;;
	tcp)
		ss -H -ltn "sport = :$port" | grep -q . || die "TCP listener missing on $port"
		ss -H -lun "sport = :$port" | grep -q . || \
			die "companion UDP listener missing for TCP mode on $port"
		printf 'udp_listener=present\n'
		;;
	*) die "invalid transport: $transport" ;;
	esac
	printf 'listener=%s\nport=%s\n' "$transport" "$port"
	;;
collect)
	(( $# == 2 )) || die "collect IFACE TOOL"
	iface=$1 tool=$(tool_path "$2")
	require_tool "$tool"
	printf '%s\n' '--- module ---'
"$(dirname "$0")/guest-module.sh" status
	printf '%s\n' '--- link ---'
	ip -details address show dev "$iface" 2>&1
	printf '%s\n' '--- public configuration ---'
	for selector in public-key listen-port endpoints allowed-ips latest-handshakes transfer; do
		"$tool" show "$iface" "$selector" 2>&1
	done
	printf '%s\n' '--- listening sockets ---'
	ss -H -lntu 2>&1
	printf '%s\n' '--- TCP connection state ---'
	ss -H -ntoepi 2>&1
	printf '%s\n' '--- kernel log since case reset ---'
	dmesg --color=never 2>&1
	;;
kernel-log-reset)
	(( $# == 0 )) || die "kernel-log-reset takes no arguments"
	command -v dmesg >/dev/null || die "dmesg is unavailable"
	dmesg --clear
	printf 'kernel_log=reset\n'
	;;
kernel-log-check)
	(( $# == 0 )) || die "kernel-log-check takes no arguments"
	command -v dmesg >/dev/null || die "dmesg is unavailable"
	severe=$({
		dmesg --level=emerg,alert,crit,err
		dmesg | grep -Ei \
			'BUG:|WARNING:|Oops:|KASAN:|KFENCE:|UBSAN:|use-after-free|general protection fault|kernel NULL pointer dereference|refcount_t:|scheduling while atomic|sleeping function called from invalid context|possible circular locking dependency' || true
	} | awk '!seen[$0]++')
	if [[ -n $severe ]]; then
		printf '%s\n' "$severe" >&2
		die "new severe kernel messages were emitted"
	fi
	printf 'kernel_log=clean\n'
	;;
diagnose)
	printf 'hostname=%s\nkernel=%s\n' "$(hostname)" "$(uname -r)"
	ip -brief address
	"$(dirname "$0")/guest-module.sh" status
	cat "$ARTIFACT_ROOT/manifest.json" 2>/dev/null || true
	;;
underlay)
	(( $# == 2 )) || die "underlay PATH0_ADDRESS PATH1_ADDRESS"
	for address in "$1" "$2"; do
		ip -o -4 address show | awk '{ print $4 }' | grep -Eq "^${address//./\\.}/" || \
			die "underlay address is missing: $address"
	done
	printf 'path0=%s\npath1=%s\n' "$1" "$2"
	;;
contract-tests)
	(( $# <= 1 )) || die "contract-tests [SOURCE_ROOT]"
	source_root=${1:-/home/ubuntu/WireguardTCP}
	[[ -f $source_root/tests/test_udp_compat_contract.py ]] || die "contract tests not found"
	cd "$source_root"
	python3 -B -m unittest discover -v
	;;
udp-netns)
	(( $# == 2 || $# == 3 )) || die "udp-netns RUN CASE [SOURCE_ROOT]"
	run_id=$1 case_id=$2 source_root=${3:-/home/ubuntu/WireguardTCP}
	[[ -f $source_root/tests/udp-compat-netns.sh ]] || die "UDP netns test not found"
	dir=$(new_auxiliary_state "$run_id" "$case_id")
	WG_FORK=$WG_FORK WG_STOCK=$WG_STOCK WG_TEST_OWNERSHIP_DIR=$dir \
		bash "$source_root/tests/udp-compat-netns.sh"
	;;
tcp-parity-netns)
	(( $# == 3 || $# == 4 )) || die "tcp-parity-netns RUN CASE MODE [SOURCE_ROOT]"
	run_id=$1 case_id=$2 mode=$3 source_root=${4:-/home/ubuntu/WireguardTCP}
	[[ $mode == fwmark || $mode == route || $mode == source-uplink || \
	   $mode == policy-churn || \
	   $mode == ipv6 || $mode == ipv6-link-local || \
	   $mode == carrier-lifetime || $mode == config-roundtrip || \
	   $mode == fault-injection ]] || \
		die "invalid TCP parity mode: $mode"
	[[ -f $source_root/tests/tcp-parity-netns.sh ]] || die "TCP parity netns test not found"
	dir=$(new_auxiliary_state "$run_id" "$case_id")
	if [[ $mode == fault-injection ]]; then
		module_helper=$(dirname "$0")/guest-module.sh
		restore_fault_module() {
			local primary_status=$? restore_status=0

			trap - EXIT HUP INT TERM
			set +e
			"$module_helper" fork >/dev/null
			restore_status=$?
			if (( restore_status != 0 )); then
				printf 'guest-node: hostile-stream status=%d; production module restore status=%d\n' \
					"$primary_status" "$restore_status" >&2
			fi
			if (( primary_status == 0 && restore_status == 0 )); then
				printf 'restored_kernel_variant=fork\n'
			fi
			(( primary_status == 0 )) || exit "$primary_status"
			exit "$restore_status"
		}
		trap restore_fault_module EXIT
		trap 'exit 129' HUP
		trap 'exit 130' INT
		trap 'exit 143' TERM
		"$module_helper" fork-fault >/dev/null
	fi
	WG_FORK=$WG_FORK WG_TEST_OWNERSHIP_DIR=$dir \
		bash "$source_root/tests/tcp-parity-netns.sh" "$mode"
	;;
tcp-nat-netns)
	(( $# == 3 || $# == 4 )) || die "tcp-nat-netns RUN CASE MODE [SOURCE_ROOT]"
	run_id=$1 case_id=$2 mode=$3 source_root=${4:-/home/ubuntu/WireguardTCP}
	[[ $mode == dual-reachable ]] || die "invalid TCP NAT mode: $mode"
	[[ -f $source_root/tests/tcp-nat-netns.sh ]] || die "TCP NAT netns test not found"
	dir=$(new_auxiliary_state "$run_id" "$case_id")
	WG_FORK=$WG_FORK WG_TEST_OWNERSHIP_DIR=$dir \
		bash "$source_root/tests/tcp-nat-netns.sh" "$mode"
	;;
tcp-roaming-netns)
	(( $# == 3 || $# == 4 )) || die "tcp-roaming-netns RUN CASE MODE [SOURCE_ROOT]"
	run_id=$1 case_id=$2 mode=$3 source_root=${4:-/home/ubuntu/WireguardTCP}
	[[ $mode == dual-router || $mode == half-open ]] || \
		die "invalid TCP roaming mode: $mode"
	[[ -f $source_root/tests/tcp-roaming-netns.sh ]] || \
		die "TCP roaming netns test not found"
	dir=$(new_auxiliary_state "$run_id" "$case_id")
	WG_FORK=$WG_FORK WG_TEST_OWNERSHIP_DIR=$dir \
		bash "$source_root/tests/tcp-roaming-netns.sh" "$mode"
	;;
cleanup)
	(( $# == 3 )) || die "cleanup RUN CASE IFACE"
	run_id=$1 case_id=$2 iface=$3
	valid_iface "$iface" || die "unsafe interface name: $iface"
	dir=$(state_dir "$run_id" "$case_id")
	if [[ ! -d $dir ]]; then
		! ip link show dev "$iface" >/dev/null 2>&1 || die "refusing to remove unowned interface: $iface"
		exit 0
	fi
	primary_owned=0 auxiliary_owned=0
	if [[ -e $dir/iface ]]; then
		[[ -r $dir/iface ]] || die "unreadable interface ownership state"
		[[ $(<"$dir/iface") == "$iface" ]] || die "state owns a different interface"
		primary_owned=1
	fi
	if [[ -e $dir/auxiliary ]]; then
		[[ -r $dir/auxiliary && $(<"$dir/auxiliary") == owned ]] || \
			die "invalid auxiliary ownership state"
		auxiliary_owned=1
	fi
	(( primary_owned || auxiliary_owned )) || die "state has no ownership marker"
	if (( ! primary_owned )) && ip link show dev "$iface" >/dev/null 2>&1; then
		die "refusing to remove unowned interface: $iface"
	fi

	owned_ifaces=()
	if [[ -e $dir/extra-ifaces ]]; then
		[[ -r $dir/extra-ifaces ]] || die "unreadable extra interface ownership state"
		mapfile -t owned_ifaces <"$dir/extra-ifaces"
		for owned_iface in "${owned_ifaces[@]}"; do
			valid_iface "$owned_iface" || die "unsafe saved interface name: $owned_iface"
		done
	fi
	owned_netns=()
	if [[ -e $dir/netns ]]; then
		[[ -r $dir/netns ]] || die "unreadable namespace ownership state"
		mapfile -t owned_netns <"$dir/netns"
		for namespace in "${owned_netns[@]}"; do
			valid_token "$namespace" && (( ${#namespace} <= 63 )) || \
				die "unsafe saved namespace name: $namespace"
		done
	fi

	if [[ -e $dir/underlay-iface ]]; then
		(( primary_owned )) || die "underlay state exists without an interface ownership marker"
		[[ -r $dir/underlay-iface ]] || die "unreadable underlay ownership state"
		underlay_iface=$(<"$dir/underlay-iface")
		valid_iface "$underlay_iface" || die "unsafe saved underlay interface"
		ip link set dev "$underlay_iface" up || die "failed to restore owned underlay interface: $underlay_iface"
		rm -f "$dir/underlay-iface"
	fi
	for namespace in "${owned_netns[@]}"; do
		if netns_exists "$namespace"; then
			ip netns del "$namespace" || die "failed to remove owned namespace: $namespace"
		fi
		netns_exists "$namespace" && die "owned namespace remains after cleanup: $namespace"
	done
	for owned_iface in "${owned_ifaces[@]}"; do
		if ip link show dev "$owned_iface" >/dev/null 2>&1; then
			ip link del dev "$owned_iface" || die "failed to remove owned interface: $owned_iface"
		fi
		! ip link show dev "$owned_iface" >/dev/null 2>&1 || \
			die "owned interface remains after cleanup: $owned_iface"
	done
	if (( primary_owned )) && ip link show dev "$iface" >/dev/null 2>&1; then
		ip link del dev "$iface" || die "failed to remove owned interface: $iface"
	fi
	if (( primary_owned )); then
		! ip link show dev "$iface" >/dev/null 2>&1 || \
			die "owned interface remains after cleanup: $iface"
	fi
	rm -f "$dir/key" "$dir/iface" "$dir/auxiliary" "$dir/extra-ifaces" "$dir/netns"
	rmdir "$dir" || die "owned state directory contains unexpected files: $dir"
	rmdir "$(dirname "$dir")" 2>/dev/null || true
	;;
*)
	die "unknown action: $ACTION"
	;;
esac
