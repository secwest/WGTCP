#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

ACTION=${1:-status}
STATE_ROOT=${WG_TEST_STATE_ROOT:-/var/lib/wireguardtcp}
KERNEL_RELEASE=$(uname -r)
FORK_MODULE=$STATE_ROOT/artifacts/modules/$KERNEL_RELEASE/wireguard-fork.ko
FORK_DEBUG_MODULE=$STATE_ROOT/artifacts/modules/$KERNEL_RELEASE/wireguard-fork-debug.ko
VARIANT_FILE=/run/wireguardtcp-module-variant

die() {
	printf 'guest-module: %s\n' "$*" >&2
	exit 1
}

module_loaded() {
	[[ -d /sys/module/wireguard ]]
}

module_unloadable() {
	grep -q '^wireguard ' /proc/modules
}

active_links() {
	local namespace
	ip -o link show type wireguard 2>/dev/null || true
	while read -r namespace _; do
		[[ -n $namespace ]] || continue
		ip netns exec "$namespace" ip -o link show type wireguard 2>/dev/null || true
	done < <(ip netns list 2>/dev/null || true)
}

status() {
	local loaded=false variant=none unloadable=false
	module_loaded && loaded=true
	module_unloadable && unloadable=true
	if [[ -r $VARIANT_FILE ]]; then
		variant=$(<"$VARIANT_FILE")
	elif module_loaded; then
		variant=unknown
	fi
	printf 'loaded=%s\nvariant=%s\nunloadable=%s\nkernel_release=%s\n' \
		"$loaded" "$variant" "$unloadable" "$KERNEL_RELEASE"
}

unload_current() {
	local links
	links=$(active_links)
	[[ -z $links ]] || die "refusing to unload while WireGuard links exist: $links"
	module_loaded || return 0
	module_unloadable || die "the active WireGuard driver is built into this kernel and cannot be switched"
	modprobe -r wireguard || die "could not unload the active WireGuard module"
	rm -f "$VARIANT_FILE"
}

if [[ $ACTION == status ]]; then
	status
	exit
fi

(( EUID == 0 )) || die "run as root"

case "$ACTION" in
stock)
	unload_current
	modprobe wireguard || die "could not load the modular stock WireGuard driver"
	module_loaded || die "stock WireGuard did not register after modprobe"
	module_unloadable || \
		die "stock WireGuard is built into this kernel and cannot be switched"
	printf 'stock\n' >"$VARIANT_FILE"
	;;
fork|fork-debug)
	module_path=$FORK_MODULE
	[[ $ACTION == fork-debug ]] && module_path=$FORK_DEBUG_MODULE
	[[ -f $module_path ]] || die "fork module not built: $module_path"
	unload_current
	dependencies=$(modinfo -F depends "$module_path") || \
		die "could not resolve dependencies for $module_path"
	IFS=, read -ra dependency_list <<<"$dependencies"
	for dependency in "${dependency_list[@]}"; do
		dependency=${dependency//[[:space:]]/}
		[[ -n $dependency ]] || continue
		modprobe "$dependency" || \
			die "could not load dependency $dependency for $module_path"
	done
	if ! insmod "$module_path"; then
		if [[ -r /sys/kernel/security/lockdown ]] && \
			grep -Eq '\[(integrity|confidentiality)\]' \
				/sys/kernel/security/lockdown; then
			die "kernel lockdown rejected the unsigned test module"
		fi
		die "could not load fork module"
	fi
	printf '%s\n' "$ACTION" >"$VARIANT_FILE"
	;;
*)
	die "usage: $0 {stock|fork|fork-debug|status}"
	;;
esac

status
