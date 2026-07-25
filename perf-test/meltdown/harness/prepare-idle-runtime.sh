#!/usr/bin/env bash
# Load and attest the pinned module without creating a WireGuard interface or carrier.
set -euo pipefail

if (( EUID != 0 )); then
    echo "prepare-idle-runtime.sh must run as root" >&2
    exit 2
fi

if (( $# != 0 )); then
    echo "usage: $0" >&2
    exit 2
fi

source_dir=/home/azureuser/WireguardTCP-meltdown-2b9513f
module="$source_dir/kernel/wireguard.ko"
expected_srcversion=01DA86291E0FBD2CD3C940C
expected_module_hash=771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e

fail() {
    echo "idle runtime preparation failed: $*" >&2
    exit 1
}

[[ "$(uname -r)" == "6.8.0-1062-azure" ]] || fail "kernel mismatch"
[[ -f "$module" ]] || fail "module is missing"
[[ "$(modinfo -F srcversion "$module")" == "$expected_srcversion" ]] ||
    fail "built module srcversion mismatch"
[[ "$(sha256sum "$module" | awk '{print $1}')" == "$expected_module_hash" ]] ||
    fail "module hash mismatch"

mapfile -t wireguard_interfaces < <(
    ip -o link show type wireguard 2>/dev/null |
        awk -F': ' '{ sub(/@.*/, "", $2); print $2 }'
)
(( ${#wireguard_interfaces[@]} == 0 )) ||
    fail "refusing module reload with WireGuard interfaces: ${wireguard_interfaces[*]}"

modprobe -r wireguard 2>/dev/null || true
[[ ! -e /sys/module/wireguard ]] ||
    fail "wireguard module remained loaded after unload"

IFS=, read -r -a dependencies <<< "$(modinfo -F depends "$module")"
for dependency in "${dependencies[@]}"; do
    [[ -z "$dependency" ]] || modprobe "$dependency"
done
insmod "$module"

[[ "$(cat /sys/module/wireguard/srcversion)" == "$expected_srcversion" ]] ||
    fail "loaded module srcversion mismatch"
[[ ! -e /sys/class/net/wg-mt-tcp && ! -e /sys/class/net/wg-mt-udp ]] ||
    fail "tunnel interface appeared during module preparation"
established="$(ss -Htn state established \
    '( sport = :51821 or dport = :51821 )' | sed '/^[[:space:]]*$/d' | wc -l)"
listeners="$(ss -Hltn | awk '$4 ~ /:51821$/ { count++ } END { print count + 0 }')"
[[ "$established" == "0" && "$listeners" == "0" ]] ||
    fail "port-51821 socket appeared during module preparation"

printf 'idle_runtime_ready_utc=%s module_srcversion=%s module_sha256=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" \
    "$expected_srcversion" "$expected_module_hash"
