#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

SOURCE_ROOT=${1:-/home/ubuntu/WireguardTCP}
STATE_ROOT=${WG_TEST_STATE_ROOT:-/var/lib/wireguardtcp}
APT_STAMP=$STATE_ROOT/.apt-updated

die() {
	printf 'guest-bootstrap: %s\n' "$*" >&2
	exit 1
}

(( EUID == 0 )) || die "run as root (for example: sudo $0 $SOURCE_ROOT)"
[[ -d $SOURCE_ROOT ]] || die "repository directory not found: $SOURCE_ROOT"

export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 "$STATE_ROOT" "$STATE_ROOT/artifacts/bin" \
	"$STATE_ROOT/artifacts/modules/$(uname -r)" /run/wireguardtcp-tests

if [[ ! -e $APT_STAMP ]] || ! find "$APT_STAMP" -mmin -720 -print -quit | grep -q .; then
	apt-get update
fi

packages=(
	build-essential
	conntrack
	iperf3
	iproute2
	iputils-ping
	jq
	kmod
	libmnl-dev
	linux-headers-"$(uname -r)"
	nftables
	pkg-config
	python3
	rsync
	tcpdump
	wireguard-tools
)

# Some Ubuntu images split the in-tree WireGuard module into linux-modules-extra.
extra_package=linux-modules-extra-"$(uname -r)"
if apt-cache show "$extra_package" >/dev/null 2>&1; then
	packages+=("$extra_package")
fi

apt-get install -y --no-install-recommends "${packages[@]}"
touch "$APT_STAMP"

kernel_release=$(uname -r)
kernel_config=/boot/config-$kernel_release
kernel_build=/lib/modules/$kernel_release/build
[[ -r $kernel_config ]] || die "kernel configuration not found: $kernel_config"
grep -q '^CONFIG_MODULES=y$' "$kernel_config" || \
	die "kernel does not support loadable modules: CONFIG_MODULES is not enabled"
grep -q '^CONFIG_WIREGUARD=m$' "$kernel_config" || \
	die "stock WireGuard is not configured as a modular driver"
[[ -f $kernel_build/Makefile ]] || \
	die "matching kernel headers not found: $kernel_build"
stock_module=$(modinfo -k "$kernel_release" -F filename wireguard 2>/dev/null) || \
	die "modular stock WireGuard is unavailable for kernel $kernel_release"
[[ -n $stock_module && $stock_module != '(builtin)' ]] || \
	die "stock WireGuard is built into the kernel and cannot be switched"
if [[ -d /sys/module/wireguard ]]; then
	grep -q '^wireguard ' /proc/modules || \
		die "the active WireGuard driver is built into the kernel"
	modprobe -r wireguard || \
		die "the active WireGuard module cannot be unloaded for preflight"
fi
modprobe wireguard || die "could not load the modular stock WireGuard driver"
grep -q '^wireguard ' /proc/modules || \
	die "stock WireGuard did not register as a loadable module"
modprobe -r wireguard || die "stock WireGuard module cannot be unloaded"

for helper in guest-bootstrap.sh guest-build.sh guest-module.sh guest-node.sh; do
	[[ -f $SOURCE_ROOT/tests/hyperv/$helper ]] || die "missing helper: $helper"
	chmod 0755 "$SOURCE_ROOT/tests/hyperv/$helper"
done

cat >"$STATE_ROOT/bootstrap.env" <<EOF
BOOTSTRAPPED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
KERNEL_RELEASE=$(uname -r)
SOURCE_ROOT=$SOURCE_ROOT
EOF

printf 'guest-bootstrap: PASS (Ubuntu %s, kernel %s)\n' \
	"$(. /etc/os-release && printf '%s' "${VERSION_ID:-unknown}")" "$(uname -r)"
