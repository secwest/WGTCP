#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

SOURCE_ROOT=${1:-/home/ubuntu/WireguardTCP}
STATE_ROOT=${WG_TEST_STATE_ROOT:-/var/lib/wireguardtcp}
BUILD_ROOT=$STATE_ROOT/src
ARTIFACT_ROOT=$STATE_ROOT/artifacts
KERNEL_RELEASE=$(uname -r)
KERNEL_BUILD=/lib/modules/$KERNEL_RELEASE/build

die() {
	printf 'guest-build: %s\n' "$*" >&2
	exit 1
}

verify_module_metadata() {
	local actual_root error= module variant

	actual_root=$(mktemp -d)
	for variant in wireguard-fork wireguard-fork-debug wireguard-fork-fault; do
		module=$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant
		if ! modinfo "$module.ko" >"$actual_root/$variant.modinfo"; then
			error="could not inspect $variant"
			break
		fi
		if ! modinfo -p "$module.ko" >"$actual_root/$variant.params"; then
			error="could not inspect parameters for $variant"
			break
		fi
		if ! cmp -s "$actual_root/$variant.modinfo" "$module.modinfo"; then
			error="saved modinfo does not match $variant"
			break
		fi
		if ! cmp -s "$actual_root/$variant.params" "$module.params"; then
			error="saved parameter manifest does not match $variant"
			break
		fi
	done
	rm -rf "$actual_root"
	[[ -z $error ]] || die "$error"

	for variant in wireguard-fork wireguard-fork-debug; do
		if grep -q '^tcp_test_' \
			"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant.params"; then
			die "fault parameters leaked into $variant"
		fi
	done
	for parameter in max_send_bytes garbage_prefix_bytes queue_limit \
			write_delay_ms fail_send_netns fail_send_ifindex \
			fail_send_local_ipv4 fail_send_source_port \
			fail_send_remote_ipv4 fail_send_remote_port fail_next_send \
			short_writes injected_prefixes resyncs queue_drops \
			fatal_send_errors; do
		grep -q "^tcp_test_$parameter:" \
			"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-fault.params" || \
			die "fault module is missing tcp_test_$parameter"
	done
}

verify() {
	local missing=0 path
	for path in \
		"$ARTIFACT_ROOT/bin/wg-stock" \
		"$ARTIFACT_ROOT/bin/wg-fork" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork.ko" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-debug.ko" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-fault.ko" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork.modinfo" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-debug.modinfo" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-fault.modinfo" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork.params" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-debug.params" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-fault.params" \
		"$ARTIFACT_ROOT/manifest.json"; do
		if [[ ! -e $path ]]; then
			printf 'guest-build: missing artifact: %s\n' "$path" >&2
			missing=1
		fi
	done
	(( missing == 0 )) || return 1
	verify_module_metadata
	python3 - "$ARTIFACT_ROOT/manifest.json" "$KERNEL_RELEASE" <<'PY'
import json
import pathlib
import sys

path, expected_kernel = sys.argv[1:]
manifest = json.loads(pathlib.Path(path).read_text())
if manifest.get("kernel_release") != expected_kernel:
    raise SystemExit(
        f"guest-build: manifest kernel {manifest.get('kernel_release')!r} "
        f"does not match {expected_kernel!r}"
    )
PY
	printf 'guest-build: artifacts verified for %s\n' "$KERNEL_RELEASE"
}

if [[ ${1:-} == --verify ]]; then
	verify
	exit
fi

(( EUID == 0 )) || die "run as root"
[[ -d $SOURCE_ROOT/kernel && -d $SOURCE_ROOT/tools ]] || \
	die "not a WireguardTCP source tree: $SOURCE_ROOT"
[[ -d $KERNEL_BUILD ]] || die "kernel headers not installed at $KERNEL_BUILD"
command -v wg >/dev/null || die "stock wg tool is not installed"

SOURCE_ROOT=$(readlink -f "$SOURCE_ROOT")
[[ $STATE_ROOT == /* && $STATE_ROOT != / ]] || die "unsafe state root: $STATE_ROOT"
[[ $BUILD_ROOT == "$STATE_ROOT/src" ]] || die "unsafe build root: $BUILD_ROOT"

install -d -m 0755 "$BUILD_ROOT" "$ARTIFACT_ROOT/bin" \
	"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE"

# Build from an isolated copy so mounted or transferred source remains pristine.
rsync -a --delete \
	--exclude=.git/ \
	--exclude=.agents/ \
	--exclude='tests/hyperv/results/' \
	--exclude='*.o' \
	--exclude='*.d' \
	--exclude='*.ko' \
	--exclude='*.mod' \
	--exclude='*.mod.c' \
	--exclude='.*.cmd' \
	"$SOURCE_ROOT/" "$BUILD_ROOT/"

make -C "$BUILD_ROOT/tools" clean
make -C "$BUILD_ROOT/tools" -j"$(nproc)" V=1
install -m 0755 "$BUILD_ROOT/tools/wg" "$ARTIFACT_ROOT/bin/wg-fork"
install -m 0755 "$(command -v wg)" "$ARTIFACT_ROOT/bin/wg-stock"

make -C "$KERNEL_BUILD" M="$BUILD_ROOT/kernel" CONFIG_WIREGUARD=m clean
make -C "$KERNEL_BUILD" M="$BUILD_ROOT/kernel" CONFIG_WIREGUARD=m \
	W=1 -j"$(nproc)" modules
install -m 0644 "$BUILD_ROOT/kernel/wireguard.ko" \
	"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork.ko"

make -C "$KERNEL_BUILD" M="$BUILD_ROOT/kernel" CONFIG_WIREGUARD=m clean
make -C "$KERNEL_BUILD" M="$BUILD_ROOT/kernel" CONFIG_WIREGUARD=m \
	CONFIG_WIREGUARD_DEBUG=y W=1 -j"$(nproc)" modules
install -m 0644 "$BUILD_ROOT/kernel/wireguard.ko" \
	"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-debug.ko"

make -C "$KERNEL_BUILD" M="$BUILD_ROOT/kernel" CONFIG_WIREGUARD=m clean
make -C "$KERNEL_BUILD" M="$BUILD_ROOT/kernel" CONFIG_WIREGUARD=m \
	CONFIG_WIREGUARD_DEBUG=y EXTRA_CFLAGS=-DWG_TCP_FAULT_INJECTION \
	W=1 -j"$(nproc)" modules
install -m 0644 "$BUILD_ROOT/kernel/wireguard.ko" \
	"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-fault.ko"

for variant in wireguard-fork wireguard-fork-debug wireguard-fork-fault; do
	modinfo "$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant.ko" \
		>"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant.modinfo"
	modinfo -p "$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant.ko" \
		>"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant.params"
done

python3 - "$ARTIFACT_ROOT/manifest.json" "$SOURCE_ROOT" "$KERNEL_RELEASE" <<'PY'
import datetime
import json
import pathlib
import subprocess
import sys

destination, source, kernel = sys.argv[1:]
try:
    revision = subprocess.check_output(
        ["git", "-C", source, "rev-parse", "HEAD"], text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except (OSError, subprocess.CalledProcessError):
    revision = "snapshot-without-git-metadata"

manifest = {
    "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "kernel_release": kernel,
    "source": source,
    "revision": revision,
}
pathlib.Path(destination).write_text(json.dumps(manifest, indent=2) + "\n")
PY

verify
printf 'guest-build: PASS\n'
