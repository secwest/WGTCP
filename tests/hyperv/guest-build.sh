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

verify() {
	local missing=0 path
	for path in \
		"$ARTIFACT_ROOT/bin/wg-stock" \
		"$ARTIFACT_ROOT/bin/wg-fork" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork.ko" \
		"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/wireguard-fork-debug.ko"; do
		if [[ ! -e $path ]]; then
			printf 'guest-build: missing artifact: %s\n' "$path" >&2
			missing=1
		fi
	done
	(( missing == 0 )) || return 1
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

for variant in wireguard-fork wireguard-fork-debug; do
	modinfo "$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant.ko" \
		>"$ARTIFACT_ROOT/modules/$KERNEL_RELEASE/$variant.modinfo"
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
