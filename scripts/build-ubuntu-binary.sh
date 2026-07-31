#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
OUTPUT_DIR=$REPO_ROOT/docs/downloads
TARGET_KERNEL_RELEASE=

die() {
	printf 'build-ubuntu-binary: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Usage: scripts/build-ubuntu-binary.sh [--output-dir PATH] [--kernel-release RELEASE]

Build an Ubuntu 24.04, architecture-native WireguardTCP release archive for
the selected installed kernel (default: the running kernel). The archive
contains the compiled source tree, production kernel module, modified wg tool,
manifest, checksums, and guarded installer.
EOF
}

while (( $# )); do
	case "$1" in
	--output-dir) OUTPUT_DIR=${2:?--output-dir requires a value}; shift 2 ;;
	--kernel-release)
		TARGET_KERNEL_RELEASE=${2:?--kernel-release requires a value}
		shift 2
		;;
	--help) usage; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done

source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] ||
	die "Ubuntu 24.04 is required"
for command in dpkg git make modinfo python3 sha256sum tar; do
	command -v "$command" >/dev/null || die "required command not found: $command"
done

architecture=$(dpkg --print-architecture)
case "$architecture" in
amd64|arm64) ;;
*) die "unsupported architecture: $architecture" ;;
esac
kernel_release=${TARGET_KERNEL_RELEASE:-$(uname -r)}
[[ $kernel_release =~ ^[A-Za-z0-9._+-]+$ ]] ||
	die "unsafe kernel release: $kernel_release"
kernel_build=/lib/modules/$kernel_release/build
[[ -r $kernel_build/Makefile ]] ||
	die "matching kernel headers are required at $kernel_build"
revision=$(git -C "$REPO_ROOT" rev-parse HEAD)
[[ -z $(git -C "$REPO_ROOT" status --porcelain --untracked-files=no) ]] ||
	die "tracked source changes are present; build from a committed revision"

OUTPUT_DIR=$(mkdir -p -- "$OUTPUT_DIR"; cd -- "$OUTPUT_DIR" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
name=WireguardTCP-ubuntu-24.04-$architecture-$kernel_release
package=$work/$name
build=$package/compiled-tree
mkdir -p -- "$build"
git -C "$REPO_ROOT" archive --format=tar HEAD | tar -xf - -C "$build"

make -C "$build/tools" clean
make -C "$build/tools" -j"$(nproc)"
make -C "$kernel_build" M="$build/kernel" CONFIG_WIREGUARD=m clean
make -C "$kernel_build" M="$build/kernel" CONFIG_WIREGUARD=m \
	-j"$(nproc)" modules

install -D -m 0755 "$build/tools/wg" "$package/bin/wg"
install -D -m 0644 "$build/kernel/wireguard.ko" \
	"$package/lib/modules/$kernel_release/updates/wireguardtcp/wireguard.ko"
install -m 0755 "$SCRIPT_DIR/install-ubuntu-binary.sh" "$package/install.sh"
modinfo "$package/lib/modules/$kernel_release/updates/wireguardtcp/wireguard.ko" \
	>"$package/wireguard.modinfo"

python3 - "$package/manifest.json" "$revision" "$architecture" \
	"$kernel_release" <<'PY'
import datetime
import json
import pathlib
import platform
import sys

destination, revision, architecture, kernel_release = sys.argv[1:]
document = {
    "schema": 1,
    "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source_revision": revision,
    "ubuntu_release": "24.04",
    "architecture": architecture,
    "kernel_release": kernel_release,
    "platform": platform.platform(),
}
pathlib.Path(destination).write_text(
    json.dumps(document, indent=2) + "\n", encoding="utf-8"
)
PY

cat >"$package/INSTALL.txt" <<EOF
WireguardTCP Ubuntu 24.04 binary archive

Architecture: $architecture
Required running kernel: $kernel_release
Source revision: $revision

This unsigned out-of-tree module works only with the exact kernel release
listed above. Disable Secure Boot or sign the module with a locally trusted
key. Remove active WireGuard interfaces, then run:

  sudo ./install.sh

The complete compiled source tree is included in compiled-tree/.
EOF

(
	cd "$package"
	sha256sum \
		bin/wg \
		"lib/modules/$kernel_release/updates/wireguardtcp/wireguard.ko" \
		wireguard.modinfo \
		>"SHA256SUMS"
)
archive=$OUTPUT_DIR/$name.tar.gz
tar --sort=name --owner=0 --group=0 --numeric-owner \
	-czf "$archive" -C "$work" "$name"
sha256sum "$archive"
