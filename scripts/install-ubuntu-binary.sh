#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -Eeuo pipefail

die() {
	printf 'install-ubuntu-binary: %s\n' "$*" >&2
	exit 1
}

(( EUID == 0 )) || die "run as root"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
MANIFEST=$SCRIPT_DIR/manifest.json
CHECKSUMS=$SCRIPT_DIR/SHA256SUMS
[[ -r $MANIFEST ]] || die "manifest not found: $MANIFEST"
[[ -r $CHECKSUMS ]] || die "checksums not found: $CHECKSUMS"
command -v python3 >/dev/null || die "python3 is required"
command -v sha256sum >/dev/null || die "sha256sum is required"
command -v depmod >/dev/null || die "depmod is required"
command -v modprobe >/dev/null || die "modprobe is required"

mapfile -t manifest < <(python3 - "$MANIFEST" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for key in ("ubuntu_release", "architecture", "kernel_release"):
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise SystemExit(f"invalid manifest field: {key}")
    print(value)
PY
)
(( ${#manifest[@]} == 3 )) || die "manifest parsing failed"
expected_ubuntu=${manifest[0]}
expected_arch=${manifest[1]}
expected_kernel=${manifest[2]}

source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == "$expected_ubuntu" ]] ||
	die "this archive requires Ubuntu $expected_ubuntu"
[[ $(dpkg --print-architecture) == "$expected_arch" ]] ||
	die "this archive requires architecture $expected_arch"
[[ $(uname -r) == "$expected_kernel" ]] ||
	die "this archive requires running kernel $expected_kernel"

(cd "$SCRIPT_DIR" && sha256sum --check SHA256SUMS)
if ip -o link show type wireguard 2>/dev/null | grep -q .; then
	die "remove active WireGuard interfaces before replacing the module"
fi

module_source=$SCRIPT_DIR/lib/modules/$expected_kernel/updates/wireguardtcp/wireguard.ko
module_target=/lib/modules/$expected_kernel/updates/wireguardtcp/wireguard.ko
tool_source=$SCRIPT_DIR/bin/wg
[[ -r $module_source ]] || die "module payload is missing"
[[ -x $tool_source ]] || die "wg payload is missing"

modprobe -r wireguard 2>/dev/null || true
install -D -m 0755 "$tool_source" /usr/local/bin/wg
install -D -m 0644 "$module_source" "$module_target"
depmod -a "$expected_kernel"
modprobe wireguard

[[ $(modinfo -F filename wireguard) == "$module_target" ]] ||
	die "the installed WireguardTCP module was not selected"
printf 'WireguardTCP installed for %s on %s\n' "$expected_kernel" "$expected_arch"
