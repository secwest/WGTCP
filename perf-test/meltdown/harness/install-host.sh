#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR=
INSTALL_DIR=/opt/wgtcp-meltdown
ROLE=
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while (($#)); do
	case "$1" in
	--source-dir) SOURCE_DIR="$2"; shift 2 ;;
	--install-dir) INSTALL_DIR="$2"; shift 2 ;;
	--role) ROLE="$2"; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

[[ $EUID -eq 0 ]] || { echo "install-host.sh must run as root" >&2; exit 1; }
[[ -n "$SOURCE_DIR" && -f "$SOURCE_DIR/kernel/wireguard.ko" && -x "$SOURCE_DIR/tools/wg" ]] ||
	{ echo "built source is missing" >&2; exit 2; }
[[ "$ROLE" == server || "$ROLE" == client ]] || { echo "--role server|client is required" >&2; exit 2; }

existing_ifaces=()
mapfile -t existing_ifaces < <(
	ip -o link show type wireguard 2>/dev/null |
		awk -F': ' '{sub(/@.*/, "", $2); print $2}'
)
for iface in "${existing_ifaces[@]}"; do
	case "$iface" in
	wg-mt-udp|wg-mt-tcp) ip link delete "$iface" 2>/dev/null || true ;;
	*) echo "refusing module replacement while unrelated WireGuard interface '$iface' exists" >&2; exit 1 ;;
	esac
done

mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/harness" "$INSTALL_DIR/state"
cp -a "$SCRIPT_DIR/." "$INSTALL_DIR/harness/"
install -m 0755 "$SOURCE_DIR/tools/wg" "$INSTALL_DIR/bin/wg"
sha256sum "$SOURCE_DIR/kernel/wireguard.ko" "$SOURCE_DIR/tools/wg" > "$INSTALL_DIR/state/build.sha256"

if [[ ! -e "$INSTALL_DIR/state/host-before.env" ]]; then
	{
		printf 'kernel=%s\n' "$(uname -r)"
		printf 'wireguard_was_loaded=%s\n' "$(lsmod | awk '$1=="wireguard"{print 1}' | head -1)"
		printf 'root_qdisc=%q\n' "$(tc qdisc show dev eth0 | tr '\n' ';')"
		printf 'tcp_cc=%s\n' "$(sysctl -n net.ipv4.tcp_congestion_control)"
	} > "$INSTALL_DIR/state/host-before.env"
fi

modprobe -r wireguard 2>/dev/null || true
IFS=, read -r -a dependencies <<< "$(modinfo -F depends "$SOURCE_DIR/kernel/wireguard.ko")"
for dependency in "${dependencies[@]}"; do
	[[ -z "$dependency" ]] || modprobe "$dependency"
done
insmod "$SOURCE_DIR/kernel/wireguard.ko"
loaded_srcversion="$(cat /sys/module/wireguard/srcversion)"
built_srcversion="$(modinfo -F srcversion "$SOURCE_DIR/kernel/wireguard.ko")"
[[ "$loaded_srcversion" == "$built_srcversion" ]] ||
	{ echo "loaded module does not match built module" >&2; exit 1; }

if [[ "$ROLE" == server ]]; then
	for unit in wgtcp-meltdown-iperf-inner wgtcp-meltdown-iperf-competitor wgtcp-meltdown-http; do
		systemctl stop "$unit.service" 2>/dev/null || true
		systemctl reset-failed "$unit.service" 2>/dev/null || true
	done
	systemd-run --unit=wgtcp-meltdown-iperf-inner --property=Restart=on-failure \
		/usr/bin/iperf3 -s -p 5201 >/dev/null
	systemd-run --unit=wgtcp-meltdown-iperf-competitor --property=Restart=on-failure \
		/usr/bin/iperf3 -s -p 5202 >/dev/null
	mkdir -p "$INSTALL_DIR/http"
	truncate -s 10240 "$INSTALL_DIR/http/10k.bin"
	truncate -s 102400 "$INSTALL_DIR/http/100k.bin"
	truncate -s 1048576 "$INSTALL_DIR/http/1m.bin"
	systemd-run --unit=wgtcp-meltdown-http --property=Restart=on-failure \
		/usr/bin/python3 -m http.server 8080 --bind 0.0.0.0 --directory "$INSTALL_DIR/http" >/dev/null
fi

printf 'INSTALL_OK host=%s role=%s module_srcversion=%s module_sha256=%s\n' \
	"$(hostname)" "$ROLE" "$loaded_srcversion" "$(sha256sum "$SOURCE_DIR/kernel/wireguard.ko" | awk '{print $1}')"
