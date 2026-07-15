#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
[[ -n "$ACTION" ]] || { echo "usage: $0 key|up|down|status [options]" >&2; exit 2; }
shift

INSTALL_DIR=/opt/wgtcp-meltdown
PEER_PUB=
PEER_PHYS=
LOCAL_UDP_IP=
PEER_UDP_IP=
LOCAL_TCP_IP=
PEER_TCP_IP=
MTU=1420
TCP_ROLE=active

while (($#)); do
	case "$1" in
	--install-dir) INSTALL_DIR="$2"; shift 2 ;;
	--peer-pub) PEER_PUB="$2"; shift 2 ;;
	--peer-phys) PEER_PHYS="$2"; shift 2 ;;
	--local-udp-ip) LOCAL_UDP_IP="$2"; shift 2 ;;
	--peer-udp-ip) PEER_UDP_IP="$2"; shift 2 ;;
	--local-tcp-ip) LOCAL_TCP_IP="$2"; shift 2 ;;
	--peer-tcp-ip) PEER_TCP_IP="$2"; shift 2 ;;
	--mtu) MTU="$2"; shift 2 ;;
	--tcp-role) TCP_ROLE="$2"; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

[[ $EUID -eq 0 ]] || { echo "setup-tunnels.sh must run as root" >&2; exit 1; }
WG="$INSTALL_DIR/bin/wg"
KEY="$INSTALL_DIR/state/wg.key"

ensure_key() {
	if [[ ! -s "$KEY" ]]; then
		umask 077
		"$WG" genkey > "$KEY"
	fi
}

down() {
	ip link delete wg-mt-udp 2>/dev/null || true
	ip link delete wg-mt-tcp 2>/dev/null || true
}

case "$ACTION" in
key)
	ensure_key
	"$WG" pubkey < "$KEY"
	exit 0
	;;
down)
	down
	exit 0
	;;
status)
	"$WG" show
	ip -brief addr show wg-mt-udp 2>/dev/null || true
	ip -brief addr show wg-mt-tcp 2>/dev/null || true
	exit 0
	;;
up) ;;
*) echo "unknown action: $ACTION" >&2; exit 2 ;;
esac

for value in "$PEER_PUB" "$PEER_PHYS" "$LOCAL_UDP_IP" "$PEER_UDP_IP" "$LOCAL_TCP_IP" "$PEER_TCP_IP"; do
	[[ -n "$value" ]] || { echo "missing tunnel option" >&2; exit 2; }
done
[[ "$TCP_ROLE" == active || "$TCP_ROLE" == passive ]] ||
	{ echo "--tcp-role must be active or passive" >&2; exit 2; }

ensure_key
down

configure_iface() {
	local iface="$1" transport="$2" port="$3" local_ip="$4" peer_ip="$5"
	ip link add dev "$iface" type wireguard
	ip address add "$local_ip/24" dev "$iface"
	if [[ "$transport" == tcp && "$TCP_ROLE" == passive ]]; then
		"$WG" set "$iface" private-key "$KEY" listen-port "$port" transport "$transport" \
			peer "$PEER_PUB" allowed-ips "$peer_ip/32"
	else
		"$WG" set "$iface" private-key "$KEY" listen-port "$port" transport "$transport" \
			peer "$PEER_PUB" endpoint "$PEER_PHYS:$port" allowed-ips "$peer_ip/32" persistent-keepalive 5
	fi
	ip link set mtu "$MTU" dev "$iface"
	ip link set up dev "$iface"
}

configure_iface wg-mt-udp udp 51820 "$LOCAL_UDP_IP" "$PEER_UDP_IP"
configure_iface wg-mt-tcp tcp 51821 "$LOCAL_TCP_IP" "$PEER_TCP_IP"
"$WG" show
