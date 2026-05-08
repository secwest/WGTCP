#!/bin/bash
# setup-tunnel.sh — idempotent. Brings up one (UDP, TCP baseline) tunnel pair
# between two peers. Defaults match the smoke-test layout (wg-udp0/wg-tcp0
# on ports 51820/51821, /24 tunnel net at 10.99.0.x).
#
# For multi-pair fleets (full campaign) the orchestrator passes per-pair
# values via --udp-iface / --tcp-iface / --my-udp-port / --my-tcp-port /
# --peer-udp-port / --peer-tcp-port / --tunnel-cidr.
#
# Usage:
#   setup-tunnel.sh \
#       --role server|client \
#       --my-priv-key /path/to/priv \
#       --peer-pub-key <base64> \
#       --peer-host 1.2.3.4 \
#       --my-tunnel-ip 10.99.0.1 \
#       --peer-tunnel-ip 10.99.0.2 \
#       [--udp-iface wg-udp0] [--tcp-iface wg-tcp0] \
#       [--my-udp-port 51820]   [--my-tcp-port 51821] \
#       [--peer-udp-port 51820] [--peer-tcp-port 51821] \
#       [--tunnel-cidr 24]

set -euo pipefail

ROLE=""; PRIV=""; PEERPUB=""; PEERHOST=""; MYIP=""; PEERIP=""
UDP_IFACE="wg-udp0"; TCP_IFACE="wg-tcp0"
MY_UDP_PORT=51820;  MY_TCP_PORT=51821
PEER_UDP_PORT=51820; PEER_TCP_PORT=51821
TUNNEL_CIDR=24

# Backward-compat: old --peer-endpoint host:port style still accepted; if
# given, port is parsed and used as MY_UDP_PORT base / PEER_UDP_PORT base.
LEGACY_PEER_ENDPOINT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)            ROLE="$2"; shift 2 ;;
    --my-priv-key)     PRIV="$2"; shift 2 ;;
    --peer-pub-key)    PEERPUB="$2"; shift 2 ;;
    --peer-host)       PEERHOST="$2"; shift 2 ;;
    --peer-endpoint)   LEGACY_PEER_ENDPOINT="$2"; shift 2 ;;
    --my-tunnel-ip)    MYIP="$2"; shift 2 ;;
    --peer-tunnel-ip)  PEERIP="$2"; shift 2 ;;
    --udp-iface)       UDP_IFACE="$2"; shift 2 ;;
    --tcp-iface)       TCP_IFACE="$2"; shift 2 ;;
    --my-udp-port)     MY_UDP_PORT="$2"; shift 2 ;;
    --my-tcp-port)     MY_TCP_PORT="$2"; shift 2 ;;
    --peer-udp-port)   PEER_UDP_PORT="$2"; shift 2 ;;
    --peer-tcp-port)   PEER_TCP_PORT="$2"; shift 2 ;;
    --tunnel-cidr)     TUNNEL_CIDR="$2"; shift 2 ;;
    *) echo "unknown $1"; exit 2 ;;
  esac
done

if [[ -n "$LEGACY_PEER_ENDPOINT" && -z "$PEERHOST" ]]; then
  PEERHOST="${LEGACY_PEER_ENDPOINT%%:*}"
fi

write_conf() {
  local iface="$1" transport="$2" my_port="$3" peer_port="$4"
  local conf=/etc/wireguard/${iface}.conf
  sudo install -m 0600 /dev/stdin "$conf" <<EOF
[Interface]
PrivateKey = $(cat "$PRIV")
Address    = ${MYIP}/${TUNNEL_CIDR}
ListenPort = ${my_port}
# Custom param consumed by WireguardTCP:
#   transport=udp -> stock UDP behaviour (control case)
#   transport=tcp -> TCP baseline transport
Transport  = ${transport}

[Peer]
PublicKey  = ${PEERPUB}
AllowedIPs = ${PEERIP}/32
Endpoint   = ${PEERHOST}:${peer_port}
PersistentKeepalive = 25
EOF
}

write_conf "$UDP_IFACE" udp "$MY_UDP_PORT" "$PEER_UDP_PORT"
write_conf "$TCP_IFACE" tcp "$MY_TCP_PORT" "$PEER_TCP_PORT"

sudo timeout 10 wg-quick down "$UDP_IFACE" 2>/dev/null || true
sudo timeout 10 wg-quick down "$TCP_IFACE" 2>/dev/null || true
sudo timeout 5 ip link delete "$UDP_IFACE" 2>/dev/null || true
sudo timeout 5 ip link delete "$TCP_IFACE" 2>/dev/null || true
sudo wg-quick up "$UDP_IFACE"
sudo wg-quick up "$TCP_IFACE"

sudo wg show "$UDP_IFACE"
sudo wg show "$TCP_IFACE"
echo "tunnels up: $UDP_IFACE (udp ${MY_UDP_PORT}->${PEERHOST}:${PEER_UDP_PORT}) $TCP_IFACE (tcp ${MY_TCP_PORT}->${PEERHOST}:${PEER_TCP_PORT})"
