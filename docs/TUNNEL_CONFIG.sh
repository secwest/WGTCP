# WireGuard TCP Test Environment — Tunnel & Node Configuration
#
# Authoritative configuration assigned by master (10.20.20.102) on 2026-03-09.
# Both test nodes have acknowledged these assignments.
#
# To restart this environment from scratch, follow the steps in each section.

# =============================================================================
# NETWORK TOPOLOGY
# =============================================================================
#
#   Master (10.20.20.102)         ← git repo, relay server, coordination
#       |
#       +-- Node 104 (10.20.20.104)  ← VM1, WireGuard tunnel endpoint
#       |
#       +-- Node 109 (10.20.20.109)  ← VM2, WireGuard tunnel endpoint
#
#   WireGuard Tunnel (TCP transport):
#       VM1 (10.0.3.1) <---wg0---> VM2 (10.0.3.2)
#       104:51820/tcp               109:51820/tcp

# =============================================================================
# KEYS
# =============================================================================
#
# VM1 (Node 104):
#   Private: provisioned separately at /etc/wireguard/private.key
#   Public:  I610z8JCf9Wv24eQS/qJVSavi2M2/TRyf67l59n+Ym4=
#
# VM2 (Node 109):
#   Private: provisioned separately at /etc/wireguard/private.key
#   Public:  BPSOiEG8+Yxizx/KOIiKuGIECIWckkFolZczyaR/Mng=

# =============================================================================
# NODE 104 — VM1 SETUP (run on 10.20.20.104)
# =============================================================================

# --- vconf.bash for node 104 (VM1) ---
# Save this as ~/vconf.bash on node 104:

VM1_PRIVATE_KEY_FILE="/etc/wireguard/private.key"
VM1_PUBLIC_KEY="I610z8JCf9Wv24eQS/qJVSavi2M2/TRyf67l59n+Ym4="
VM2_PUBLIC_KEY="BPSOiEG8+Yxizx/KOIiKuGIECIWckkFolZczyaR/Mng="
VM1_TUNNEL_IP="10.0.3.1/24"
VM2_TUNNEL_IP="10.0.3.2"
LISTEN_PORT=51820
PEER_ENDPOINT="10.20.20.109:51820"
TRANSPORT="tcp"

# --- Commands to bring up tunnel on node 104 ---

# 1. Load module
sudo insmod /home/dr/linux-source-6.8.0/drivers/net/wireguard/wireguard.ko

# 2. Create interface
sudo ip link add wg0 type wireguard
sudo ip addr add 10.0.3.1/24 dev wg0

# 3. Configure WireGuard
sudo ~/wg set wg0 private-key "$VM1_PRIVATE_KEY_FILE"
sudo ~/wg set wg0 listen-port 51820 transport tcp
sudo ip link set up dev wg0

# 4. Add peer (VM2 = node 109)
sudo ~/wg set wg0 peer BPSOiEG8+Yxizx/KOIiKuGIECIWckkFolZczyaR/Mng= \
    allowed-ips 10.0.3.2/32 \
    endpoint 10.20.20.109:51820 \
    persistent-keepalive 25

# 5. Route
sudo ip route add 10.0.3.2/32 dev wg0

# =============================================================================
# NODE 109 — VM2 SETUP (run on 10.20.20.109)
# =============================================================================

# --- vconf.bash for node 109 (VM2) ---
# Save this as ~/vconf.bash on node 109:

VM2_PRIVATE_KEY_FILE="/etc/wireguard/private.key"
VM2_PUBLIC_KEY="BPSOiEG8+Yxizx/KOIiKuGIECIWckkFolZczyaR/Mng="
VM1_PUBLIC_KEY="I610z8JCf9Wv24eQS/qJVSavi2M2/TRyf67l59n+Ym4="
VM2_TUNNEL_IP="10.0.3.2/24"
VM1_TUNNEL_IP="10.0.3.1"
LISTEN_PORT=51820
PEER_ENDPOINT="10.20.20.104:51820"
TRANSPORT="tcp"

# --- Commands to bring up tunnel on node 109 ---

# 1. Load module
sudo insmod /home/dr/linux-source-6.8.0/drivers/net/wireguard/wireguard.ko

# 2. Create interface
sudo ip link add wg0 type wireguard
sudo ip addr add 10.0.3.2/24 dev wg0

# 3. Configure WireGuard
sudo ~/wg set wg0 private-key "$VM2_PRIVATE_KEY_FILE"
sudo ~/wg set wg0 listen-port 51820 transport tcp
sudo ip link set up dev wg0

# 4. Add peer (VM1 = node 104)
sudo ~/wg set wg0 peer I610z8JCf9Wv24eQS/qJVSavi2M2/TRyf67l59n+Ym4= \
    allowed-ips 10.0.3.1/32 \
    endpoint 10.20.20.104:51820 \
    persistent-keepalive 25

# 5. Route
sudo ip route add 10.0.3.1/32 dev wg0

# =============================================================================
# MASTER (10.20.20.102) — RELAY & COORDINATION
# =============================================================================

# 1. Start relay server
cp /home/dr/naked_gun/relay_server.py /tmp/agent_http_server.py
python3 /tmp/agent_http_server.py &

# 2. Verify relay
curl -s http://localhost:4040/status | jq .

# 3. Broadcast hello to reconnect nodes
curl -s -X POST http://localhost:4040/broadcast \
  -H "Content-Type: application/json" \
  -d '{"from":"10.20.20.102","type":"hello","body":"Master relay restarted. Resume polling."}'

# 4. Check node messages
curl -s http://localhost:4040/messages?for=10.20.20.102 | jq .

# =============================================================================
# BACKGROUND POLLER — RUN ON EACH TEST NODE
# =============================================================================
#
# The poller (node_poller.py v5) runs continuously and:
# - Polls master relay (10.20.20.102:4040) every 10s
# - Executes shell commands from master autonomously
# - Sends heartbeats and command results back
# - Logs to /tmp/node_poller.log
#
# On node 104 (VM1):
#   nohup python3 /tmp/node_poller.py 10.20.20.104 VM1 >> /tmp/node_poller.log 2>&1 &
#
# On node 109 (VM2):
#   nohup python3 /tmp/node_poller.py 10.20.20.109 VM2 >> /tmp/node_poller.log 2>&1 &
#
# The master copy of node_poller.py is at /home/dr/naked_gun/node_poller.py
# Deploy to nodes via: scp node_poller.py dr@<node_ip>:/tmp/node_poller.py

# =============================================================================
# TESTING THE TUNNEL
# =============================================================================
#
# Once both nodes have loaded the module and configured wg0:
#
# From node 104 (VM1):
#   ping 10.0.3.2
#
# From node 109 (VM2):
#   ping 10.0.3.1
#
# Check tunnel status on either node:
#   sudo ~/wg show wg0
#
# =============================================================================
# TEARDOWN
# =============================================================================
#
# On each test node:
#   sudo ip link del wg0
#   sudo rmmod wireguard
#
# =============================================================================
# NOTES
# =============================================================================
#
# - The original vconf.bash on BOTH VMs was identical (both claiming VM1).
#   This was resolved by master assigning 104=VM1, 109=VM2.
#
# - The original peer endpoint in vconf.bash was 10.20.20.107:51820 which
#   is stale/incorrect. Corrected to use actual node IPs (.104 and .109).
#
# - Custom wg binary at ~/wg supports "transport tcp" parameter.
#
# - Module path: /home/dr/linux-source-6.8.0/drivers/net/wireguard/wireguard.ko
#
# - Source code (with all 63 warning fixes) is in the tcp branch of
#   git@github.com:jnathan/naked_gun on the master host.
#
# - Both nodes confirmed source sync: all 28 files checksummed identical,
#   module builds clean with 0 warnings on both nodes.
