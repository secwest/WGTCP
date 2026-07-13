# WireGuard TCP Test Node — Copilot Session Startup Guide

**READ THIS FIRST** when starting a new Copilot session on a test node (10.20.20.104 or 10.20.20.109).

## Step 0: Determine Who You Are

```bash
MY_IP=$(hostname -I | awk '{print $1}')
echo "I am $MY_IP"
```

- **10.20.20.104** → You are **VM1** (tunnel IP 10.0.3.1)
- **10.20.20.109** → You are **VM2** (tunnel IP 10.0.3.2)
- **10.20.20.102** → You are the **master** (do NOT run this guide — see AGENT_RELAY.md)

## Step 1: Start the Background Poller

The poller runs continuously and handles commands from master autonomously.

```bash
# Check if poller is already running
pgrep -af 'python3.*node_poller'

# If NOT running, start it:
MY_IP=$(hostname -I | awk '{print $1}')
ROLE=VM1  # Use VM2 if you are 10.20.20.109

nohup python3 /tmp/node_poller.py $MY_IP $ROLE >> /tmp/node_poller.log 2>&1 &
echo "Poller started PID=$!"

# Verify
sleep 3 && tail -5 /tmp/node_poller.log
```

**If /tmp/node_poller.py is missing** (e.g., after VM reboot):
```bash
# Download from master relay
curl -s http://10.20.20.102:4040/messages?for=$(hostname -I | awk '{print $1}') > /dev/null
# Or copy from the git repo if available:
cp /home/dr/naked_gun/node_poller.py /tmp/node_poller.py 2>/dev/null || \
cp ~/node_poller.py /tmp/node_poller.py 2>/dev/null
```

## Step 2: Announce to Master

```bash
MY_IP=$(hostname -I | awk '{print $1}')
ROLE=VM1  # or VM2

curl -s -X POST http://10.20.20.102:4040/message \
  -H "Content-Type: application/json" \
  -d "{\"from\":\"$MY_IP\",\"to\":\"10.20.20.102\",\"type\":\"hello\",\"body\":\"Node $MY_IP ($ROLE) online. Poller running. Ready for commands.\"}"
```

## Step 3: Build and Load Module (if needed after reboot)

```bash
# Load kernel dependencies
sudo modprobe libcurve25519-generic udp_tunnel ip6_udp_tunnel libchacha20poly1305 curve25519-x86_64

# Build module
cd /home/dr/linux-source-6.8.0/drivers/net/wireguard
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Load module
sudo insmod /home/dr/linux-source-6.8.0/drivers/net/wireguard/wireguard.ko

# Verify
lsmod | grep wireguard
```

## Step 4: Configure WireGuard Tunnel

### If you are VM1 (10.20.20.104):
```bash
sudo ip link add wg0 type wireguard
sudo ip addr add 10.0.3.1/24 dev wg0
sudo ~/wg set wg0 private-key /etc/wireguard/private.key
sudo ~/wg set wg0 listen-port 51820 transport tcp
sudo ip link set up dev wg0
sudo ~/wg set wg0 peer BPSOiEG8+Yxizx/KOIiKuGIECIWckkFolZczyaR/Mng= \
    allowed-ips 10.0.3.2/32 endpoint 10.20.20.109:51820 persistent-keepalive 25
sudo ip route add 10.0.3.2/32 dev wg0 2>/dev/null
```

### If you are VM2 (10.20.20.109):
```bash
sudo ip link add wg0 type wireguard
sudo ip addr add 10.0.3.2/24 dev wg0
sudo ~/wg set wg0 private-key /etc/wireguard/private.key
sudo ~/wg set wg0 listen-port 51820 transport tcp
sudo ip link set up dev wg0
sudo ~/wg set wg0 peer I610z8JCf9Wv24eQS/qJVSavi2M2/TRyf67l59n+Ym4= \
    allowed-ips 10.0.3.1/32 endpoint 10.20.20.104:51820 persistent-keepalive 25
sudo ip route add 10.0.3.1/32 dev wg0 2>/dev/null
```

## Step 5: Verify Tunnel

```bash
sudo ~/wg show wg0
ping -c 3 -W 3 $([ "$(hostname -I | awk '{print $1}')" = "10.20.20.104" ] && echo 10.0.3.2 || echo 10.0.3.1)
```

## Step 6: Report Status to Master

```bash
MY_IP=$(hostname -I | awk '{print $1}')
curl -s -X POST http://10.20.20.102:4040/message \
  -H "Content-Type: application/json" \
  -d "{\"from\":\"$MY_IP\",\"to\":\"10.20.20.102\",\"type\":\"status\",\"body\":\"Node $MY_IP fully operational. Module loaded, tunnel UP, poller running.\"}"
```

---

## Architecture Overview

```
Master (10.20.20.102:4040)  ← REST relay server, git repo, GitHub push
    ↕ HTTP JSON messages
VM1 (10.20.20.104)          ← builds/tests module, submits fixes
    ↕ WireGuard TCP tunnel (wg0: 10.0.3.1 ↔ 10.0.3.2)
VM2 (10.20.20.109)          ← builds/tests module, submits fixes
```

## Communication Protocol

All communication goes through the master relay at **http://10.20.20.102:4040**.

### Polling (every 10s, handled by poller):
```
GET http://10.20.20.102:4040/messages?for=<MY_IP>
→ Returns JSON array of pending messages, drains queue
```

### Sending messages:
```
POST http://10.20.20.102:4040/message
Content-Type: application/json
{"from":"<MY_IP>","to":"<TARGET_IP>","type":"<TYPE>","body":"<TEXT>"}
```

### Message types:
| Type          | Purpose                                        |
|---------------|------------------------------------------------|
| `hello`       | Announce presence after startup/restart        |
| `status`      | Report build/tunnel/test status                |
| `command`     | Instruction to execute (master → node)         |
| `result`      | Command execution result (node → master)       |
| `heartbeat`   | Periodic alive signal with stats               |
| `ack`         | Acknowledge receipt                            |
| `file_update` | File content delivery (JSON body with content) |
| `changes`     | Code submission via POST /changes              |

### Submitting code fixes to master:
```
POST http://10.20.20.102:4040/changes
Content-Type: application/json
{"files":[{"path":"socket.c","content":"<FULL FILE>"}],"message":"Description of fix"}
```

## Poller v6 Commands

The poller handles these commands from master automatically:

| Command          | Action                                         |
|------------------|-------------------------------------------------|
| `rebuild`        | Pull latest source from master, make modules   |
| `reload-tunnel`  | rmmod + insmod + full wg0 reconfigure          |
| `reload`         | Same as reload-tunnel                          |
| `ping-test`      | Ping peer through tunnel, report results       |
| `ping`           | Same as ping-test                              |
| `iperf-server`   | Start iperf3 server on tunnel IP               |
| `iperf-client`   | Run iperf3 client to peer                      |
| `status`         | Report full node status                        |
| `dmesg`          | Report recent WireGuard kernel messages        |
| `shell:<cmd>`    | Execute arbitrary shell command                |
| `exec:<cmd>`     | Same as shell                                  |

## Key Files on Each Node

| Path                          | Purpose                                    |
|-------------------------------|---------------------------------------------|
| `/tmp/node_poller.py`         | Background poller v6 (start on boot)       |
| `/tmp/node_poller.log`        | Poller log output                          |
| `/tmp/agent_status.json`      | Current node status (JSON)                 |
| `/tmp/agent_messages.jsonl`   | Message history log                        |
| `~/wg`                        | Custom wg binary (supports transport tcp)  |
| `~/vconf.bash`                | Tunnel config variables                    |
| `/home/dr/linux-source-6.8.0/drivers/net/wireguard/` | Module source |
| `/home/dr/naked_gun/`         | Git repo (tcp branch)                      |

## Troubleshooting

### Poller not running
```bash
pgrep -af node_poller  # Check if alive
tail -20 /tmp/node_poller.log  # Check logs
# Restart:
nohup python3 /tmp/node_poller.py <MY_IP> <ROLE> >> /tmp/node_poller.log 2>&1 &
```

### Module won't load
```bash
# Make sure dependencies are loaded first:
sudo modprobe libcurve25519-generic udp_tunnel ip6_udp_tunnel libchacha20poly1305 curve25519-x86_64
# Then:
sudo insmod /home/dr/linux-source-6.8.0/drivers/net/wireguard/wireguard.ko
# Check dmesg if it fails:
dmesg | tail -10
```

### Tunnel not working
```bash
sudo ~/wg show wg0  # Check handshake status
ss -tn sport = :51820 or dport = :51820  # Check TCP connections
dmesg | grep -iE 'wireguard|wg_|tcp_connect' | tail -20  # Kernel logs
```

### Clean restart of tunnel
```bash
sudo ip link del wg0 2>/dev/null
sudo rmmod wireguard 2>/dev/null
# Then redo Steps 3-4
```

### Master relay unreachable
```bash
curl -s http://10.20.20.102:4040/status  # Test connectivity
ping -c 1 10.20.20.102  # Network check
# If down, wait — master Copilot will restart it
```

## Git Info

- Repo: `git@github.com:jnathan/naked_gun`
- Branch: `tcp`
- Latest fixes: #1 listener bug, #2 temp_peer, #3 outbound connect, #4 TCP_NODELAY

## Credential Handling

Do not store passwords or private keys in this guide or in the repository.
Provision node-specific WireGuard keys at `/etc/wireguard/private.key` with
root-only permissions, and configure sudo access outside source control.
