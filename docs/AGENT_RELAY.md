# WireGuard TCP — Inter-Agent Relay Setup

## Overview

This project uses a 3-node test environment for developing and testing the WireGuard TCP kernel module. A central **relay server** on the master host coordinates communication between all nodes using a simple JSON-over-HTTP protocol.

### Nodes

| Role       | IP Address     | Description                                      |
|------------|----------------|--------------------------------------------------|
| **Master** | 10.20.20.102   | Development host. Runs relay server, holds git repo. |
| **Node 1** | 10.20.20.104   | Test VM. Builds module, fixes compiler warnings. |
| **Node 2** | 10.20.20.109   | Test VM. Builds module, runs TCP tunnel tests.   |

All three nodes may be running Copilot agents that communicate through the relay.

---

## Starting the Relay Server

On the master host (10.20.20.102):

```bash
python3 /tmp/agent_http_server.py &
```

This starts an HTTP server on **port 4040** accepting connections from all nodes.

The server script should be at `/tmp/agent_http_server.py`. If it's missing, recreate it from the copy kept in this repo:

```bash
cp /home/dr/naked_gun/relay_server.py /tmp/agent_http_server.py
python3 /tmp/agent_http_server.py &
```

---

## Protocol Specification (v2.0)

All communication is **JSON over HTTP on port 4040**.

### Endpoints

| Method | Path                    | Description                                  |
|--------|-------------------------|----------------------------------------------|
| GET    | `/protocol`             | Returns full protocol description as JSON    |
| GET    | `/status`               | Relay status: nodes, queued messages, totals |
| GET    | `/messages?for=<ip>`    | Poll for pending messages addressed to `<ip>` |
| POST   | `/message`              | Send a message to a specific node            |
| POST   | `/broadcast`            | Send a message to all other nodes            |
| POST   | `/changes`              | Submit source code file changes              |

### Message Format (POST /message)

```json
{
  "from": "10.20.20.104",
  "to":   "10.20.20.109",
  "type": "patch",
  "body": "Human-readable description or content"
}
```

- **`from`** — sender IP (required)
- **`to`** — recipient IP (optional; omit to just log, or use `/broadcast`)
- **`type`** — one of the types below
- **`body`** — message content (string)

### Message Types

| Type        | Purpose                                                |
|-------------|--------------------------------------------------------|
| `hello`     | Initial handshake / presence announcement              |
| `ack`       | Acknowledge receipt of a previous message              |
| `patch`     | Unified diff to apply to WireGuard source              |
| `changes`   | Notification that files were submitted via `/changes`  |
| `status`    | Build/tunnel/test status update                        |
| `request`   | Ask for information (peer pubkey, source version, etc) |
| `command`   | Instruction from master to a test node                 |
| `broadcast` | General announcement to all nodes                      |

### Submitting Code Changes (POST /changes)

```json
{
  "files": [
    {
      "path": "drivers/net/wireguard/socket.c",
      "content": "... full file content ..."
    }
  ],
  "message": "Fix 63 compiler warnings in TCP socket code"
}
```

Files are saved to `/tmp/agent_inbox/<session_id>/` and the master is notified.

### Polling for Messages (GET /messages?for=<ip>)

Each node should periodically poll for messages addressed to it:

```bash
curl -s http://10.20.20.102:4040/messages?for=10.20.20.109
```

Returns a JSON array of pending messages (drains the queue).

---

## Test Node Setup Instructions

Each test node Copilot agent should, on startup:

### 1. Announce Presence

```bash
curl -s -X POST http://10.20.20.102:4040/message \
  -H "Content-Type: application/json" \
  -d '{
    "from": "<MY_IP>",
    "to": "10.20.20.102",
    "type": "hello",
    "body": "Node <MY_IP> online. Ready for instructions."
  }'
```

### 2. Poll for Messages (loop)

```bash
while true; do
  curl -s http://10.20.20.102:4040/messages?for=<MY_IP>
  sleep 10
done
```

Or in the agent's workflow, poll between tasks.

### 3. Send Status Updates

```bash
curl -s -X POST http://10.20.20.102:4040/message \
  -H "Content-Type: application/json" \
  -d '{
    "from": "<MY_IP>",
    "to": "10.20.20.102",
    "type": "status",
    "body": "Module built successfully. Loading wireguard.ko..."
  }'
```

### 4. Submit Fixed Source Files

```bash
curl -s -X POST http://10.20.20.102:4040/changes \
  -H "Content-Type: application/json" \
  -d '{
    "files": [{"path": "drivers/net/wireguard/send.c", "content": "..."}],
    "message": "Fixed warnings in send.c"
  }'
```

---

## Workflow

1. **Master** starts relay server on port 4040
2. **Test nodes** send `hello` messages to announce themselves
3. **Node 104** fixes code, submits via `POST /changes`
4. **Master** reviews changes, commits to `tcp` branch on GitHub
5. **Master** relays changes to **Node 109** via queued messages
6. **Node 109** applies changes, rebuilds `wireguard.ko`, tests TCP tunnel
7. All nodes report **status** throughout the process

---

## File Locations

| Path                              | Description                          |
|-----------------------------------|--------------------------------------|
| `/tmp/agent_http_server.py`       | Running relay server script          |
| `/home/dr/naked_gun/relay_server.py` | Checked-in copy of relay server   |
| `/tmp/agent_inbox/`              | Received messages and file changes   |
| `/tmp/agent_server.log`          | Relay server log                     |
| `/home/dr/naked_gun/wireguard-linux/` | WireGuard Linux kernel module source |
| `/home/dr/naked_gun/wireguard-tools/` | WireGuard userspace tools         |
| `/home/dr/naked_gun/allcode/`    | Flat copy of WireGuard module source |

---

## Node Capabilities (Confirmed)

| Node         | Listening Port | Capabilities                                              |
|--------------|---------------|-----------------------------------------------------------|
| 10.20.20.102 | 4040          | Master relay, git repo, GitHub push, code review          |
| 10.20.20.104 | 4040          | Source relay, module build, compiler warning fixes         |
| 10.20.20.109 | 4041          | Module build, tunnel testing, polling relay at 10.20.20.102 |

**Note:** Nodes 104 and 109 also run their own local HTTP listeners for direct peer-to-peer
communication. However, all coordination should go through the master relay at 10.20.20.102:4040
to maintain a single source of truth.

---

## Protocol Convergence Status

**All three nodes have confirmed Protocol v2.0 (2026-03-09).**

- 10.20.20.104: `ack` — "Protocol v2.0 accepted. Polling every 10s. Already submitted 4 changed files."
- 10.20.20.109: `ack` — "Protocol v2.0 accepted. Polling every 10s. Pulling fixed source files from peer."
- 10.20.20.102: Master relay running, all messages routed successfully.

---

## Quick Restart Checklist — Master (10.20.20.102)

```bash
# 1. Start relay server
cp /home/dr/naked_gun/relay_server.py /tmp/agent_http_server.py
nohup python3 /tmp/agent_http_server.py >> /tmp/agent_server.log 2>&1 &

# 2. Verify it's running
curl -s http://localhost:4040/status | jq .

# 3. Broadcast hello to re-establish comms with test nodes
curl -s -X POST http://localhost:4040/broadcast \
  -H "Content-Type: application/json" \
  -d '{"from":"10.20.20.102","type":"hello","body":"Master relay restarted. Resume polling GET /messages?for=<your_ip> on 10.20.20.102:4040. Protocol v2.0 in effect — see AGENT_RELAY.md."}'

# 4. Check that nodes reconnect
curl -s http://localhost:4040/status | jq .

# 5. Drain master inbox to see what nodes have sent
curl -s http://localhost:4040/messages?for=10.20.20.102 | jq .
```

## Quick Restart Checklist — Test Node (104 or 109)

When a test node VM reboots or a new Copilot session starts, run these steps:

```bash
# 1. Determine which node you are
MY_IP=$(hostname -I | awk '{print $1}')
# If 10.20.20.104 -> role=VM1; if 10.20.20.109 -> role=VM2
if [ "$MY_IP" = "10.20.20.104" ]; then ROLE=VM1; else ROLE=VM2; fi

# 2. Copy the background poller from the repo (or /tmp if already there)
# The master keeps the latest version at /home/dr/naked_gun/node_poller.py
# On the node it should be at /tmp/node_poller.py
# If missing, download from master:
curl -s http://10.20.20.102:4040/status > /dev/null && echo "Master relay reachable"

# 3. Start the background poller (v5 — executes commands from master)
nohup python3 /tmp/node_poller.py $MY_IP $ROLE >> /tmp/node_poller.log 2>&1 &
echo "Poller started PID=$!"

# 4. Verify poller is running
sleep 5 && tail -5 /tmp/node_poller.log

# 5. Send hello to master
curl -s -X POST http://10.20.20.102:4040/message \
  -H "Content-Type: application/json" \
  -d "{\"from\":\"$MY_IP\",\"to\":\"10.20.20.102\",\"type\":\"hello\",\"body\":\"Node $MY_IP ($ROLE) restarted. Poller v5 running. Ready for commands.\"}"

# 6. Rebuild the module (if needed after reboot)
cd /home/dr/linux-source-6.8.0/drivers/net/wireguard
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# 7. Set up tunnel — see TUNNEL_CONFIG.sh for full commands
```

### Background Poller (node_poller.py v5)

The poller runs continuously on each test node and:
- Polls master relay every 10s for pending messages
- **Executes shell commands** sent by master (type="command") — no permission prompts
- Sends command output back to master as type="cmd_result"
- Sends heartbeat every 2 minutes with cycle count, commands run, and error count
- Logs to /tmp/node_poller.log, status to /tmp/agent_status.json

The master can send commands like:
```json
{"from":"10.20.20.102","to":"10.20.20.109","type":"command","body":"echo STATUS OK"}
{"from":"10.20.20.102","to":"10.20.20.109","type":"command","body":"dmesg | tail -20"}
{"from":"10.20.20.102","to":"10.20.20.109","type":"command","body":"sudo ~/wg show wg0"}
```

## Sudo Password

The sudo password for user `dr` on the master host is needed for package installs (e.g., jq).
It has been confirmed working for apt-get operations.
