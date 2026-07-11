# WireGuard TCP Transport

WireguardTCP adds an opt-in TCP carrier to the Linux WireGuard kernel module
while retaining its UDP transport branch. TCP mode wraps otherwise standard
WireGuard handshake, keepalive, and encrypted data messages in small framed
records carried by a long-lived per-peer TCP connection. UDP remains the
default selection, but this snapshot still has UDP-visible port and cookie
handling regressions, so stock behavioral parity remains a design target.

This repository contains source extracted from the `tcp` branch of
`github.com/jnathan/naked_gun`, cleaned into a standalone layout without the
redundant full Linux kernel tree.

Source snapshot: `jnathan/naked_gun@4211b00ef437`.

> **Status: experimental.** UDP compatibility is the design intent, but this
> snapshot is not ready for production deployment, a drop-in UDP compatibility
> claim, or a claim of complete WireGuard feature parity. The detailed design
> records the current behavior, known gaps, and closure criteria in
> [`docs/TCP_TRANSPORT_DESIGN.md`](docs/TCP_TRANSPORT_DESIGN.md).

## Design summary

| Area | Change |
|---|---|
| Transport selection | Adds interface-wide `udp` and `tcp` modes; UDP is value zero and remains the default |
| UAPI | Appends `WGDEVICE_A_TRANSPORT` to the Linux generic-netlink device attributes |
| Wire format | Adds an 8-byte TCP record header with total length, type, flags, and a framing checksum |
| Cryptography | Reuses the standard WireGuard Noise handshake, AEAD data messages, replay checks, and key rotation |
| TCP lifecycle | Adds listeners, nonblocking outbound connect, socket callbacks, per-peer read/write workers, cleanup, and retry |
| Receive integration | Reconstructs endpoint metadata and feeds decoded records into the existing WireGuard receive pipeline |
| Roaming foundation | Accepts unknown inbound TCP connections provisionally; its post-authentication peer-promotion path still requires safety fixes |
| Diagnostics | Optional TCP socket metrics include cwnd, RTT/RTO, retransmission state, and queue pressure |

The transport is selected below WireGuard's encryption layer:

```text
inner IP -> WireGuard encrypt -> UDP socket
                              -> TCP record -> per-peer TCP stream

TCP stream -> record parser -> WireGuard authenticate/decrypt -> inner IP
```

TCP framing is not an additional security layer. Its checksum only helps detect
record boundaries; WireGuard authentication remains authoritative.

## Configuration

Both endpoints require the modified Linux kernel module and modified `wg` tool.
TCP mode requires a nonzero effective listen port. This fork currently
initializes every new interface to port 51820, including UDP interfaces, instead
of preserving stock WireGuard's random-port behavior. Configure `ListenPort`
explicitly so that the deployment does not depend on that compatibility
difference.

For the current static topology, give both peers bidirectional inbound TCP
reachability or port forwarding on their matching configured ports. The
handshake path can attempt a reverse TCP connection, so ordinary one-sided
client-behind-NAT responder behavior is not yet established.

```ini
[Interface]
PrivateKey = <private-key>
ListenPort = 51821
Transport = tcp

[Peer]
PublicKey = <peer-public-key>
AllowedIPs = 10.0.0.2/32
Endpoint = peer.example.net:51821
PersistentKeepalive = 25
```

The direct command form is:

```bash
wg set wg0 listen-port 51821 transport tcp
```

Configure the mode while the interface is down, then bring the interface up.
Live UDP/TCP switching does not yet rebuild all listener and peer state safely.
Apply transport changes as a separate `wg set` operation without repeating the
private key, then verify the resulting mode; the current netlink SET path can
skip a transport change when an unchanged private key is included.

The modified Linux IPC tool also prints raw netlink diagnostics
unconditionally. Those messages can contain keys and corrupt machine-readable
`wg` output, so do not use production keys or depend on `wg-quick` automation
until the prints are removed.

### Compatibility model

- Omitting `Transport` preserves stock-style configuration and selects UDP on a
  new interface.
- `Transport = udp` explicitly selects the retained UDP send branch.
- `Transport = tcp` requires this implementation at both ends.
- There is no on-wire negotiation or automatic TCP-to-UDP fallback.
- Transport is device-wide. Use separate WireGuard interfaces for TCP and UDP
  peers or for an operational fallback path.
- Existing `Endpoint`, `AllowedIPs`, keys, preshared keys, and
  `PersistentKeepalive` syntax is unchanged.
- New interfaces currently default to port 51820 rather than stock WireGuard's
  random listen port; this is a known UDP compatibility regression.
- UDP-mode handshake cookie behavior under load also differs from stock in this
  snapshot; default selection is not yet evidence of drop-in behavioral parity.
- TCP mode is implemented only by the Linux kernel/generic-netlink backend in
  this snapshot; do not assume cross-platform or wireguard-go support.

The current `wg showconf` writes `TransportMode` while the parser accepts
`Transport`. Until that is fixed, do not rely on `wg-quick SaveConfig` for TCP
interfaces.

## Roaming and WireGuard parity

The intended identity rule is the same as WireGuard's: an authenticated public
key identifies a peer, not its IP address or TCP source port. The listener can
hold an unknown inbound connection in provisional state and process its normal
WireGuard handshake. The code contains an intended promotion path after Noise
identifies the peer, but its current ownership and RCU handling are unsafe and
must be fixed before responder-only roaming is relied upon. Authenticated
handshakes and data retain the existing endpoint-learning hooks.

The per-peer TCP foundation supports operation with static configured
endpoints and provides a basis for roaming, but responder-only identity
promotion and full roaming parity are still in progress. Important remaining
work includes:

- updating future reconnect targets after an authenticated address change;
- separating a peer's configured listen port from an observed ephemeral TCP
  source port;
- supporting asymmetric listen ports and `ListenPort = 0`;
- reacting to local route, address, and uplink changes;
- preserving `FwMark`, full-tunnel policy routing, and network-namespace
  semantics for outer TCP sockets;
- deterministic handling of simultaneous inbound and outbound connections;
- robust dual-stack listeners and IPv6 validation;
- bounded provisional connections, queues, record lengths, and handshake time;
- correcting current promotion, partial-write, and configuration round-trip
  issues before hostile-network use.

The full roaming state model and acceptance checklist are in the
[design document](docs/TCP_TRANSPORT_DESIGN.md#roaming-and-endpoint-mobility).

## Benefits analysis

TCP mode is a deployment option, not a universal replacement for UDP.

| Potential benefit | Where it helps | Tradeoff |
|---|---|---|
| Reachability on UDP-blocked paths | Networks that allow raw TCP to the selected port | The stream is not HTTP/TLS camouflage and can still be blocked |
| Reuse of WireGuard security model | Same peer keys, Noise sessions, AllowedIPs, replay checks, keepalives, and rekey | Both endpoints need the modified Linux implementation |
| Outer reliable delivery | Non-congestive loss where completeness matters more than timeliness | Ordered recovery can create latency and head-of-line blocking |
| Reliable carriage of inner UDP | Bulk or transactional datagrams | Late packets may be worse than loss for voice, gaming, or real-time video |
| Stateful firewall/NAT friendliness | Potentially useful on TCP-friendly policy paths | Current reverse-dial behavior needs bidirectional reachability; ordinary one-sided NAT operation is unvalidated |
| Per-deployment choice | Separate UDP and TCP interfaces can serve different routes | Additional configuration and operational testing |

Use UDP when it works and low latency, datagram semantics, or minimal state are
the priority. Evaluate TCP where UDP is blocked or on a measured path where its
tradeoffs are acceptable. Highly multiplexed, roaming, full-tunnel, and
long-duration production workloads should wait for the parity checklist in the
design document.

## Performance and TCP-over-TCP behavior

The repository includes an empirical application-level Azure campaign comparing
TCP-WG and UDP-WG across x64/arm64, four latency tiers, and configured loss
values from 0% to 20%. These are synthetic two-vCPU VM tests: bulk TCP uses four
parallel streams, bulk UDP is capped at 1 Gbps, and injected loss is iid random.
Its published tables contain striking results. Examples include:

- LAN x64 bulk TCP: 2789.4 Mbps over TCP-WG versus 2588.2 Mbps over UDP-WG on
  the clean cell.
- The same published 10% cell: 2751.2 Mbps over TCP-WG versus 28.8 Mbps over
  UDP-WG.
- LAN x64 short HTTPS at the published 10% cell: 154.54 requests/s over TCP-WG
  versus 6.01 over UDP-WG.
- Clean high-latency x64 bulk TCP also shows the cost side: TCP-WG is 14% behind
  UDP-WG at the report's HIGH tier and 23% behind at MAX.

The surprising result is that no classic nested-TCP throughput collapse is
visible in the published application tables, including the 60-second bulk
runs. Across these real application workloads in Azure, merely nesting TCP
inside the long-lived TCP carrier did not automatically produce collapse. That
suggests a useful working hypothesis: severe TCP-over-TCP meltdown may be a
narrower, condition-dependent failure mode than initially expected from common
worst-case warnings. The campaign does not yet identify those boundary
conditions, so this is **not proof of general TCP-over-TCP meltdown
resilience**.

The executable harness applies `netem` to `wg-tcp0` or `wg-udp0` for tunneled
runs, not demonstrably to the physical outer carrier. It therefore does not
exercise outer TCP segment loss in the way required to validate retransmission,
congestion-window recovery, or nested timer interaction. The stored data also
lacks sufficient qdisc and outer retransmission evidence for a causal claim.
Impairment is installed only on the client VM/interface, so the data and ACK
directions were not symmetrically impaired either.

The report records a contrary stability event as well: a prolonged arm64,
high-latency, configured 10-20% loss test wedged the VM network stack until a
hard reboot. A later 360-second cap avoided the condition but did not establish
a root-cause fix.

The defensible conclusion is that the prototype produced unexpectedly strong
published application results and makes the narrower-condition hypothesis worth
testing directly. Establishing where meltdown begins still requires
outer-interface random/burst loss, congestion and finite queues, reorder, many
inner flows, TCP_INFO/retransmission capture, roaming, blackouts, and multi-hour
soak tests.

See [`perf-test/REPORT.md`](perf-test/REPORT.md) for the published tables and
[`docs/TCP_TRANSPORT_DESIGN.md`](docs/TCP_TRANSPORT_DESIGN.md#performance-evidence)
for the methodology audit and required follow-up campaign.

## Repository structure

```text
kernel/                       WireGuard kernel module with TCP transport
tools/                        Modified WireGuard userland tools
include/uapi/                 Additive Linux transport UAPI
docs/TCP_TRANSPORT_DESIGN.md  Detailed architecture and parity design
docs/                         Relay and tunnel setup notes from the source branch
perf-test/                    Performance plan, harness, reports, and matrices
BIG-WireguardTCP-Patch        Combined patch from historical stock WireGuard
```

## Building

### Kernel module

```bash
cd kernel
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

### Userland tools

```bash
cd tools
make
```

The module and tool builds deliberately use the repository's local transport
UAPI. Installing only one side is insufficient for TCP configuration.

## Diagnostics

Optional kernel diagnostic builds are available:

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules \
  EXTRA_CFLAGS='-DWG_TCP_DIAG'

make -C /lib/modules/$(uname -r)/build M=$(pwd) modules \
  EXTRA_CFLAGS='-DWG_TCP_VERBOSE'
```

`WG_TCP_DIAG` emits unrate-limited, per-packet TCP state such as cwnd, RTT/RTO,
retransmissions, and queue pressure, so enabling it can perturb a benchmark.
`WG_TCP_VERBOSE` can print packet and sensitive cryptographic material and is
for isolated lab debugging only. The current modified Linux IPC tooling also
contains unconditional diagnostic output around netlink messages; do not use
production keys or machine-readable tool output until that code is removed.

## Documentation

- [TCP transport design, compatibility, roaming, and resilience](docs/TCP_TRANSPORT_DESIGN.md)
- [Performance campaign report](perf-test/REPORT.md)
- [Performance test plan](perf-test/TESTPLAN.md)
- [Performance runbook](perf-test/RUNBOOK.md)
- [Relay notes](docs/AGENT_RELAY.md)
- [Node setup notes](docs/NODE_README.md)
