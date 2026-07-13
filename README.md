# WireGuard TCP Transport

WireguardTCP adds an opt-in TCP carrier to the Linux WireGuard kernel module
while retaining its UDP transport branch. TCP mode wraps otherwise standard
WireGuard handshake, keepalive, and encrypted data messages in small framed
records carried by a long-lived per-peer TCP connection. UDP remains the
default selection and preserves stock random-port binding, handshake-cookie
protection, endpoint learning, and script-facing tool output.

This repository contains source extracted from the `tcp` branch of
`github.com/jnathan/naked_gun`, cleaned into a standalone layout without the
redundant full Linux kernel tree.

Source snapshot: `jnathan/naked_gun@4211b00ef437`.

> **Status: experimental for TCP.** UDP is the drop-in-compatible Linux path;
> omitting `Transport` retains the stock-facing UDP behavior described below.
> The brokered two-VM Ubuntu 24.04 run `wg20260712T212739Z` passed all 16
> stock/fork kernel/tool UDP combinations, every focused UDP case, and all three
> TCP cases: **26 PASS, 0 FAIL, 0 SKIP** overall in 208.713 seconds and 433
> logged commands. That evidence covers the tested combinations and TCP
> scenarios, not every kernel release, third-party controller, or hostile stream
> condition. TCP mode is not ready for production deployment or a claim of
> complete WireGuard feature parity. See the
> [regression results](tests/hyperv/RESULTS.md) and the detailed
> [design document](docs/TCP_TRANSPORT_DESIGN.md).

## Design summary

| Area | Change |
|---|---|
| Transport selection | Adds interface-wide `udp` and `tcp` modes; UDP is value zero and remains the default |
| UAPI | Appends `WGDEVICE_A_TRANSPORT` to the Linux generic-netlink device attributes |
| Wire format | Adds an 8-byte TCP record header with total length, type, flags, and a framing checksum |
| Cryptography | Reuses the standard WireGuard Noise handshake, AEAD data messages, replay checks, and key rotation |
| TCP lifecycle | Adds listeners, nonblocking outbound connect, socket callbacks, per-peer read/write workers, cleanup, and retry |
| Receive integration | Reconstructs endpoint metadata and feeds decoded records into the existing WireGuard receive pipeline |
| Provisional inbound path | Accepts unknown TCP connections before identity is known with a device cap and authentication deadlines; socket promotion is structurally disabled, so responder-only roaming is unsupported |
| Diagnostics | Optional TCP socket metrics include cwnd, RTT/RTO, retransmission state, and queue pressure |

The transport is selected below WireGuard's encryption layer:

```text
inner IP -> WireGuard encrypt -> UDP socket
                              -> TCP record -> per-peer TCP stream

TCP stream -> record parser -> WireGuard authenticate/decrypt -> inner IP
```

TCP framing is not an additional security layer. Its checksum only helps detect
record boundaries; WireGuard authentication remains authoritative.

TCP records are built once as contiguous header, optional fragment metadata,
and WireGuard payload. A single write worker advances the same byte sequence
across nonblocking short writes, so it cannot insert a second header or resend
an emitted prefix. The receiver rejects unknown types/flags and lengths outside
the WireGuard message minimum and `WG_MAX_PACKET_SIZE` before resizing. Send
queues are capped at 1024 frames per peer and reject the newest frame under
pressure, preserving any partially emitted stream head.

## Configuration

TCP mode requires the modified Linux kernel module and modified `wg` tool at both
endpoints. In either mode, an omitted or zero `ListenPort` selects a random port
when the interface comes up. For TCP, the companion UDP socket selects the
concrete port first and the TCP listener binds the same number; configure the
peer endpoint with that selected port.

For the current static topology, give both peers bidirectional inbound TCP
reachability or port forwarding on their matching configured ports. The
handshake path can attempt a reverse TCP connection, so ordinary one-sided
client-behind-NAT responder behavior is not yet established.

TCP mode currently binds a TCP listener and the normal WireGuard UDP sockets on
the same numeric `ListenPort`. A TCP-only deployment must block that UDP port at
the firewall. On a TCP-mode interface, handshakes received through either
carrier bypass the inexpensive MAC1/cookie screen and proceed to Noise
processing. Noise authentication remains authoritative: this is additional
pre-authentication CPU/resource denial-of-service exposure, not an
authentication bypass.

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
Live UDP/TCP mode changes are rejected while the interface is running. A TCP
listen-port change also requires the interface to be down; a rejected live
change returns `EBUSY` without disturbing the active listeners. With existing
peers, remove them first or apply a link-down replacement configuration so the
carrier cannot change underneath live sockets.

The regression mode guard verifies that behavior directly: it attempts a live
TCP listen-port update, observes `EBUSY`, and confirms both listeners remain.
It then takes the link down, requests port zero, brings it back up, and confirms
that TCP and its companion UDP socket use the same newly selected random port.

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
- UDP retains random-port selection, authenticated endpoint ports and roaming
  updates, under-load cookie challenges, and the stock `wg show`/`dump` shape.
- UDP retains stock IPv4/IPv6 self-route rejection with `-ELOOP`, preventing an
  outer packet from being recursively sent through its own WireGuard device.
  Sending without a configured endpoint retains the stock `-EAFNOSUPPORT`
  result.
- Official stock `wg` ignores the appended transport attribute and can control a
  UDP interface on the modified kernel. The modified tool treats explicit UDP
  as a no-op on a stock kernel and rejects TCP as unsupported.
- TCP mode is implemented only by the Linux kernel/generic-netlink backend in
  this snapshot; do not assume cross-platform or wireguard-go support.

`wg showconf` emits the canonical `Transport = tcp` key. The parser also accepts
the historical `TransportMode` spelling so configurations produced by earlier
snapshots can be recovered.

## Roaming and WireGuard parity

The intended identity rule is the same as WireGuard's: an authenticated public
key identifies a peer, not its IP address or TCP source port. The listener can
hold an unknown inbound connection in provisional state and process its normal
WireGuard handshake. Provisional entries are capped at 128 per device, expire
after five seconds without activity, and have a 30-second absolute
pre-authentication lifetime. The receive path does not contain socket-transfer
or list-destruction ownership: TCP activity can refresh only a socket already
owned by the authenticated peer, and UDP alone uses the stock endpoint-learning
hook during handshake receive. Automatic socket promotion has not been
designed, so responder-only and automatic TCP roaming remain unsupported.

The dated Hyper-V campaign passed static IPv4 TCP connectivity, stock-tool
management, and operator-configured migration to a second underlay. The
migration case changed both configured endpoints, disabled the original path,
cycled both WireGuard interfaces down and up, and recovered bidirectional
traffic on the replacement path. Explicit netlink configuration replaces the
TCP `peer_endpoint` dial target and shuts down an active outbound stream so its
normal retry path can reconnect; authenticated endpoint learning from received
packets does not rewrite that configured target. This validates the tested
configured migration and interface-restart sequence, not responder-only
promotion or automatic authenticated TCP roaming.

TCP listeners and outbound sockets are created in the WireGuard device's
retained creation namespace. New and reconnected outbound streams use
route-selected source addressing there and inherit the device `FwMark`. The
namespace-only runtime test passes; changing `FwMark`, routes, or addresses
does not yet force an already-established TCP stream to reconnect.

Important remaining TCP parity work includes:

- updating future reconnect targets after an authenticated address change;
- separating a peer's configured listen port from an observed ephemeral TCP
  source port;
- validating asymmetric listen ports beyond the tested matching-port topology;
- reacting to local route, address, and uplink changes;
- validating full-tunnel policy routing and reconnecting an established stream
  after a live `FwMark`, route, or source-address change;
- deterministic handling of simultaneous inbound and outbound connections;
- runtime IPv6 and dual-stack validation for the independent listeners;
- per-source accept throttling and a cookie-equivalent pre-authentication cost
  defense;
- designing authenticated socket promotion and dial-target updates for roaming;
- stress-testing short writes, parser resynchronization, queue pressure, and
  configuration round trips before hostile-network use.

The full roaming state model and acceptance checklist are in the
[design document](docs/TCP_TRANSPORT_DESIGN.md#roaming-and-endpoint-mobility).

## Benefits analysis

TCP mode is a deployment option, not a universal replacement for UDP.

| Potential benefit | Where it helps | Tradeoff |
|---|---|---|
| Reachability on UDP-blocked paths | Networks that allow raw TCP to the selected port | The stream is not HTTP/TLS camouflage and can still be blocked |
| Reuse of WireGuard security model | Same peer keys, Noise sessions, AllowedIPs, replay checks, keepalives, and rekey | Both endpoints need the modified Linux implementation |
| Potential outer-loss recovery | Non-congestive loss where completeness matters more than timeliness | Ordered recovery can create latency and head-of-line blocking; the published campaign did not validate physical-carrier loss |
| Reliable carriage of inner UDP | Bulk or transactional datagrams | Late packets may be worse than loss for voice, gaming, or real-time video |
| Stateful firewall/NAT friendliness | Potentially useful on TCP-friendly policy paths | Current reverse-dial behavior needs bidirectional reachability; ordinary one-sided NAT operation is unvalidated |
| Per-deployment choice | Separate UDP and TCP interfaces can serve different routes | Additional configuration and operational testing |

Use UDP when it works and low latency, datagram semantics, or minimal state are
the priority. Evaluate TCP where UDP is blocked or on a measured path where its
tradeoffs are acceptable. Highly multiplexed, roaming, and long-duration
production workloads should wait for the parity checklist in the design
document. Namespace isolation now has an IPv4 runtime test; full-tunnel policy
routing and live routing changes still require deployment-specific validation.

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

No classic nested-TCP throughput collapse is visible in the published
application tables, including the 60-second bulk runs. These real-world
application tests support a working hypothesis: severe TCP-over-TCP meltdown
may be a narrower, path- and workload-dependent condition than broad warnings
first suggest. The campaign did not impair or instrument the physical outer TCP
carrier, so it neither demonstrates general meltdown resilience nor identifies
the boundary conditions.

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

### Compatibility tests

The source-level contract test runs anywhere with Python:

```bash
python -m unittest tests/test_udp_compat_contract.py -v
```

On a Linux kernel build host, build the module and tool, load the module, then
run the root-only network-namespace smoke test:

```bash
sudo env WG_FORK="$PWD/tools/wg" WG_STOCK=/usr/bin/wg \
  bash ./tests/udp-compat-netns.sh
```

It verifies random ports, two simultaneous UDP interfaces, stock grammar and
tool output, stock-tool control, bidirectional UDP traffic, absence of a TCP
listener in UDP mode, and a TCP tunnel whose underlay exists only inside the
two device creation namespaces.

For the full stock/fork cross-host matrix, use the repeatable two-VM Ubuntu
24.04 Hyper-V lab. The complete creation and recovery record is in
[`tests/hyperv/HYPERV_SETUP.md`](tests/hyperv/HYPERV_SETUP.md), with the shorter
operating guide in [`tests/hyperv/README.md`](tests/hyperv/README.md). The lab
provisions isolated outer paths, builds production and DEBUG modules, and
records timestamped JSON, Markdown, and per-command logs. The latest committed
summary is in [`tests/hyperv/RESULTS.md`](tests/hyperv/RESULTS.md); run
`wg20260712T212739Z` passed all 26 cases with no failures or skips in 208.713
seconds across 433 logged commands. Its tested source snapshot used base commit
`35c9110cac0f10a6f6481d5d25d8cc6d5989918a` and provisioned overlay SHA-256
`e19ba9759f2636849290a2773b2c5f764cd974437d94d745e837a69ee26e151c`.
Source-contract checks cover framing and lifecycle invariants, but this campaign
did not inject malformed streams or force short writes and queue exhaustion
under hostile network pressure.

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
for isolated lab debugging only. The userspace tool no longer contains raw
netlink payload dumps, and its debug trace macro is disabled so normal and
machine-readable output retain stock behavior.

## Documentation

- [TCP transport design, compatibility, roaming, and behavior](docs/TCP_TRANSPORT_DESIGN.md)
- [Hyper-V host and VM creation guide](tests/hyperv/HYPERV_SETUP.md)
- [Hyper-V regression results](tests/hyperv/RESULTS.md)
- [Performance campaign report](perf-test/REPORT.md)
- [Performance test plan](perf-test/TESTPLAN.md)
- [Performance runbook](perf-test/RUNBOOK.md)
- [Relay notes](docs/AGENT_RELAY.md)
- [Node setup notes](docs/NODE_README.md)
