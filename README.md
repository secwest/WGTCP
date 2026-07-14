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
> The brokered two-VM Ubuntu 24.04/Linux 6.8 run `wg20260714T010310Z` passed
> every recorded UDP and TCP case: **36 PASS, 0 FAIL, 0 SKIP** in 558.520
> seconds across 541 logged commands. TCP coverage included asymmetric listen
> ports, configured migration, authenticated target learning, live route,
> source-address, uplink, and `FwMark` reconnects, full-tunnel recursion
> avoidance, IPv6/dual-stack and scoped link-local carriers, live configuration
> application and SaveConfig serialization, a 40-second authenticated-carrier lifetime, and
> dual-reachable NAT44 with live source-port remapping, and isolated forced
> short-write/parser/queue-pressure recovery. That evidence
> covers the tested combinations and scenarios, not
> every kernel release, controller, NAT, or hostile stream condition. TCP mode
> remains experimental and is not a claim of complete WireGuard feature parity.
> Focused follow-up `wg20260713T225629Z` then passed a real `wg-quick` down/up
> reload and the guest-owned fault-module lifecycle on both VMs.
> See the
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
| Provisional inbound path | Accepts unknown TCP connections before identity is known with device/per-source caps, per-source throttling, and authentication deadlines; authenticated carriers are retained, but socket promotion is not implemented |
| Endpoint mobility | Keeps the configured peer listen port separate from an observed ephemeral source port, learns a future dial IP only from authenticated traffic, and reconnects after relevant endpoint, route, address, uplink, and `FwMark` changes |
| Connection collision | Uses a deterministic public-key tie-break when simultaneous TCP Noise initiations collide |
| Configuration persistence | Canonical TCP state round-trips through `showconf`, `setconf`, and `syncconf`; the tested Ubuntu `wg-quick` also serializes it through SaveConfig |
| Diagnostics | Optional TCP metrics include cwnd, RTT/RTO, retransmission state, and queue pressure; destructive stream faults exist only in a separate lab module |

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

Give both peers bidirectional inbound TCP reachability or port forwarding on
each peer's configured listen port. The ports may differ; the recorded
asymmetric-listen-port case passed. A namespace-isolated NAT44 case also passed
with a private peer behind SNAT, a stable external DNAT port for the reverse
carrier, and a configured endpoint in both directions. It recovered when the
private peer's translated source port changed from 41001 to 41002 without
replacing the configured forwarded port. This is a dual-reachable topology;
ordinary one-sided client-behind-NAT responder behavior without a reverse
port-forward still requires authenticated accepted-carrier promotion.

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

The identity rule remains WireGuard's: an authenticated public key identifies a
peer, not its address or TCP source port. An unknown inbound connection starts
in provisional state under a 128-entry device cap, an eight-entry per-source
cap, and a 32-accept-per-second source throttle. It has five-second idle and
30-second absolute pre-authentication deadlines. Once the stream carries valid
Noise traffic, it is removed from pre-authentication accounting and no longer
expires under those deadlines; the campaign retained the same authenticated
carrier tuples while carrying traffic for 40 seconds.

Authenticated TCP metadata may update the IP used for a future dial, but the
observed ephemeral source port never replaces the peer's configured listen
port. Device-monotonic accepted-connection IDs prevent an older retained
carrier from reverting a newer target, and a material authenticated address
change queues a reconnect outside receive/NAPI context. Explicit netlink
endpoint changes remain authoritative and also reconnect through the normal
cleanup/retry path. These mechanisms passed authenticated address learning,
asymmetric listen ports, source-address migration, and uplink migration in the
recorded topology.

No path atomically promotes a provisional accepted socket into the configured
peer. The current model therefore does not provide general responder-only
roaming or one-sided NAT parity; it can learn an authenticated remote IP only
when the separately configured peer listen port remains reachable.

The recorded NAT44 case exercises that reachable-listen-port model directly.
It passed SNAT, DNAT from external port 52241 to private listener 52221,
bidirectional traffic, idle persistent keepalives, and recovery after a forced
41001-to-41002 SNAT remap on both Ubuntu guests. The public peer continued to
report configured port 52241, proving that the observed NAT source port did not
contaminate future dial state. The old accepted 41001 socket remained locally
visible after the new carrier and traffic recovered, so deterministic stale
carrier retirement remains separate parity work. A live `FwMark` update then
forced the public peer to reconnect through configured forward 52241; the
router observed a new SYN and bidirectional traffic remained usable.

TCP listeners, accepted sockets, and outbound sockets use the WireGuard
device's retained creation namespace and carry its `FwMark`. Route, netdevice,
and address notifications reconnect affected established streams, and a live
`FwMark` change refreshes socket marks and reconnects. The campaign passed live
route, source-address, uplink, and mark changes, plus a full-tunnel policy test
whose unmarked endpoint lookup hit a recursion guard while marked TCP sockets
used the physical path. Independent IPv4/IPv6 TCP and companion UDP listeners
and bidirectional ULA and scoped link-local IPv6 TCP tunnel traffic also
passed. Canonical TCP configuration survived `showconf`, live `setconf`,
drift-removing `syncconf`, and `wg-quick SaveConfig` on both guests.
Focused follow-up `wg20260713T225629Z` removed and recreated `wga` in each
guest's isolated pair from the saved file, recovered bidirectional traffic, and
reproduced the exact canonical WireGuard configuration.

Important remaining TCP parity work includes:

- implementing atomic authenticated carrier-to-peer binding and promotion,
  duplicate-carrier retirement, and general responder-only/NAT ephemeral-port
  roaming;
- adding exact-stream handshake/cookie replies, TCP cookie-response
  consumption, MAC1 validation, and a staged MAC2 challenge rollout so
  pre-Noise cost defense does not break older TCP peers under load;
- validating namespace teardown/move and VRF behavior;
- completing MTU accounting, longer hostile-network soaks, and broader kernel,
  controller, topology, physical-carrier impairment, malformed-stream, and
  multi-flow coverage before claiming production or all-modes parity.

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
| Stateful firewall/NAT friendliness | Dual-reachable NAT44 with explicit reverse port-forwarding, keepalives, and one forced source-port remap passed on both guests | Ordinary one-sided NAT still needs accepted-carrier promotion; stale accepted sockets are not yet retired deterministically |
| Per-deployment choice | Separate UDP and TCP interfaces can serve different routes | Additional configuration and operational testing |

Use UDP when it works and low latency, datagram semantics, or minimal state are
the priority. Evaluate TCP where UDP is blocked or on a measured path where its
tradeoffs are acceptable. Highly multiplexed, roaming, and long-duration
production workloads should wait for the parity checklist in the design
document. Namespace-isolated IPv4/IPv6 tunnels, full-tunnel policy routing, and
live route, source, uplink, and mark reconnects passed the recorded topology;
deployment-specific firewall, connmark, namespace, and VRF policy still require
validation.

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
DESIGNLOG.md                  Chronological architectural decisions
CHANGELOG.md                  User-visible changes and validation history
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
provisions isolated outer paths, builds production, DEBUG, and isolated
fault-injection modules, and records timestamped JSON, Markdown, and per-command
logs. The latest committed
summary is in [`tests/hyperv/RESULTS.md`](tests/hyperv/RESULTS.md); run
`wg20260714T010310Z` passed all 36 cases with no failures or skips in 558.520
seconds across 541 logged commands. Its tested snapshot used HEAD
`83d424cb0191bc2b90090c071728db6348f7b983`, base archive SHA-256
`2de2c670dba76cac01dd1bd35f9de99605d36b032070048d6b94f5e6f3ec0d12`,
and overlay SHA-256
`40c4db67c0b9660f3589239ca85ac1870d40306075ce67617085a40b1a3d3e9a`.
Both Ubuntu 24.04 guests ran Linux 6.8 and passed all 107 local source contracts
during preflight. The isolated fault case forced 80 short writes, four malformed
prefixes, four successful parser resynchronizations, 437/442 drop-newest queue
rejections, and clean bidirectional recovery on each guest. Build-time
`modinfo` checks prove the `tcp_test_*` controls are absent from production and
ordinary DEBUG modules.
Focused follow-up `wg20260713T225629Z` passed the actual `wg-quick` reload and
the hardened one-shot fault case for **2 PASS, 0 FAIL, 0 SKIP** in 134.149
seconds. The exact follow-up overlay was
`efe576b3c226089de2bbbd23670c599f78a45d8ec315c896cf6c6494a9692dd7`;
all 103 source contracts and reuse-only artifact verification passed on both
guests.

Strengthened NAT44 run `wg20260714T005957Z` passed on both guests for **1 PASS,
0 FAIL, 0 SKIP** in 57.867 seconds. It verified exact nftables and conntrack
SNAT/DNAT state, bidirectional tunnel traffic, idle keepalive activity, a live
source-port remap from 41001 to 41002, and preservation of configured forwarded
port 52241. A live mark change forced a reverse reconnect and each router
counted a new SYN through that forward. Run it independently with:

```powershell
python .\tests\hyperv\regression.py --only-case tcp-nat44-dual-reachable
```

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

Deterministic destructive tests use the separately built
`wireguard-fork-fault.ko`. Its root-only `tcp_test_*` parameters are an unstable
lab interface, module-global across namespaces, and absent from production and
ordinary DEBUG artifacts. The committed runner serializes those tests, compares
counter deltas, resets every control, and verifies post-pressure traffic.

## Documentation

- [Design decision log](DESIGNLOG.md)
- [Change log](CHANGELOG.md)
- [TCP transport design, compatibility, roaming, and behavior](docs/TCP_TRANSPORT_DESIGN.md)
- [Hyper-V host and VM creation guide](tests/hyperv/HYPERV_SETUP.md)
- [Hyper-V regression results](tests/hyperv/RESULTS.md)
- [Performance campaign report](perf-test/REPORT.md)
- [Performance test plan](perf-test/TESTPLAN.md)
- [Performance runbook](perf-test/RUNBOOK.md)
- [Relay notes](docs/AGENT_RELAY.md)
- [Node setup notes](docs/NODE_README.md)
