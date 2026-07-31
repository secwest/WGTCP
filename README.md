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

## Start here

WireguardTCP is useful when two Linux endpoints need WireGuard security but
their network blocks or operationally restricts UDP. It keeps the normal
WireGuard key, peer, `AllowedIPs`, and encryption model, then carries encrypted
messages in framed TCP streams. Operators select TCP per interface with
`Transport = tcp`; there is no automatic negotiation or fallback.

The main benefit is TCP reachability while retaining familiar WireGuard
administration. The tradeoffs are connection state, head-of-line blocking, and
an experimental TCP roaming/NAT implementation. It is not HTTP or TLS
camouflage, and stock WireGuard UDP remains the preferred mode when it is
available.

New users should follow the
**[WireGuard TCP QuickStart](QUICKSTART.md)** to install the module and
tool, configure a verified two-host tunnel, and adapt the advanced
site-to-site, asymmetric-port, dual-stack, and NAT templates.

Ubuntu 24.04 users running the exact `6.8.0-136-generic` kernel can install
without compiling:

- [amd64 binary archive](docs/downloads/WireguardTCP-ubuntu-24.04-amd64-6.8.0-136-generic.tar.gz)
- [arm64 binary archive](docs/downloads/WireguardTCP-ubuntu-24.04-arm64-6.8.0-136-generic.tar.gz)
- [SHA-256 checksums](docs/downloads/SHA256SUMS.txt)

The archives include the modified `wg` tool, production kernel module, guarded
installer, and complete compiled source tree. The installer rejects a different
Ubuntu release, architecture, or running kernel rather than loading an
incompatible module. See the [binary-install instructions](QUICKSTART.md#install-without-compiling-on-ubuntu-2404)
for Secure Boot and installation requirements.

> **Status: experimental for TCP.** UDP is the drop-in-compatible Linux path;
> omitting `Transport` retains the stock-facing UDP behavior described below.
> The merged source passes **221 local tests plus 16 subtests**. Production,
> DEBUG, and isolated fault modules built on both Ubuntu 24.04 Linux guests.
> Definitive Linux run `wg20260731T130556Z` exercised the complete UDP/TCP,
> stock/fork, policy, IPv4/IPv6, NAT, roaming, recovery, configuration, and
> hostile-stream matrix with **40 PASS, 0 FAIL, 0 SKIP** in 955.098 seconds and
> clean kernel-log checks. These results cover the tested
> Linux/nftables topologies, not every kernel, controller, NAT, or middlebox.
> See the
> [regression results](tests/hyperv/RESULTS.md) and the detailed
> [design document](docs/TCP_TRANSPORT_DESIGN.md). Investigation decisions and
> repository changes are tracked in the [design log](docs/DESIGN_LOG.md) and
> [changelog](CHANGELOG.md).

## Design summary

| Area | Change |
|---|---|
| Transport selection | Adds interface-wide `udp` and `tcp` modes; UDP is value zero and remains the default |
| UAPI | Appends `WGDEVICE_A_TRANSPORT` to the Linux generic-netlink device attributes |
| Wire format | Adds an 8-byte TCP record header with total length, type, flags, and a framing checksum |
| Cryptography | Reuses the standard WireGuard Noise handshake, AEAD data messages, replay checks, and key rotation |
| TCP lifecycle | Adds listeners, nonblocking outbound connect, process-context authenticated bootstrap/promotion, per-peer read/write workers, exact callback-owner tokens, exact-socket terminal-I/O cleanup, and single-owner retry |
| Receive integration | Reconstructs endpoint metadata and feeds decoded records into the existing WireGuard receive pipeline |
| Provisional inbound path | Accepts unknown TCP connections under device/per-source caps, throttling, and authentication deadlines; authenticated traffic promotes the exact accepted carrier to its configured peer |
| Endpoint mobility | Keeps the configured peer listen port separate from an observed ephemeral source port, learns a future dial IP only from authenticated traffic, and reconnects after relevant endpoint, route, address, uplink, and `FwMark` changes |
| Connection collision | Either authenticated direction may be retained when both peers are reachable; duplicate and older-generation carriers cannot displace the current authenticated owner |
| Configuration persistence | Canonical TCP state round-trips through `showconf`, `setconf`, and `syncconf`; the tested Ubuntu `wg-quick` also serializes it through SaveConfig |
| Diagnostics | Optional TCP metrics include cwnd, RTT/RTO, retransmission state, and queue pressure; destructive stream faults, including an exact IPv4 4-tuple one-shot send failure, exist only in a separate lab module |

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

### Callback and terminal-I/O recovery

TCP socket callbacks hold the socket callback lock for reading while they load
and use `sk_user_data`, queue peer work, and invoke the saved callback. A
per-peer mutex serializes exact socket publication, callback setup/reset, and
release. Each direction retains its own owner token; setup installs the wrapper
and callbacks before publishing `callbacks_set`, while reset checks that flag
before interpreting `sk_user_data`, restores the saved callbacks from the owner
token, detaches only its own wrapper, and clears ownership last. A setup failure
therefore cannot make cleanup free foreign socket data. Every published wrapper
also owns a module reference acquired before callback publication and released
only after successful callback restoration and detachment.

Inbound and outbound removal work also records the exact socket it claimed. A
stale worker cannot remove a replacement, one release clears every alias of the
same physical socket exactly once, and removing an inactive direction re-arms
queued work on the surviving active stream. If an internal detach invariant is
ever violated, teardown fails closed: the socket is retained behind permanent
stop gates and the peer keeps one quarantine reference instead of risking a
callback use-after-free. Its wrapper retains the module reference, so module
unload is refused rather than leaving a live callback into unloaded text.
Device reopen preserves that quarantine: it does not clear the stop gate or
queue retry, staged packets, or keepalives for the retained peer.

EOF, hard receive failures, zero-byte sends, and hard send failures now converge
on exact-socket recovery. The worker discards incomplete parser state or the
uncertain outbound frame, then claims cleanup only if that exact socket is still
the peer's published outbound socket or tracked temporary inbound socket. It
does not replay a frame whose prefix may already have entered the stream.
Outbound removal and delayed retry have one owner. Synchronous connect failure
uses the same exact reset/release helper, purges partial parser and send-queue
state, and publishes retry only after releasing the failed socket and
rechecking the stop barrier.

The one-shot send-failure selector is compiled only into
`wireguard-fork-fault.ko`. It matches network-namespace inode, WireGuard
ifindex, and the complete local/remote IPv4 address and port tuple before
injecting `EPIPE`; production and ordinary DEBUG modules expose none of these
parameters. The source contracts, VM builds, and hostile-stream runtime case cover that
isolation and restore the production module after fault injection.

## Configuration

TCP mode requires the modified Linux kernel module and modified `wg` tool at both
endpoints. In either mode, an omitted or zero `ListenPort` selects a random port
when the interface comes up. For TCP, the companion UDP socket selects the
concrete port first and the TCP listener binds the same number; configure the
peer endpoint with that selected port.

At minimum, the dialing peer needs the other peer's reachable TCP listen port.
The ports may differ; the recorded asymmetric-listen-port case passed. For a
private peer behind NAT, configure only its reachable peer endpoint: the public
peer can authenticate and promote the accepted carrier without a reverse port
forward. The focused Hyper-V gate passed source-port and source-address changes
from `192.0.2.1:41001` to `192.0.2.129:41002`. When both peers are reachable,
either authenticated TCP direction may become the active carrier.

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

An authenticated packet received on a provisional accepted socket now promotes
that exact carrier into the configured peer in process context. This permits a
private peer to dial a reachable peer through ordinary SNAT without a reverse
DNAT or forwarded listen port. A device-monotonic connection ID prevents a
retained older carrier from reverting the authenticated winner.

Final rebased Hyper-V run `wg20260731T074807Z` passed this outbound-only model on both Ubuntu
guests. It verified accepted-carrier promotion, bidirectional traffic,
keepalive activity, a forced `41001`-to-`41002` source-port change,
authenticated reacquisition, source-address roaming to `192.0.2.129`,
retirement of the old accepted carrier, and clean kernel logs. When both peers
are reachable, either authenticated TCP direction may win and the tunnel
continues over that carrier.

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

Focused policy-churn coverage now repeats route, source-address, uplink, and
`FwMark` changes with asymmetric listen ports. On each VM it completed 11
transitions with 20 distinct replacement-carrier proofs and eight
mark-specific SYN proofs. Every mutation follows a quiet exact-tuple baseline,
and the `FwMark` phases prove socket-mark propagation and reconnect; the
separate full-tunnel `fwmark` mode remains the owner of mark-selected routing
coverage.

The half-open case blackholes only the established carrier, observes increasing
`TCP_INFO` retransmission metrics and namespace `RetransSegs`, and validates a
new authenticated carrier before proving that the old client tuple is absent
and traffic works in both directions. It deliberately
sets namespace-local `tcp_retries2=5` and `tcp_syn_retries=3`. Those accelerated
values make failure detection practical in regression and are not evidence for
production-default detection time.

Run `wg20260714T084959Z` passed a narrower same-identity two-carrier surrogate
on both VMs. Two client devices share one private key but use independent
listen ports, marks, carrier routes, and path-specific inner source routes. The
new device is preplumbed up, routed, keyless, and peerless; after one encrypted
old-path data record is queued behind a 60-second delay, the old device is cut
off and the new peer is activated. The endpoint moves to the second router
while configured forward port `52241` is preserved. When the delayed
authenticated data record arrives, both WireGuard RX and an exact inner-echo
counter advance, but the endpoint does not roll back and the old router sees no
new reverse SYN. After a 16-second stable-state barrier, a live server `FwMark`
change creates a different marked outbound tuple through the new DNAT, retires
the prior established tuple, and preserves bidirectional traffic.

That test is intentionally a same-identity **two-device carrier surrogate**.
It validates generation ordering, configured-port preservation, delayed-data
rollback resistance, and reconnect targeting across two carriers. It does not
move one live WireGuard device, atomically promote an accepted socket, or prove
general responder-only NAT roaming. Those are limits of that historical test,
not of the current implementation: the later SNAT-only focused gate validates
same-device accepted-carrier promotion, source-address/port movement, and
old-carrier retirement without an inbound forward.

The strengthened version of that surrogate harness calls its physical topology
`independent-outbound-pair`. It uses a 110-second staged-record delay, a
12-second exact-tuple pre-stage baseline, 12-second automatic-authentication
gates after initial and post-`FwMark` establishment, and separate 16-second
quiet barriers before stale release and mark change. The 12-second gates exceed
twice the five-second provisional idle timeout. Those surrogate carriers are
still two
independently dialed streams, not accepted-socket promotion or deduplication;
static-key ordering selects Noise initiation and does not elect a physical TCP
carrier.

Important remaining TCP parity work includes:

- adding exact-stream handshake/cookie replies, TCP cookie-response
  consumption, MAC1 validation, and a staged MAC2 challenge rollout so
  pre-Noise cost defense does not break older TCP peers under load;
- validating namespace teardown/move and VRF behavior;
- completing MTU accounting, longer hostile-network soaks, and broader kernel,
  controller, topology, physical-carrier impairment, malformed-stream, and
  multi-flow coverage before claiming production or all-modes parity.
- combining a partial write followed by a terminal send failure to prove that
  no emitted prefix is replayed, and injecting EOF after a partial receive to
  prove parser-state disposal and reconnect under that exact sequence;
- rerunning the complete cross-platform suite, including IPv6 and dual-stack
  cases, against the merged recovery and roaming source.

The full roaming state model and acceptance checklist are in the
[design document](docs/TCP_TRANSPORT_DESIGN.md#roaming-and-endpoint-mobility).

## Benefits analysis

TCP mode is a deployment option, not a universal replacement for UDP.

| Potential benefit | Where it helps | Tradeoff |
|---|---|---|
| Reachability on UDP-blocked paths | Networks that allow raw TCP to the selected port | The stream is not HTTP/TLS camouflage and can still be blocked |
| Reuse of WireGuard security model | Same peer keys, Noise sessions, AllowedIPs, replay checks, keepalives, and rekey | Both endpoints need the modified Linux implementation |
| No reverse NAT rule for a private peer | The private peer initiates through ordinary SNAT; the reachable peer authenticates and promotes that exact carrier | Keep the private mapping alive when the NAT has a short idle timeout |
| Kernel-native persistent carrier | No proxy, relay, or extra userspace encapsulation hop is required for ordinary packet flow | Kernel module deployment follows the target kernel ABI |
| Automatic recovery and mobility | Exact-socket failure recovery, half-open replacement, authenticated address/port roaming, and route/source/uplink/mark reconnects passed | Broader provider and long-duration testing remains prudent |
| Bounded stream handling | Framing validation, capped queues, short-write continuation, parser resynchronization, and fatal-send replacement passed destructive focused tests | TCP still imposes ordered-stream head-of-line behavior |
| Potential outer-loss recovery | Non-congestive loss where completeness matters more than timeliness | Ordered recovery can create latency and head-of-line blocking; the published campaign did not validate physical-carrier loss |
| Reliable carriage of inner UDP | Bulk or transactional datagrams | Late packets may be worse than loss for voice, gaming, or real-time video |
| Stateful firewall/NAT friendliness | Outbound-only single NAT, authenticated accepted-carrier promotion, source-port rebinding, stale-carrier retirement, and dual-reachable initiation with either authenticated direction passed | Validate the target provider's timeout and filtering policy |
| Familiar operations | `wg`, `wg-quick`, `showconf`, `setconf`, `syncconf`, SaveConfig, asymmetric ports, dual stack, and scoped IPv6 remain available | TCP is selected per interface |
| Per-deployment choice | Separate UDP and TCP interfaces can serve different routes | Additional configuration and operational testing |

Use UDP when it works and low latency, datagram semantics, or minimal state are
the priority. Evaluate TCP where UDP is blocked or on a measured path where its
tradeoffs are acceptable. Namespace-isolated IPv4/IPv6 tunnels, full-tunnel
policy routing, authenticated roaming, and live route, source, uplink, and mark
reconnects passed the recorded topology. For highly multiplexed or
long-duration production deployments, validate the target provider, firewall,
connmark, namespace, and VRF policy against the design checklist.

## Performance and TCP-over-TCP behavior

The repository contains two distinct evidence sets. The calibrated conclusion
and replication index are in
[`docs/TCP_MELTDOWN.md`](docs/TCP_MELTDOWN.md).

The legacy application-level Azure campaign compares TCP-WG and UDP-WG across
x64/arm64, four latency tiers, and configured loss values from 0% to 20%. These
are synthetic two-vCPU VM tests: bulk TCP uses four parallel streams, bulk UDP
is capped at 1 Gbps, and injected loss is iid random. Its published tables
contain striking results. Examples include:

- LAN x64 bulk TCP: 2789.4 Mbps over TCP-WG versus 2588.2 Mbps over UDP-WG on
  the clean cell.
- The same published 10% cell: 2751.2 Mbps over TCP-WG versus 28.8 Mbps over
  UDP-WG.
- LAN x64 short HTTPS at the published 10% cell: 154.54 requests/s over TCP-WG
  versus 6.01 over UDP-WG.
- Clean high-latency x64 bulk TCP also shows the cost side: TCP-WG is 14% behind
  UDP-WG at the report's HIGH tier and 23% behind at MAX.

No classic nested-TCP throughput collapse is visible in those application
tables, including the 60-second bulk runs. That legacy harness impaired the
WireGuard interface rather than demonstrably impairing and instrumenting the
physical outer TCP carrier, so it cannot locate an outer-loss boundary.

The ARM gap-fill was corrected with bounded workload execution and hardened
capture/retry handling. It completed all 32/32 HIGH-arm TCP-WG cells cleanly
with no retries, and the final application matrix contains all 512 unique
cells. Subsequent transport work also repaired writer wakeups, bounded the
send queue, and validated short-write, queue-pressure, fatal-send, and
replacement-carrier recovery paths.

The newer mechanistic campaign tests the physical carrier path directly. Its
82 clean calibration and finite-queue/RTT screening cells are all valid/stable.
No-loss 16-flow TCP controls at 200-400 ms delivered about 47 Mb/s with
essentially no zero-delivery stalls.

Severe behavior appeared only after combining a 50 Mb/s, 1x-BDP FIFO with 16
continuously backlogged CUBIC flows, 200-400 ms RTT, and persistent random or
Gilbert-Elliott loss. The lowest demonstrated severe profile had 4.42% nominal
stationary burst loss at 200 ms; its two valid TCP repetitions delivered
0.73-1.09 Mb/s, stalled in 52.8%-62.2% of 100 ms bins, and had longest
continuous stalls of 0.7 and 6.3 seconds. Across all nine valid logical TCP
breadth cells, longest stalls ranged from 0.7 to 40.2 seconds.

This is an extreme laboratory corner, not evidence that healthy modern
networks commonly enter meltdown. It can resemble transient conditions on
congested mobile, interfered Wi-Fi, satellite, mobility-handoff, or overloaded
tunnel paths. The planned 0.3% random-loss onset row was not run, so the exact
lower threshold is unknown.

Across all 162 post-repair raw executions, 122 are valid: 92 stable, 17
degraded, 13 near-meltdown, and zero formal meltdown. No valid execution
simultaneously contains the required stall, declining-goodput, and inner-RTO
conditions. The campaign demonstrates a narrow failure mechanism, not its
prevalence and not general immunity.

The traffic evidence applies to its recorded runtime fingerprint. The
campaign-era parity/lifecycle integration built identically on both ARM hosts;
the current tree additionally passes 213 local tests plus focused NAT/recovery
and hostile-stream gates. Those later correctness results complement rather
than retroactively alter the recorded performance cells.

See [`perf-test/REPORT.md`](perf-test/REPORT.md) for the legacy application
tables and [`perf-test/meltdown/`](perf-test/meltdown/README.md) for the
replicable mechanistic harness, raw-stall analysis workflow, and evidence
inventory.

## Repository structure

```text
kernel/                       WireGuard kernel module with TCP transport
tools/                        Modified WireGuard userland tools
include/uapi/                 Additive Linux transport UAPI
QUICKSTART.md                  Installation, first tunnel, and configuration templates
PERFORMANCE.md                 Performance advantages and calibrated meltdown results
docs/TCP_TRANSPORT_DESIGN.md  Detailed architecture and parity design
docs/TCP_MELTDOWN.md          Calibrated meltdown scope and replication index
DESIGNLOG.md                  Chronological architectural decisions
CHANGELOG.md                  User-visible changes and validation history
docs/                         Relay and tunnel setup notes from the source branch
perf-test/                    Performance plan, harness, reports, and matrices
perf-test/meltdown/           Mechanistic carrier impairment and stall harness
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

For the full stock/fork cross-host matrix, use either repeatable two-VM Ubuntu
24.04 lab. Both paths provision isolated outer carrier networks, build
production, DEBUG, and isolated fault-injection modules on both guests, and
record timestamped JSON, Markdown, and per-command logs.

**Linux (libvirt/QEMU):** On a Linux KVM host, install the dependencies and
verify a Canonical Ubuntu cloud image as described in
[`tests/linux/README.md`](tests/linux/README.md), then run:

```bash
sudo ./tests/linux/Provision-LinuxRegression.sh \
  --base-image "$PWD/noble-server-cloudimg-amd64.img" \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" \
  --ssh-private-key "$HOME/.ssh/id_ed25519"
./tests/linux/Run-LinuxRegression.sh
```

The Linux harness creates `wgtcp-a` and `wgtcp-b` on the existing libvirt
management network plus private `wgtcp-path0` and `wgtcp-path1` networks. It
uses verified SSH host keys for management, transfers the exact Git-visible
snapshot, then delegates to the same complete case list and guest helpers as
the Hyper-V runner. Linux run `wg20260731T130556Z` passed all 40 cases with no
failures or skips in 955.098 seconds.

**Windows (Hyper-V):** On Windows 10/11 Pro, Enterprise, or Education, enable
Hyper-V and install the verified Multipass package as described in
[`tests/hyperv/HYPERV_SETUP.md`](tests/hyperv/HYPERV_SETUP.md). From an elevated
PowerShell 7 session:

```powershell
.\tests\hyperv\Enable-HyperV.ps1 `
  -MultipassMsi C:\Installers\multipass-installer.msi `
  -StatePath .\tests\hyperv\results\host-enable.json
# Reboot if the script reports RestartNeeded, then:
.\tests\hyperv\Provision-HyperV.ps1
.\tests\hyperv\Run-HyperVRegression.ps1
```

The shorter Windows operating guide is
[`tests/hyperv/README.md`](tests/hyperv/README.md). The latest committed
Hyper-V campaign summary is in [`tests/hyperv/RESULTS.md`](tests/hyperv/RESULTS.md); run
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

Focused run `wg20260714T070320Z` passed the policy-churn and half-open cases on
both guests. The policy case recorded 11 transitions, 20 exact reconnect
proofs, and eight mark-specific SYN proofs per guest. The half-open case used
accelerated namespace-local TCP retry policy, corroborated the dropped
carrier with exact `TCP_INFO` and `RetransSegs` movement, and proved a
conntrack-correlated replacement tuple. That mixed run also contained an older
failing revision of the dual-router case, so it is not a complete green gate.

Corrected historical run `wg20260714T084959Z` passed the
`tcp-nat44-dual-router-address-roam` two-device surrogate on both guests.
Current run `wg20260731T074807Z` supersedes it for operational NAT roaming:
the single private device changed its outbound source address and port without
DNAT, promoted the new authenticated carrier, retired the old carrier, and
retained bidirectional tunnel traffic. A full rerun of every historical case
on the current source remains separate from this green focused gate.

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
counter deltas, resets every control, and verifies post-pressure traffic. Its
terminal-send fault arms last and matches the network namespace, WireGuard
ifindex, and exact IPv4 4-tuple, preventing an unrelated stream from consuming
the one-shot `EPIPE` injection.

## Documentation

- [Installation, basic tunnel, and advanced configuration QuickStart](QUICKSTART.md)
- [Performance advantages and TCP-over-TCP meltdown results](PERFORMANCE.md)
- [Design decision log](DESIGNLOG.md)
- [Change log](CHANGELOG.md)
- [TCP transport design, compatibility, roaming, and behavior](docs/TCP_TRANSPORT_DESIGN.md)
- [Linux libvirt regression lab](tests/linux/README.md)
- [Hyper-V host and VM creation guide](tests/hyperv/HYPERV_SETUP.md)
- [Hyper-V regression results](tests/hyperv/RESULTS.md)
- [Performance campaign report](perf-test/REPORT.md)
- [Performance test plan](perf-test/TESTPLAN.md)
- [Performance runbook](perf-test/RUNBOOK.md)
- [Relay notes](docs/AGENT_RELAY.md)
- [Node setup notes](docs/NODE_README.md)
