# WireguardTCP Design History

This document explains how the WireguardTCP architecture evolved from the
preserved original TCP branch into the current kernel module, userland tools,
test systems, and performance framework. It records implemented design
decisions and the bug fixes that refined them.

## 1. Source lineage and standalone layout

### Original TCP branch

The preserved implementation identifies its source as
`jnathan/naked_gun@4211b00ef437f097ffd741145ec4379eb89bb031`. Its original
commit graph is no longer available from GitHub, so the design of that period is
reconstructed from the imported source and retained source-era notes.

The original branch made TCP a carrier beneath WireGuard rather than a new VPN
protocol:

```text
inner packet
    -> WireGuard Noise encryption
    -> WireGuard message
    -> UDP datagram or framed TCP record
```

This retained WireGuard's peer keys, Noise state machine, replay protection,
timers, `AllowedIPs`, and encrypted message formats. TCP framing was introduced
only to recover record boundaries from a byte stream.

### Standalone import - `ffe7285`

The April 2026 import retained:

- the complete out-of-tree kernel module;
- the modified `wg` and `wg-quick` tools;
- the transport-aware UAPI;
- source-era build and tunnel notes; and
- no redundant Linux kernel source tree.

That layout made the transport implementation directly buildable against the
running kernel and made kernel, userland, UAPI, tests, and documentation
reviewable in one repository.

## 2. Device-wide transport selection

### Original decision

Transport selection is an interface property:

- value zero and an omitted setting select UDP;
- explicit `udp` selects the retained UDP path; and
- explicit `tcp` selects the TCP carrier.

The Linux generic-netlink device attributes carry the selection between the
modified tool and kernel. The parser accepts `Transport = tcp`, the direct
command supports `wg set <interface> transport tcp`, and canonical
configuration output uses the same spelling.

### Compatibility refinement - `f515eb5` and `849d702`

The compatibility work established these invariants:

- Existing configurations remain UDP unless they opt into TCP.
- Stock-facing UDP command grammar and output remain unchanged.
- UDP random-port selection remains available.
- TCP mode binds its listener and companion UDP socket to the same selected
  numeric port.
- Transport and TCP listen-port replacement occur while the interface is down,
  preserving active socket ownership.
- Separate interfaces provide independent TCP and UDP policy when both are
  required by one host.

The Hyper-V matrix tested stock and modified tools against stock and modified
kernels, while source contracts encoded parser, netlink, output, random-port,
and live-mode transition behavior.

## 3. TCP record format and receive integration

### Original framing design

The TCP carrier prepends an 8-byte header to each encrypted WireGuard message.
The header carries:

- total record length;
- WireGuard message type;
- framing flags; and
- a lightweight framing checksum.

The checksum locates plausible record boundaries; WireGuard authentication
continues to determine whether a message is trusted.

The receiver:

1. reads stream bytes without assuming one socket read equals one record;
2. validates type, flags, checksum, and bounded length;
3. retains incomplete records for the next read;
4. reconstructs endpoint metadata from the selected socket; and
5. passes complete encrypted messages into the normal WireGuard receive path.

### Stream parser hardening - `f515eb5`, `88b7173`, and `849d702`

The parser evolved to:

- use right-sized leftover buffers;
- grow buffers only when a validated record requires more space;
- process complete buffered records before requesting more socket data;
- retain a possible seven-byte split-header suffix during resynchronization;
- reschedule bounded buffered work; and
- pin one socket through receive, parse, metadata construction, delivery, and
  requeue.

These changes made parser state belong to the exact carrier being consumed
rather than to a mutable peer socket alias.

### Hostile-stream validation

The separate fault module added:

- bounded garbage prefixes;
- parser resynchronization counters;
- forced short writes;
- queue-pressure controls;
- one-shot writer delay; and
- post-pressure traffic verification.

Production and ordinary DEBUG builds do not expose these destructive controls.

## 4. Listener, dialer, and provisional accepted connections

### Original listener and dialer design

TCP mode supports both directions:

- a per-device listener accepts new streams;
- configured peers create nonblocking outbound connections;
- socket callbacks schedule peer work; and
- retry and cleanup workers own reconnection and retirement.

Accepted sockets initially use temporary peers because the remote WireGuard
identity becomes known only after authenticated Noise traffic arrives.

Source-era notes record fixes to listener setup, temporary-peer handling,
outbound connection establishment, and `TCP_NODELAY` on both accepted and
outbound sockets.

### Admission and identity hardening - `849d702`

Provisional connections gained:

- a device-wide admission cap;
- a per-source admission cap;
- a fixed-size source accounting table;
- source throttling;
- idle and absolute authentication deadlines;
- stable device-local connection identifiers; and
- release of pre-authentication accounting after valid Noise traffic.

The listener records the temporary peer and connection identity in the tracked
connection entry. Asynchronous authentication can therefore refer to one exact
accepted carrier even when multiple sockets are active.

## 5. Socket ownership and retirement

### Original model

The imported module already had listener, inbound, outbound, and selected peer
socket aliases plus read, write, retry, inbound-removal, and outbound-removal
work items.

### Lifetime serialization - `b1c40d9`

The July lifetime fix introduced two peer-level ownership locks:

- a write mutex serializing send activity against retirement; and
- a cleanup mutex granting exclusive retirement ownership.

Read and write recheck flags record callbacks that arrive while their worker is
already active. Teardown synchronously cancels both workers and clears
scheduling state under the corresponding locks.

The resulting invariant is:

> A retiring socket is detached from callbacks, drained from asynchronous work,
> and released once by its serialized owner.

### Complete lifecycle hardening - `849d702`

Later work unified:

- connection-attempt ownership;
- publication of peer and outbound aliases;
- callback installation and reset;
- retry scheduling;
- inbound and outbound removal ownership;
- peer stop barriers;
- queue draining; and
- final socket release.

Removal workers claim the exact socket they retire. Peer stop establishes its
barrier before cancelling work and snapshotting sockets. Network callbacks and
notifiers request work rather than releasing sockets directly.

### Cleanup pass - `8b2e3c7`, `c8d317c`, `d3fa877`, and `000a4ea`

The implementation was then consolidated by:

- moving shared declarations to `socket.h`;
- removing stale prototypes;
- deleting duplicate and incomplete structures;
- removing the redundant `wg_tcp_socket_list_entry` definition;
- removing dead receive, Noise, cookie, send, and socket paths; and
- clarifying debug helper names.

## 6. Serialized transmission and backpressure

### Per-peer output queue

Every framed message enters one bounded per-peer queue. One write worker owns
`kernel_sendmsg()` calls for that peer, preserving stream order.

When a send writes only part of a frame:

- the exact unsent suffix remains at the queue head;
- no second encapsulation header is created;
- already-sent bytes are not repeated; and
- the worker resumes from the retained offset.

Queue pressure rejects the newest frame, preserving the partially transmitted
head and every earlier serialized frame.

### Lost-wakeup fix - `7f8472d`

The write worker originally checked `sk_stream_is_writeable()` before calling
`kernel_sendmsg()`. The fix removed that precondition because a nonblocking send
reaching `EAGAIN` is what establishes the TCP stack's normal `SOCK_NOSPACE`
wakeup contract.

The corrected design:

- attempts the nonblocking send;
- explicitly arms write-space notification whenever work remains blocked;
- pairs the flag update with the kernel memory barrier used by TCP polling; and
- relies on `sk_write_space` to reschedule the serialized writer.

This eliminated a condition in which queued frames could remain without a
future callback.

## 7. Endpoint identity, learning, and simultaneous initiation

### Configured endpoint separation

TCP has two distinct port concepts:

- the configured peer listen port used for future outbound connections; and
- the observed source port of an accepted connection.

The implementation keeps them separate. Authenticated traffic can update the
remote IP used by a future dial, while the configured listen port remains
operator-controlled.

Device-monotonic connection identifiers order authenticated observations so an
older retained carrier cannot overwrite a newer target. Explicit netlink
endpoint changes remain authoritative.

### Simultaneous initiation

When both peers initiate at the same time, static public-key ordering selects a
deterministic Noise initiation role under the handshake lock. Both endpoints
therefore make the same role decision without a separate coordination service.

### NAT44 behavior

The isolated NAT regression formalized a dual-reachable topology:

- the private peer creates an outbound connection through SNAT;
- a stable external port DNATs to its listener for reverse connectivity;
- keepalives maintain state;
- observed translated source ports do not replace the configured forwarded
  port; and
- a live `FwMark` update can force a new reverse dial through the configured
  forward.

All router behavior lives in a disposable network namespace, keeping host and
guest root networking unchanged.

## 8. Network namespaces, routes, and socket marks

### Creation namespace

Listener and outbound sockets use the WireGuard device's retained creation
namespace. The design takes a reference while creating the socket and releases
it after creation.

### Device marks

Listener, accepted, and outbound sockets carry the WireGuard device's
`FwMark`. Live mark changes refresh socket policy and request serialized
reconnection where required.

### Route and address changes

Route, address, netdevice, and uplink notifications do not directly replace
sockets. They request reconnection through the same cleanup and retry owners
used by ordinary lifecycle events.

This model was validated with:

- full-tunnel policy routing;
- recursion avoidance;
- route replacement;
- source-address replacement;
- uplink migration;
- endpoint updates; and
- live `FwMark` changes.

## 9. IPv4, IPv6, and scoped endpoints

IPv4 and IPv6 listeners are independently created, published, and released.
Failure or teardown of one family does not transfer ownership of the other
family's socket or thread.

For link-local IPv6 carriers:

- userspace preserves the named `%interface` zone;
- kernel endpoint state carries `sin6_scope_id`;
- accepted and dialed socket metadata retain the selected scope; and
- synthetic receive metadata passes that scope into authenticated endpoint
  handling.

The runtime suite validated independent dual-stack listeners, IPv6 outer
carriers, asymmetric ports, scoped link-local endpoints, and bidirectional
inner IPv6 traffic.

## 10. Configuration persistence

The transport setting follows the normal WireGuard configuration lifecycle:

- `wg showconf` emits canonical `Transport = tcp`;
- `wg setconf` applies a complete configuration;
- `wg syncconf` removes drift while retaining the desired transport; and
- `wg-quick SaveConfig` preserves the setting across interface recreation.

Regression tests keep private keys and secret-bearing configurations in
guest-local restricted directories, compare files without printing secrets,
and report only public pass/fail metadata.

## 11. Diagnostics and test-only fault injection

### Diagnostic builds

The kernel Makefile supports:

- `WG_TCP_DIAG` for TCP congestion, RTT, retransmission, queue, and socket
  diagnostics; and
- `WG_TCP_VERBOSE` for detailed isolated-lab tracing.

### Build variants

The regression environment builds and fingerprints:

- a production module;
- an ordinary DEBUG module; and
- a DEBUG plus `WG_TCP_FAULT_INJECTION` module.

Module metadata checks prove destructive parameters exist only in the fault
variant. A guest-owned command installs cleanup before loading the fault module,
runs the test, restores production, and reports both test and restoration
status.

## 12. Regression architecture

### Source contracts

Python contract tests inspect stable source sections and encode design
invariants for transport grammar, netlink behavior, ownership, listener
lifecycle, stream ordering, parser bounds, namespace use, endpoint learning,
marks, ports, diagnostics, NAT, and test infrastructure.

The July code cleanup removed several old comments and declarations that tests
had used as section markers. Commit `cdc35c0` replaced those brittle markers
with stable function and preprocessor boundaries, restoring all 181 contracts.

### Hyper-V backend

The Windows backend provisions two Ubuntu guests through Hyper-V/Multipass,
adds isolated carrier networks, transfers a source snapshot, builds all module
variants, switches modules, runs cases, classifies infrastructure failures, and
captures timestamped reports and command logs.

### Linux libvirt backend

The Linux backend provisions the same topology with libvirt/QEMU/KVM and uses
verified OpenSSH transport. It imports the Hyper-V runner's authoritative case
definitions, so both host platforms execute one shared suite.

Live provisioning fixes established:

- UUID-based ownership for networks and domains;
- canonical libvirt isolated-network handling;
- SeaBIOS loading for unsigned test modules;
- explicit SSH key and host-key management;
- exact Git-visible source snapshots;
- scoped Git trust;
- privileged result ownership handoff; and
- Linux-specific preflight reporting.

## 13. Performance test architecture

### Application campaign

The application campaign chose isolated point-to-point pairs so each latency
tier and architecture had an independent TCP-WG/UDP-WG comparison.

The matrix combined:

- x64 and arm64;
- four region/latency tiers;
- TCP-WG and UDP-WG;
- short HTTPS, bulk TCP, bulk UDP, HTTP/2, and interactive traffic;
- eight configured loss levels; and
- three repetitions.

Parser and orchestration fixes made report generation deterministic:

- failed requests no longer enter successful latency statistics;
- all-failed cells do not report a request rate;
- HTTP/2 timing survives non-2xx response classification;
- CPU samplers use supported intervals;
- endpoint roles and region pairs are recovered and checked explicitly; and
- tunnel-reset support allows exact gap-cell reruns.

### Mechanistic carrier campaign

The physical-carrier campaign added:

- finite BDP-sized queues;
- controlled rate and RTT;
- random and burst loss;
- matched TCP and UDP controls;
- 100 ms tunnel-interface delivery sampling;
- BPF retransmission and timeout events;
- socket and qdisc snapshots;
- workload and server identity;
- source and runtime fingerprints; and
- exact-cell rerun and composite rules.

Test criteria are committed before execution. Results are recorded afterward
with their original fingerprints. Invalid evidence remains visible but does not
enter formal classifications.

Concurrency-safe per-CPU BPF aggregation and monotonic sequence identifiers
make lost or duplicated trace evidence detectable. Endpoint-role checks prevent
the controller from measuring local traffic by mistake.

The campaign completed 122 valid post-repair executions with zero formal
meltdown classifications. The operator summary is maintained in
`PERFORMANCE.md`, while `docs/TCP_MELTDOWN.md` and `perf-test/meltdown/` preserve
the fixed definitions, detailed matrices, and reproduction workflow.

## 14. Documentation evolution

Documentation grew with the implementation:

1. Source-era node, relay, build, and tunnel notes.
2. Standalone build instructions in the imported README.
3. `docs/TCP_TRANSPORT_DESIGN.md` for the complete transport architecture.
4. Hyper-V and Linux regression runbooks.
5. `docs/TCP_MELTDOWN.md` for the measured performance operating envelope.
6. Root `QUICKSTART.md` for compilation, installation, first tunnel, advanced
   templates, and troubleshooting.
7. Root `PERFORMANCE.md` for measured advantages and formal campaign results.
8. This chronological design history and the companion `CHANGELOG.md`.

## Maintainer update policy

Record future design changes chronologically within the relevant subsystem.
Include the implementing commit, the invariant or behavior established, the bug
fixed, and the validation that demonstrates the resulting design.
