# WireguardTCP Design History

This document explains how the WireguardTCP architecture evolved from the
preserved original TCP branch into the current kernel module, userland tools,
test systems, and performance framework. It records implemented design
decisions and the bug fixes that refined them.

## Part I - Chronological design history

### 2024-02-28 - Source assembly and transport configuration

The preserved implementation identifies its source as
`jnathan/naked_gun@4211b00ef437f097ffd741145ec4379eb89bb031`. Its original
authenticated GitHub commit graph was inspected directly. It contains more than
1,000 fine-grained revisions from the project's assembly on 2024-02-28 through
the imported tip on 2026-03-11. Those commits establish chronology, but only the
complete tree at `4211b00` is treated as the inherited code baseline.

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

The first design decision was to select transport in the existing WireGuard
configuration plane rather than invent a second VPN protocol. After same-day
parser experiments and reverts, commit
[`b810051`](https://github.com/jnathan/naked_gun/commit/b81005137846621befb12b9e3d09d49af29b5053)
consolidated TCP-aware configuration and command-line setup.

### 2024-02-29 through 2024-03-01 - Control plane reaches the kernel

Device and peer transport commands
([`658692f`](https://github.com/jnathan/naked_gun/commit/658692fc8ce58d016db5513876a4126ce6ed4160))
were connected to kernel generic netlink
([`c7c30d1`](https://github.com/jnathan/naked_gun/commit/c7c30d167d41a1b36adf5910a6a96f69b389c47b))
and passed through the tools
([`ce2e585`](https://github.com/jnathan/naked_gun/commit/ce2e58561ad10863e7aa71c0ff8f2adcc8211cc4)).
This established the lasting interface-wide policy: UDP remains the default;
TCP is an explicit alternative.

### 2024-03-03 - Kernel carrier prototype

[`8c24329`](https://github.com/jnathan/naked_gun/commit/8c24329c49609f7ac2815d8ff6a80d6654eab05c)
introduced the first kernel TCP handling. The design immediately required
process-context workers because WireGuard packet production and TCP stream I/O
have different blocking and framing rules.

### 2024-03-06 and 2024-03-07 - Send integration and endpoint reconstruction

The ordinary IPv4 and IPv6 send functions began queuing through the TCP carrier
in
[`c8c9c12`](https://github.com/jnathan/naked_gun/commit/c8c9c125bd859863f2022bd39bb4e4ed4cbe908c).
Socket endpoint extraction, endpoint comparison, and IPv6 link-local scope
handling then supplied the metadata expected by the common WireGuard receive
path.

### 2024-03-13 through 2024-03-17 - Listener and provisional-peer lifecycle

The branch added TCP-specific MTU handling, listener threads, callback reset,
device connection lists, accepted temporary peers, cleanup, and separate IPv4
and IPv6 listener ownership. Unknown accepted sockets could not be trusted as a
configured peer until a WireGuard handshake established identity, so
provisional peer state became a core lifecycle concept.

### 2024-04-04 through 2024-04-08 - Framing, connect, and retry

The encapsulation header moved into the shared socket interface. Outbound
connection creation, retry work, peer socket fields, timeout handling, and lock
types were refined together. Framing and lifetime were therefore coupled: a
partial record could not safely outlive or migrate away from its exact stream.

### 2024-04-10 through 2024-04-15 - Queues and configuration round trip

Per-peer send queues, partial-record storage, cleanup work, and connection-list
iteration were added. In parallel, `wg` parsing, display, Linux IPC, and
container structures were extended so the transport choice could make a
complete userspace round trip.

### 2024-04-17 through 2024-07-31 - Integration into device lifecycle

Generic-netlink, device, peer, and socket changes moved TCP from a hard-wired
prototype into selected device behavior. June added required peer/device state.
July refined startup, address reuse, listener selection, outbound connect
placement, callback setup, retry scheduling, shutdown, and port validation.

### 2024-08-01 through 2024-08-07 - Explicit dual transport

Early connection-list locking was replaced with RCU-oriented handling,
diagnostics expanded, and hard-wired TCP behavior was removed. The branch
defined an explicit UDP/TCP selector and brought up both paths under one device
policy.

### 2024-08-11 through 2024-08-16 - Worker and callback ownership

Connection cleanup, queuing, state callbacks, read/write workers, callback
publication flags, locks, and peer socket cleanup were repeatedly refined.
These changes exposed the central rule later formalized in the standalone
repository: callback installation, parser state, queued output, and release
must have one exact socket owner.

### 2024-08-17 through 2024-08-21 - Stream parser hardening

Handshake, cookie, packet, and stream diagnostics were used to correct null
dereferences, partial reads, header synchronization, leftover SKBs,
`sk_user_data` ownership, and TCP-specific receive metadata. UDP header
processing was explicitly skipped for TCP records before both paths rejoined
the common authenticated receive machinery.

### 2024-08-22 through 2024-08-25 - Promotion and directional carriers

The design iterated through temporary-peer promotion, connection races,
separate inbound/outbound callbacks, endpoint storage, retry cleanup, and
source/destination tracking. The hundreds of granular commits in this period
record experiments and reversals, not a release train.

### 2024-08-26 through 2024-09-24 - Stabilization and diagnostics

Temporary debugging was reduced, the configured TCP port replaced hard-wired
values, and the working branch was synchronized. September corrected pointer
arithmetic, leftover-buffer handling, and transfer locking while adding
structured TCP/IP decoding. ECN was disabled for the experimental outer TCP
carrier.

### 2025-01-28 through 2025-03-11 - Instrumentation-led socket repair

Send, receive, pointer, device, SKB, and endpoint diagnostics drove targeted
socket and parser corrections. The instrumentation remained a development aid,
not an extension of the wire protocol or trust model.

### 2025-05-01 through 2025-07-22 - Worker experiments and rollback

Full SKB tracing and receive/socket worker experiments were added, then the May
worker changes were reverted in June. July reworked the transfer path without
depending on the discarded arrangement. The history preserves unsuccessful
approaches instead of presenting only the final state.

### 2025-07-29 through 2025-09-30 - Fragmentation and queue convergence

Conditional fragmentation-header length and detection were corrected in
[`dee4602`](https://github.com/jnathan/naked_gun/commit/dee4602c904c21689181da5c58ce6b8e63e8352b)
and
[`e66f421`](https://github.com/jnathan/naked_gun/commit/e66f4215b0970f9853c14d7629ac13b26210bcac).
The branch then removed obsolete maximum-packet and write-queue remnants,
renamed framing fields, and continued stream fixes.

### 2026-02-05 - Structured diagnostic and socket-fix tranche

A formal TCP diagnostic framework preceded memory, initialization,
return-value, listener, and socket refactoring fixes. The tranche ended with
the temporary-peer prototype correction in
[`51765a1`](https://github.com/jnathan/naked_gun/commit/51765a1cb4c28ab30595a676418b57cc75810b7f).

### 2026-03-08 - Listener, connect, and latency corrections

The branch corrected listener temporary-peer construction, outbound connect
completion, and `TCP_NODELAY` setup on accepted and outbound sockets. Verbose
and diagnostic logging were separated. Relay and node-agent work supported
development operations but did not change the carrier wire format.

### 2026-03-09 - Rekey and buffered-read correctness

Handshake/rekey livelock and buffered-read starvation were addressed with
pre-send drain/recheck sequencing and processing of already-buffered records in
[`fe2fd51`](https://github.com/jnathan/naked_gun/commit/fe2fd5135dc168cc6d44bb7a76b831d7c38804f6),
[`7f66568`](https://github.com/jnathan/naked_gun/commit/7f6656843900431953ed79db36efbdb9fe3f8c14),
and
[`def79f2`](https://github.com/jnathan/naked_gun/commit/def79f2144c6244a3a30f1d00ad7b25a2cfc1fcc).

### 2026-03-11 - Historical source boundary

[`4211b00`](https://github.com/jnathan/naked_gun/commit/4211b00ef437f097ffd741145ec4379eb89bb031)
fixed module-removal deadlock and callback use-after-free hazards. This exact
`tcp` tip is the inherited baseline. The default `main` branch is separate: its
February socket-fix batches were reverted as wrong-branch changes, and its May
testing documents postdate the imported tip.

### 2026-04-27 - Standalone import (`ffe7285`)

The standalone import retained:

- the complete out-of-tree kernel module;
- the modified `wg` and `wg-quick` tools;
- the transport-aware UAPI;
- source-era build and tunnel notes; and
- no redundant Linux kernel source tree.

That layout made the transport implementation directly buildable against the
running kernel and made kernel, userland, UAPI, tests, and documentation
reviewable in one repository.

### 2026-04-30 through 2026-05-03 - Application performance architecture

The project added isolated point-to-point x64/arm64 pairs, matched TCP-WG and
UDP-WG tunnels, four latency tiers, five application workload families, loss
matrices, repeated runs, raw-result preservation, and reproducible aggregation.
Parser corrections excluded failed HTTP requests from successful latency,
retained valid non-2xx timing, used supported CPU sampling, and allowed exact
gap-cell reruns. The resulting claims were intentionally application-level,
not proof about every TCP-over-TCP mechanism.

### 2026-05-08 - Performance documentation maintenance

Quota, clone, naming, and campaign instructions were corrected without changing
the measured evidence.

### 2026-07-11 - Exact socket retirement and reviewability

`b1c40d9` serialized send, callback reset, queue drain, and socket release with
peer-level locks and synchronous worker cancellation. `245774d` made the
complete fork reviewable as one generated patch, while `35c9110` documented the
transport architecture and bounded performance findings.

### 2026-07-12 - Compatibility becomes an explicit invariant

`f515eb5` established UDP-default behavior, stock-facing grammar and output,
shared TCP/UDP listen-port rules, transport-aware UAPI and tools, namespace and
dual-stack coverage, and a two-VM regression matrix. Compatibility became a
tested contract rather than an assumption inherited from the fork.

### 2026-07-13 - Lifecycle, writer, NAT, and mechanistic test design

The project created formal change/design logs, added the physical-carrier
meltdown campaign, repaired the TCP writer lost wakeup, expanded parity
contracts, added isolated NAT44 validation, preserved transport through
configuration reload, and isolated destructive hostile-stream controls in a
separate fault module. Campaign gates were committed before results so later
interpretation could not silently move thresholds.

### 2026-07-14 - Evidence integrity and full parity

Transport-aware clean controls, exact endpoint roles, concurrency-safe BPF
aggregation, monotonic event sequences, immutable reruns, and provenance-bound
composites made invalid or missing evidence detectable. `849d702` consolidated
device, listener, endpoint, network-notifier, parser, admission, and stream
ownership. The 36-case functional campaign completed with 36 PASS, 0 FAIL, and
0 SKIP.

### 2026-07-15 - Operating envelope and boundary campaigns

`d24fa51` separated observed severe degradation from the formal meltdown
definition and documented the measured operating envelope. Subsequent commits
predeclared timed boundary and correlation campaigns instead of generalizing
beyond completed evidence.

### 2026-07-30 - Cleanup, Linux regression, and user documentation

Kernel cleanup removed dead declarations and duplicate structures. A Linux
libvirt/QEMU/KVM backend was added beside Hyper-V and completed the shared
36-case suite. Regression contracts were repaired around stable source
boundaries, and the QuickStart and performance guide were expanded for users.

### 2026-07-30 - TCP modularization and roaming groundwork

`a8ef645` moved TCP-specific carrier and diagnostic code out of the generic
socket/send files into `wg_tcp.c`, `wg_tcp.h`, and dedicated debug sources.
`7f45beb` checkpointed expanded lifecycle, NAT, policy-churn, and roaming
documentation and regression scaffolding. This checkpoint records groundwork;
it does not retroactively broaden the authenticated-promotion or real-device
roaming claims.

## Appendix - Detailed architecture by subsystem

## Device-wide transport selection

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

## TCP record format and receive integration

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

## Listener, dialer, and provisional accepted connections

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

## Socket ownership and retirement

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

## Serialized transmission and backpressure

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

## Endpoint identity, learning, and simultaneous initiation

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

## Network namespaces, routes, and socket marks

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

## IPv4, IPv6, and scoped endpoints

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

## Configuration persistence

The transport setting follows the normal WireGuard configuration lifecycle:

- `wg showconf` emits canonical `Transport = tcp`;
- `wg setconf` applies a complete configuration;
- `wg syncconf` removes drift while retaining the desired transport; and
- `wg-quick SaveConfig` preserves the setting across interface recreation.

Regression tests keep private keys and secret-bearing configurations in
guest-local restricted directories, compare files without printing secrets,
and report only public pass/fail metadata.

## Diagnostics and test-only fault injection

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

## Regression architecture

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

## Performance test architecture

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

## Documentation evolution

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
