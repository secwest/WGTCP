# WireguardTCP Code History and Changelog

This document records the development of WireguardTCP from the preserved
`jnathan/naked_gun` TCP branch snapshot through the current standalone
repository. It concentrates on implemented features, engineering changes, bug
fixes, validation, tooling, and documentation.

## Historical evidence

The imported source identifies its lineage as the `tcp` branch of
`github.com/jnathan/naked_gun` at commit
`4211b00ef437f097ffd741145ec4379eb89bb031`. The original authenticated GitHub
commit graph was inspected directly. Dates in the pre-import timeline follow
GitHub's displayed commit-day groupings; links point to representative commits
rather than implying that every one of the branch's more than 1,000
fine-grained revisions was independently releasable. Every entry beginning
with the April 2026 import is also backed by this repository's Git history.

## 2024-02-28 through 2026-03-11 - Original `naked_gun` TCP timeline

### 2024-02-28 - Repository assembly and transport configuration

- Combined `wireguard-tools` and `wireguard-linux` in one development
  repository.
- Iterated through parser stubs and same-day reverts before landing consolidated
  TCP-aware configuration and command-line plumbing in
  [`b810051`](https://github.com/jnathan/naked_gun/commit/b81005137846621befb12b9e3d09d49af29b5053).

### 2024-02-29 through 2024-03-01 - Userspace and netlink control plane

- Added device and peer transport-mode commands in
  [`658692f`](https://github.com/jnathan/naked_gun/commit/658692fc8ce58d016db5513876a4126ce6ed4160).
- Added kernel generic-netlink configuration in
  [`c7c30d1`](https://github.com/jnathan/naked_gun/commit/c7c30d167d41a1b36adf5910a6a96f69b389c47b)
  and passed the new flags from the tools in
  [`ce2e585`](https://github.com/jnathan/naked_gun/commit/ce2e58561ad10863e7aa71c0ff8f2adcc8211cc4).

### 2024-03-03 - Initial kernel TCP carrier

- Added the initial kernel TCP handling and socket workers in
  [`8c24329`](https://github.com/jnathan/naked_gun/commit/8c24329c49609f7ac2815d8ff6a80d6654eab05c).

### 2024-03-06 - Normal send-path integration

- Routed the normal IPv4 and IPv6 send paths through TCP queuing in
  [`c8c9c12`](https://github.com/jnathan/naked_gun/commit/c8c9c125bd859863f2022bd39bb4e4ed4cbe908c).

### 2024-03-07 - Endpoint extraction and IPv6 scope

- Added socket-to-endpoint extraction, endpoint comparison, and IPv6
  link-local scope handling so a TCP carrier could reconstruct the metadata
  expected by the normal WireGuard receive path.

### 2024-03-13 through 2024-03-17 - Listener and temporary-peer lifecycle

- Added conditional TCP MTU handling, callback reset, device connection
  tracking, listener initialization, temporary-peer ownership, connection-list
  cleanup, dual IPv4/IPv6 listener threads, and listener socket pointers.
- Moved accepted sockets from an isolated prototype toward device-owned
  lifecycle and teardown.

### 2024-04-04 through 2024-04-08 - Framing, connect, and retry foundations

- Moved the TCP encapsulation header into the shared socket interface, corrected
  lock types, expanded outbound connection creation, added peer retry state,
  and converted socket timeout handling to supported kernel interfaces.

### 2024-04-10 through 2024-04-15 - Per-peer queues and userspace round trip

- Added per-peer TCP send queues and locks, partial-record storage, cleanup
  work, connection-list iteration, and peer-associated socket state.
- Extended `wg` configuration parsing, display, Linux IPC, and container
  structures so transport selection survived the complete userspace path.

### 2024-04-17 through 2024-04-24 - Kernel configuration integration

- Continued generic-netlink, device, socket, and configuration integration,
  turning the carrier into a selectable device behavior rather than a
  hard-wired experiment.

### 2024-06-08 and 2024-06-20 - Peer and device state

- Added the peer- and device-side state required by the developing listener,
  retry, and stream paths.

### 2024-07-16 through 2024-07-23 - Listener/connect lifecycle

- Refined device startup, generic-netlink application, address reuse,
  IPv4/IPv6 listener selection, outbound connection placement, callback setup,
  and release ordering.

### 2024-07-26 through 2024-07-31 - Cleanup and callback reliability

- Stopped listeners during socket release, tightened port validation,
  strengthened state-change cleanup, added retry scheduling guards, and made
  keypair release more defensive.

### 2024-08-01 through 2024-08-07 - Locking, diagnostics, and transport selection

- Replaced early connection-list locking with RCU-oriented handling, expanded
  diagnostics, and removed the temporary hard-wiring of TCP.
- Defined the UDP/TCP transport selector and brought up both paths under an
  explicit device mode.

### 2024-08-11 through 2024-08-16 - Worker and callback ownership

- Reworked connection-list cleanup, packet queuing, listener callbacks, state
  tracking, read/write workers, callback safety flags, locking, and peer socket
  cleanup.

### 2024-08-17 through 2024-08-21 - Stream receive hardening

- Added handshake/cookie and packet diagnostics, then corrected null
  dereferences, partial reads, header synchronization, leftover SKB handling,
  callback user-data ownership, and UDP-header bypass for TCP records.

### 2024-08-22 through 2024-08-25 - Carrier promotion and endpoint ownership

- Iterated on encrypted-record diagnostics, framing lengths, accepted temporary
  peers, promotion, connection races, separate inbound/outbound callbacks,
  exact endpoint storage, retry cleanup, and source/destination tracking.
- The high commit density records active fault isolation and design
  exploration, not hundreds of releases.

### 2024-08-26 through 2024-08-31 - Port correctness and stabilization

- Removed temporary debug changes, stopped hard-wiring the TCP port, restored
  the configured port, synchronized the working TCP branch, and continued
  endpoint and socket cleanup.

### 2024-09-17 through 2024-09-24 - Parser and packet diagnostics

- Corrected pointer arithmetic, leftover-buffer handling, transfer locking, and
  kernel formatting.
- Added progressively structured TCP/IP packet decoding and disabled ECN for
  the experimental outer TCP carrier.

### 2025-01-28 through 2025-03-11 - Send/receive diagnostics and socket repair

- Expanded send and receive diagnostics, pointer visibility, device tracing,
  SKB inspection, and targeted receive/socket fixes.

### 2025-05-01 through 2025-05-22 - SKB tracing and worker experiments

- Added full SKB printouts and compile fixes, then experimented with receive and
  socket worker changes.

### 2025-06-10 through 2025-07-22 - Reverts and transfer-worker redesign

- Reverted the May receive/socket experiments, then reworked the transfer path
  to stop depending on the earlier worker arrangement.

### 2025-07-29 and 2025-08-26 - Fragmentation correctness

- Corrected conditional fragmentation-header length in
  [`dee4602`](https://github.com/jnathan/naked_gun/commit/dee4602c904c21689181da5c58ce6b8e63e8352b)
  and fragmentation-header detection in
  [`e66f421`](https://github.com/jnathan/naked_gun/commit/e66f4215b0970f9853c14d7629ac13b26210bcac).

### 2025-09-21 through 2025-09-30 - Queue and stream convergence

- Removed obsolete maximum-packet and write-queue remnants, renamed framing
  fields for clarity, and continued socket, receive, and format corrections.

### 2026-02-05 - Structured diagnostics and socket repair

- Added the TCP diagnostic framework and a concentrated sequence of memory,
  initialization, return-value, listener, and socket refactoring fixes.
- Ended the tranche with the temporary-peer prototype correction in
  [`51765a1`](https://github.com/jnathan/naked_gun/commit/51765a1cb4c28ab30595a676418b57cc75810b7f).

### 2026-03-08 - Listener, connect, latency, and relay fixes

- Corrected listener temporary-peer construction, the outbound connect
  completion check, and `TCP_NODELAY` on accepted and outbound sockets.
- Split verbose and diagnostic logging and added relay/node-agent development
  support. The relay and agent are operating infrastructure, not additions to
  the WireGuard-on-TCP wire format.

### 2026-03-09 - Rekey and buffered-read fixes

- Fixed handshake/rekey livelock and buffered-read starvation through
  pre-send drain/recheck sequencing and processing of already-buffered data in
  [`fe2fd51`](https://github.com/jnathan/naked_gun/commit/fe2fd5135dc168cc6d44bb7a76b831d7c38804f6),
  [`7f66568`](https://github.com/jnathan/naked_gun/commit/7f6656843900431953ed79db36efbdb9fe3f8c14),
  and
  [`def79f2`](https://github.com/jnathan/naked_gun/commit/def79f2144c6244a3a30f1d00ad7b25a2cfc1fcc).

### 2026-03-11 - Imported source tip

- Fixed module-removal deadlock and socket-callback use-after-free hazards in
  [`4211b00`](https://github.com/jnathan/naked_gun/commit/4211b00ef437f097ffd741145ec4379eb89bb031).
- This exact `tcp`-branch commit became the standalone repository's source
  snapshot on 2026-04-27.

### 2026-03-11 - Branch boundary

The repository's default `main` branch is not this lineage. Two socket-fix
batches added to `main` in February 2026 were immediately reverted as
wrong-branch changes. The `main`-only testing documents added in May 2026 also
postdate `4211b00`; none of those states is part of the imported snapshot.

### 2026-03-11 - Imported-tip feature inventory

The preserved source snapshot already contained the core WireguardTCP
implementation:

- Added a device-wide transport selection with UDP as the default and TCP as an
  explicit alternative.
- Extended the Linux WireGuard generic-netlink UAPI with a transport attribute.
- Extended the `wg` configuration parser and command line to accept transport
  selection.
- Retained WireGuard's existing Noise handshake, key rotation, replay
  protection, peer identities, `AllowedIPs`, and encrypted message formats.
- Added an 8-byte TCP encapsulation header carrying record length, type, flags,
  and a framing checksum.
- Added TCP listener sockets, outbound connection creation, accepted
  connections, socket callbacks, retry work, cleanup work, and per-peer stream
  state.
- Added temporary peers for accepted connections whose WireGuard identity was
  not yet known.
- Added TCP record parsing and synthetic receive metadata so decoded records
  could re-enter the normal WireGuard receive path.
- Added per-peer queues and workers for transmitting WireGuard messages over
  connected TCP sockets.
- Added diagnostic controls for verbose function tracing and TCP state
  reporting.
- Preserved a companion UDP socket and the existing UDP data path.
- Added source-era relay, node, and two-host tunnel notes used to compile,
  install, configure, and exercise the module.

Retained source notes identify four late fixes in the original branch:

1. Corrected TCP listener setup and listener operation.
2. Corrected temporary-peer creation and tracking for accepted sockets.
3. Corrected outbound TCP connection establishment.
4. Enabled `TCP_NODELAY` on accepted and outbound sockets to prevent Nagle and
   delayed-ACK interaction from adding avoidable latency.

## 2026-04-27 - Standalone source import

### `ffe7285` - Import cleaned WireGuardTCP source

- Imported the source snapshot into `secwest/WireguardTCP`.
- Removed the redundant full Linux kernel tree and retained the standalone
  WireGuard module, modified userland tools, UAPI headers, and source-era
  documentation.
- Established the current repository layout:
  - `kernel/` for the loadable WireGuard module;
  - `tools/` for the modified `wg` and `wg-quick` utilities;
  - `include/uapi/` for the transport-aware generic-netlink definitions; and
  - `docs/` for implementation and test-environment notes.
- Documented direct out-of-tree module and userland tool builds.
- Documented optional `WG_TCP_DIAG` and `WG_TCP_VERBOSE` builds.

## 2026-04-30 through 2026-05-03 - Application performance campaign

### 2026-04-30 - `b84c95a` adds the point-to-point performance harness

- Added the Azure point-to-point performance framework under `perf-test/`.
- Provisioned isolated x64 and arm64 VM pairs across LAN, medium, high, and
  maximum-latency region pairs.
- Configured matched TCP-WG and UDP-WG interfaces on every pair.
- Added short HTTPS, long TCP/UDP transfer, HTTP/2 web-mix, and interactive SSH
  workloads.
- Added carrier-loss matrices, repeated runs, result collection, aggregation,
  and report generation.
- Protected the transport-aware `wg` binary from distribution package
  replacement during image bootstrap.

### 2026-04-30 - Reporting and naming improvements

Commits `31c3822`, `9e28508`, `a1bfd46`, `517f241`, `e1e482a`, `fcf8196`,
`e530be4`, and `db18003`:

- Renamed the TCP test label from `tcp-fast` to `tcp-base`.
- Split summaries by application workload and latency tier.
- Promoted the campaign summary to `perf-test/REPORT.md`.
- Explained end-to-end application measurements, throughput columns, coverage,
  interpretation, and test caveats.
- Added periodic report regeneration for campaigns in progress.
- Added latency parsing for HTTP/2 results.

### 2026-04-30 through 2026-05-01 - Campaign completion and gap filling

Commits `5431d06`, the report-refresh series from `577c690` through `83de32a`,
and the focused gap-fill commits:

- Completed the 1,536-cell baseline matrix.
- Filled high-latency TCP-WG cells with `1d4b179`.
- Recovered region-pair identity from result-directory paths with `5e47404`.
- Added bounded request times and exponential retry backoff for high-latency
  arm64 runs with `bb3c2c4`.
- Closed the final six high-latency cells with `fd179f9`.
- Added tunnel reset and recovery support with `987476f`.
- Filled remaining high-latency HTTP/2 cells with `2c4c878`.

### 2026-05-01 through 2026-05-03 - Parser and harness bug fixes

Commits `d856cdf`, `f31faa5`, `0d0177b`, `9e7e9d4`, `880bbfb`, `e11aef3`, and
`78bc294`:

- Excluded failed `curl` requests from time-to-first-byte statistics.
- Suppressed request-rate output for cells in which every request failed.
- Preserved HTTP/2 timing data when a response was received with a non-2xx
  status.
- Replaced unsupported fractional `mpstat` sampling intervals.
- Added workload padding so CPU samples covered the intended web-mix window.
- Re-ran stale SSH cells after the sampler correction.
- Removed an incorrect HTTP `Host` override that caused HTTP 421 responses.
- Reparsed the stored campaign after each parser fix so published tables used
  consistent rules.

### 2026-05-03 - Campaign result

- Published a complete x64/arm64, TCP/UDP, workload, latency, and loss matrix.
- Recorded competitive clean-path TCP performance and strong delivery in
  selected synthetic-loss scenarios.
- Preserved raw campaign results and a reproducible reporting workflow.

## 2026-05-08 - Performance documentation maintenance

### `71bd166`, `a9e48cd`, and `4f31e2a`

- Corrected the quota-check documentation.
- Corrected the repository clone command and target directory.
- Removed obsolete `FAST` naming from performance documentation, scripts,
  matrices, and reports.

## 2026-07-11 - TCP socket lifetime fix

### `b1c40d9` - Fix TCP socket retirement lifetime

- Added peer-level write and cleanup mutexes to serialize TCP send and socket
  retirement ownership.
- Added read and write recheck flags so callbacks arriving while a worker was
  active were not lost.
- Changed peer teardown to cancel read and write workers synchronously.
- Cleared worker scheduling state under the corresponding locks.
- Serialized direct sends, callback reset, queue draining, and socket release.
- Ensured a retiring socket was quiesced before release and retired exactly
  once.

## 2026-07-11 - Review and architecture documentation

### `245774d` - Add combined WireGuard TCP patch

- Added `BIG-WireguardTCP-Patch`, a generated full-tree delta from the recorded
  stock WireGuard base.
- Made the complete module, UAPI, userland, documentation, and test delta
  reviewable as one patch.
- Regenerated the artifact after later source changes.

### `35c9110` - Document TCP transport design and performance findings

- Added the first comprehensive TCP transport design document.
- Documented transport selection, framing, listener and dialer operation,
  temporary peers, socket lifetime, endpoint handling, dual-stack behavior,
  diagnostics, and measured performance.
- Expanded the root README with user-facing configuration and architecture
  information.

## 2026-07-12 - Compatibility and full regression framework

### `f515eb5` - Complete TCP transport compatibility and regression coverage

- Added the Windows Hyper-V regression environment under `tests/hyperv/`.
- Added repeatable creation of two Ubuntu guests, isolated carrier paths,
  source transfer, module builds, module switching, test execution, log
  capture, and cleanup.
- Added guest scripts for bootstrap, builds, module selection, namespace
  topology, and node-level operations.
- Added Python source-contract tests for:
  - TCP lifecycle and ownership;
  - listener setup and teardown;
  - namespaces and socket marks;
  - listen-port behavior;
  - endpoint learning and roaming;
  - stream framing, queueing, parsing, and short writes;
  - UDP compatibility;
  - Hyper-V provisioning and runner contracts.
- Reworked kernel listener, dialer, peer, receive, send, netlink, cookie, and
  device paths to satisfy the shared compatibility model.
- Extended the modified userland tools, manual pages, and completion data.
- Added a cookie self-test and broader kernel/UAPI contract coverage.

## 2026-07-13 - Formal change tracking and mechanistic testing

### `7a1a647` - Add design and change logs

- Added the original root changelog and design log.
- Established the practice of recording architecture and user-visible behavior
  alongside substantive changes.

### `88b7173` - Add TCP meltdown investigation campaign

- Added a dedicated physical-carrier performance investigation under
  `perf-test/meltdown/`.
- Added HTB, finite FIFO, IFB, netem, random loss, and Gilbert-Elliott burst-loss
  shaping.
- Added endpoint, interface, socket, queue, and BPF event sampling.
- Added source, build, matrix, repetition, cell, and campaign fingerprints.
- Added a predeclared test plan and a fail-closed analyzer.
- Added source tests for campaign analysis.
- Integrated authenticated-carrier and stream-reader fixes before campaign
  execution.

### `7f8472d` - Fix TCP writer wakeups and qualify screening

- Fixed a lost-wakeup condition in the TCP write worker.
- Removed the pre-send `sk_stream_is_writeable()` gate.
- Allowed nonblocking `kernel_sendmsg()` to establish the kernel's normal
  `SOCK_NOSPACE` wakeup state.
- Added explicit write-space arming with the required memory barrier when a
  blocked or partial write was requeued.
- Preserved the exact unsent suffix of every partially written frame.
- Published completed clean calibration and finite-queue screening evidence.

### `c8853c7` - Harden TCP parity regression coverage

- Expanded transport-mode, lifecycle, listener, endpoint, and stream contracts.
- Strengthened guest and host assertions around module identity and cleanup.

### Screening and mechanism campaign series

Commits `0557140`, `518f1e1`, `ac66719`, `2b9513f`, `f62b150`, `23fc651`,
`458818b`, `4f0a879`, `38771f7`, and `c829c59`:

- Qualified clean calibration and initial finite-queue/RTT screening results.
- Added lower-rate, adaptive-queue, outer-recovery, and burst-recovery matrices.
- Committed test criteria before execution and results afterward.
- Refined burst-loss parameters and recovery gates from observed evidence.
- Preserved exact-cell reruns without replacing already-qualified cells.

### `8803e4d` - Add isolated TCP NAT44 regression coverage

- Added a private peer, isolated router namespace, and public peer topology.
- Added explicit SNAT and stable external DNAT port validation.
- Added keepalive, conntrack, source-port remap, reverse reconnect, and endpoint
  preservation checks.
- Confined forwarding, nftables, and conntrack mutation to disposable
  namespaces.

### Configuration persistence and hostile-stream validation

- Added canonical `Transport = tcp` output to `showconf`.
- Preserved transport state through `setconf`, `syncconf`, and `wg-quick`
  `SaveConfig`.
- Protected private configuration material in guest-only restricted
  directories.
- Added a separate fault-injection module build.
- Kept destructive `tcp_test_*` controls out of production and ordinary DEBUG
  modules.
- Added controlled short writes, malformed prefixes, parser
  resynchronization, queue pressure, writer delay, and recovery counters.
- Added one-command ownership of fault-module loading, testing, restoration, and
  result reporting.
- Verified post-test restoration to the production module.

## 2026-07-14 - Evidence integrity and complete parity hardening

### Burst and transport-aware campaign fixes

Commits `0cd7431`, `0a55dd9`, `f7a76b0`, `c49591c`, `0ceda3f`, `d986133`,
`7b61375`, `f81ea7f`, and `0b91c0f`:

- Published corrected burst-recovery evidence.
- Added physical endpoint-role validation before impairment.
- Rejected reversed controller and endpoint assignments.
- Replaced shared BPF summary counters with concurrency-safe per-CPU
  aggregation.
- Added monotonic event, layer, and CPU sequences so missing or duplicated BPF
  evidence was detectable.
- Added transport-aware clean controls and exact impairment validation.
- Added a fixed burst-breadth matrix and published its conclusions.
- Recorded 122 valid post-repair executions with no formal meltdown
  classification.

### `849d702` - Complete TCP parity and lifecycle hardening

- Consolidated lifecycle, listener, endpoint, network-notifier, and stream
  ownership fixes across the kernel module.
- Preserved UDP as the default transport.
- Preserved stock-facing UDP grammar, output, endpoint behavior, and random
  listen-port behavior.
- Required the TCP listener and companion UDP socket to share the selected
  numeric listen port.
- Separated configured peer listen ports from observed TCP source ports.
- Added monotonic accepted-connection identifiers for authenticated endpoint
  observations.
- Added deterministic public-key ordering for simultaneous Noise initiation.
- Routed endpoint, route, source-address, netdevice, uplink, and `FwMark`
  reconnects through serialized cleanup and retry ownership.
- Added bounded device-wide and per-source admission accounting for provisional
  accepted connections.
- Added independent IPv4 and IPv6 listener ownership.
- Preserved IPv6 scope information for link-local carriers.
- Serialized all frame output through one per-peer writer.
- Pinned the selected receive socket through parsing and delivery.
- Added right-sized leftover buffering and bounded parser resynchronization.
- Added `tests/tcp-parity-netns.sh` and expanded source contracts.

### Full functional regression

- Completed the 36-case two-VM Ubuntu campaign.
- Passed all stock/fork kernel and userland compatibility combinations.
- Passed UDP and TCP mode transitions, random ports, asymmetric ports,
  namespaces, IPv4, IPv6, scoped link-local carriers, full-tunnel routing,
  route and address changes, uplink migration, endpoint learning, keepalives,
  NAT44, and `FwMark` reconnects.
- Completed 36 PASS, 0 FAIL, 0 SKIP across 541 recorded commands.

## 2026-07-15 - Performance operating envelope and boundary tools

### `d24fa51` - Document TCP meltdown operating envelope

- Added `docs/TCP_MELTDOWN.md`.
- Summarized stable clean calibration and finite-queue/RTT controls.
- Documented the predeclared formal classification and the result of zero formal
  meltdown classifications across valid executions.
- Added exact contiguous stall export to the analyzer.

### `8e6b839`, `a46fa40`, and `92c1d52`

- Added a predeclared boundary campaign.
- Added timed impairment control.
- Added boundary correlation matrices and status reporting.
- Expanded analysis tests for the new timeline and boundary outputs.

## 2026-07-30 - Tool documentation and kernel cleanup

### `4467122` - Add transport configuration example

- Added a `Transport` example to the `wg-quick` manual.

### `cb7f218` - Normalize comments to kernel style

- Updated comments across kernel and userland sources to Linux kernel style.
- Improved consistency for review and maintenance without changing behavior.

### `8b2e3c7`, `c8d317c`, `d3fa877`, and `000a4ea`

- Removed stale and unnecessary forward declarations.
- Reordered local includes.
- Moved reusable socket prototypes into `socket.h`.
- Added the logical `allowedips.h` dependency where it is used.
- Removed unused receive, Noise, cookie, send, and socket code.
- Removed duplicate and incomplete structure definitions.
- Removed the redundant `wg_tcp_socket_list_entry` definition.
- Renamed send-path debug helpers for clarity.
- Corrected include ordering.

## 2026-07-30 - Linux libvirt regression environment

### `f17a419` and `8ab4b3c` - Add Linux libvirt regression harness

- Added `tests/linux/` as a Linux-native alternative to Hyper-V.
- Added root-owned libvirt network and domain provisioning.
- Added two Ubuntu guests with management and two isolated carrier networks.
- Added verified SSH host-key handling.
- Added exact Git-visible source snapshot transfer.
- Reused the Hyper-V guest build helpers and authoritative regression case list.
- Added Linux provisioner and runner contract tests.
- Added Linux and Windows regression instructions to the root README.

### `8c23126` and `ac7bfca` - Fix live Linux provisioning

- Added required libvirt DHCP and BIOS packages.
- Accepted canonical isolated-network XML emitted by libvirt.
- Selected legacy QEMU BIOS without an unsupported `virt-install` firmware
  descriptor.
- Added explicit SSH private-key support.
- Scoped Git safe-directory trust to the requested repository.
- Corrected results-directory ownership after privileged provisioning.
- Added Linux-specific preflight metadata.
- Completed live two-guest provisioning, production/DEBUG/fault module builds,
  and a full 36-case pass.

## 2026-07-30 - Regression contract repair and user documentation

### `cdc35c0` - Fix regression contracts and add user QuickStart

- Replaced source-contract section delimiters that depended on removed comments,
  declarations, and structure definitions.
- Switched the tests to stable function and preprocessor boundaries.
- Restored the complete 181-test source-contract suite.
- Added an end-to-end QuickStart covering prerequisites, compilation,
  installation, module loading, keys, a two-host tunnel, verification,
  troubleshooting, and advanced templates.

### `5151312` and `19bb88d`

- Moved `QUICKSTART.md` to the repository root.
- Added plain-language benefits, tested NAT and routing behavior, measured
  performance examples, and a six-step setup overview.

### `81b396e` - Document TCP mode performance advantages

- Added root `PERFORMANCE.md`.
- Consolidated clean-path, synthetic-loss, stable-control, and formal
  classification results.
- Explained carrier retransmission, persistent kernel connections, stateful
  firewall/NAT compatibility, and workload selection.

### `59d510d` - Remove obsolete performance cost estimate

- Removed the old campaign cost estimate.
- Removed active references and renumbered the performance campaign workflow.

## 2026-07-30 - TCP source modularization

### `a8ef645` - Separate TCP carrier and debug implementation

- Moved TCP-specific carrier code out of the generic socket and send sources
  into `kernel/wg_tcp.c` and `kernel/wg_tcp.h`.
- Moved most TCP diagnostic implementation into dedicated debug sources.
- Updated the kernel build and dependent device, peer, receive, timer, and
  header integration.
- Kept this as a source-organization change; it did not redefine the TCP record
  format or WireGuard cryptographic protocol.

## 2026-07-30 - Lifecycle and roaming groundwork

### `7f45beb` - Checkpoint expanded regression design

- Expanded TCP lifecycle, NAT, route/source-policy, and roaming documentation.
- Added repeatable TCP roaming and delayed-record regression scaffolding.
- Extended Hyper-V provisioning, runner diagnostics, and source contracts for
  the broader lifecycle matrix.
- Recorded this as groundwork rather than a claim that authenticated accepted
  carrier promotion or real single-device roaming was complete.

## 2026-07-31 - Single-NAT operation and authenticated carrier roaming

### Latest-tree integration

- Rebased the NAT work through WireguardTCP commit `a1f93da`, retaining the
  upstream TCP source split and the latest history, contract, prototype, and
  Linux image-verification changes.
- Migrated lifecycle, listener, namespace, port, framing, roaming, fault, and
  UDP-compatibility contracts to the split implementation.
- Added `kernel/wg_tcp_debug.o` to the relevant module builds and kept
  destructive fault controls restricted to the fault-injection variant.

### Accepted-carrier promotion

- Promoted an accepted provisional TCP socket to the configured WireGuard peer
  only after an authenticated WireGuard packet identifies that peer.
- Transferred the exact accepted tuple and callback ownership, then detached
  the provisional entry so only one owner can release the socket.
- Used device-monotonic connection identifiers to reject older carriers after a
  newer authenticated NAT mapping is observed.
- Added outbound authenticated bootstrap so a private peer can establish the
  tunnel without waiting for pre-existing inner traffic.
- Deferred bootstrap and accepted-carrier promotion to process-context workers.
  Promotion drains work, takes mutexes, and calls `synchronize_rcu()`, which is
  invalid in the receive NAPI/softirq path.
- Added a scheduler gate around promotion work so an authenticated observation
  arriving while the worker exits cannot be lost.
- Serialized stop, reconnect, callback reset, and exact-socket removal to
  prevent stale callbacks, double release, and cross-generation cleanup.

### Single-private NAT44 regression

- Added `tcp-nat44-single-private`, an isolated topology with one private peer
  behind SNAT and no DNAT or forwarded inbound port.
- Verified that only the private peer dials, the public peer replies over the
  promoted accepted carrier, keepalives preserve the mapping, and traffic is
  bidirectional.
- Replaced the NAT source port from `41001` to `41002`, flushed conntrack, and
  verified authenticated reacquisition, bidirectional recovery, and retirement
  of the old accepted carrier.

### Validation

- Passed all 209 local source and contract tests.
- Built the production module with `W=1` against the prepared WSL 6.6 tree.
- Built production, DEBUG, and fault-injection modules on both Hyper-V Ubuntu
  guests running `6.8.0-136-generic`.
- Final rebased Hyper-V run `wg20260731T070252Z` passed
  `tcp-nat44-single-private` on both guests with clean kernel logs. Acquisition
  completed within the case deadline on both guests; the same run passed DEBUG
  initialization self-tests.
- Final rebased Hyper-V run `wg20260731T070427Z` passed hostile-stream parsing, short-write,
  fatal-send, exact-target retirement, recovery, and production-module restore
  checks on both guests.
- Follow-up run `wg20260731T064611Z` kept clean kernel logs but failed three
  older dual-reachable tuple-direction assertions. Immediate bootstrap allows
  the public peer's valid outbound/DNAT carrier to win when both peers are
  reachable, while those tests require the private peer's `41001` SNAT carrier.
  This is an unresolved simultaneous-initiation policy/test expectation, not
  evidence against the outbound-only single-NAT result.

## Maintainer update policy

Add future entries chronologically. Include the date, commit hash, implemented
change, bug fix, affected subsystem, and validation result. Group generated
report refreshes and generated patch updates under the substantive change that
produced them.
