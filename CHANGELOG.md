# Changelog

This file records notable user-visible, operational, compatibility, and testing
changes. Update it in the same commit as every substantive change. Architectural
rationale belongs in `DESIGNLOG.md`; both logs should be updated when a change
affects design and externally visible behavior.

## Unreleased

### Added

- Added a prospectively isolated 30-cell packet-correlation replication with a
  fresh stage identity, fixed pair assignment, runtime-only package-maintenance
  isolation, terminal safety stops, and no reuse of frozen Stage 2 evidence.

- Added a dedicated `perf-test/meltdown/` campaign for mechanistic
  TCP-over-TCP meltdown testing.
- Added selective HTB plus finite-queue bottleneck construction, with IFB/netem
  propagation delay and optional loss isolated from SSH and control traffic.
- Added matched TCP and UDP WireGuard cells covering calibration, BDP queue
  depth, and RTT-boundary screening.
- Added a predeclared lower-rate mechanism matrix that gates broader testing on
  observed finite-queue overflow in matched 35 Mb/s/200 ms/0.25x-BDP smoke
  cells.
- Added a separately fingerprinted 0.10x-BDP adaptive smoke with a gated
  0.05x-BDP fallback after the 0.25x-BDP queue did not overflow.
- Added a 0.05x-BDP recovery smoke that gates lower-rate, higher-RTT, and
  contention rows on observed outer TCP retransmission or RTO.
- Added a matched Gilbert-Elliott burst-recovery smoke at 50 Mb/s, 200 ms, and
  1x BDP that gates broader burst testing on valid observed outer recovery.
- Added a separately fingerprinted corrected burst-recovery smoke with netem
  `P/R/1-H/1-K` parameters `2/25/90/1` after the original good-state loss made
  every preflight invalid.
- Added 100 ms receiver tunnel-interface sampling, layered BPF
  retransmission/RTO tracing, socket and qdisc sampling, clock normalization,
  carrier-tuple tracking, and cross-layer coupling metrics.
- Added predeclared meltdown classification and strict per-cell validity checks.
- Added fail-closed validation of the live netem random or Gilbert-Elliott loss
  model and its exact configured probabilities.
- Added realized-loss validation from monotonic IFB netem packet/drop counters,
  with a predeclared 0.5x-2x stationary-expectation band.
- Added source, runtime build, matrix-axis, repetition, cell, and campaign
  fingerprints so resumed evidence cannot cross implementation or test-plan
  boundaries.
- Added explicit socket-sampler completion records and six BPF event summaries.
  Summaries must not exceed emitted events and may trail by at most one final
  event racing tracer shutdown.
- Added focused analysis tests for BOM-prefixed JSON, diagnostic-prefixed iperf
  output, interface delivery, carrier stability, and matched UDP controls.
- Added lifecycle, roaming, and stream contracts for accepted-connection
  provenance, admission accounting, listener handoff, and buffered record
  draining.
- Added a Hyper-V-selectable symmetric passive TCP-carrier lifetime regression:
  both listeners are configured before concurrent endpoint activation, both use
  five-second keepalives, and exactly two authenticated carrier tuples must
  remain unchanged throughout 40 seconds.
- Added the investigation report and design decision log.
- Added compact reviewable evidence for the 14-cell clean calibration, 68-cell
  initial finite-queue/RTT screening, seven-cell qualification rerun, and final
  68-cell qualified composite, plus the 0.25x- and 0.10x-BDP mechanism smoke
  gates, the failed 0.05x-BDP outer-recovery gate and invalid-cell retry, and
  the four invalid preflight-only Gilbert-Elliott burst-smoke cells, corrected
  burst-recovery gate, exact invalid-cell rerun, bounded transport-aware gate,
  exact TCP replacement, and qualified four-cell composite.
- Added compact evidence for the complete 20-execution burst-breadth base, six
  exact invalid-cell reruns, the permanently stopped composite path, and a
  reproducible 162-execution inclusion/exclusion ledger.
- Added `docs/TCP_MELTDOWN.md` as a concise operating-envelope, stall-duration,
  and replication guide.
- Added `analyze.py stalls` to export every contiguous zero-delivery interval
  from a reproduced cell using the campaign's exact receiver and 100 ms
  alignment rules.
- Added a fail-closed campaign composite generator that requires complete source
  manifests, identical runtime identities and matrix axes, valid replacement
  evidence, and explicit per-cell source fingerprints.
- Added a multi-shard campaign compositor that preserves chronological valid,
  invalid, failed, stopped, and unrun records; permits one rerun only after
  invalid evidence; requires exact cell and pair fingerprints plus strictly
  newer hash-bound rerun timestamps; rejects cross-pair matched controls;
  separates raw from matched-control-adjusted classifications; validates typed
  result fields; rejects unmanifested cell evidence; latches analyzed and
  unanalyzed safety stops independently from outcomes and makes them terminal;
  rejects symlinks and special entries before hashing each source evidence tree;
  and binds external audit bundles without promoting an incomplete selection.
- Added compact timed-boundary evidence for the qualified transition smoke and
  the stopped 30-cell packet-correlation matrix, including 32 attempt records,
  23 selected valid logical cells, one unresolved control, and six unrun cells.
- Added an opt-in prospective interval-completion policy that can qualify only
  allowlisted final-control failures with exact flow count, near-full
  continuous interval output in every active direction, and complete
  independent interface delivery. Missing policy remains strict, so historical
  invalid evidence is unchanged.
- Added common endpoint iperf version fingerprinting, exact restarted-server
  process identity, and an attached-command BPF event cutoff with one second of
  pre-summary quiescence. The fixed iperf executable hash and JSON-reported
  client version are also reconciled.
- Replaced concurrent shared-scalar BPF event summaries with versioned per-CPU
  `count()` aggregation and exact raw/summary reconciliation while retaining
  historical trace semantics.
- Replaced the separate per-CPU aggregate for new evidence with monotonic
  event/layer/CPU sequences, making every missing or duplicated detail row
  directly detectable while retaining historical summary parsers. The final
  production-form live validation reconciled 957 rows across eight streams.
- Required explicit workload exit-status evidence and exact restarted process
  identity for both inner and selected competitor iperf servers.
- Added a pre-impairment endpoint-role check that binds physical and fixed
  tunnel addresses, preventing reversed controllers from running local iperf
  traffic.
- Marked targeted cell manifests as non-qualifying subsets and barred them from
  serving as qualified-composite bases. Composite bases now require explicit
  full-matrix attestation and complete iperf identity, without changing exact
  cell-fingerprint rerun semantics.
- Predeclared a separate four-execution `2/25/90/1` burst-qualified smoke using
  the prospective workload and tracing contracts.
- Predeclared one bounded transport-aware rerun at unchanged `2/25/90/1`
  severity. It adds a clean per-cell tunnel control, retains strict UDP
  RTT/loss bands and exact TCP impairment/counter checks, and measures
  post-loss TCP RTT amplification and adaptive realized loss as outcomes
  without rescoring historical evidence.
- Qualified the transport-aware burst gate with four valid cells and observed
  TCP outer recovery. The provenance-bound composite contains three degraded
  cells and one near-meltdown cell; neither TCP cell meets the full formal
  meltdown definition.
- Added the fixed 20-execution burst-breadth matrix released by that gate. It
  compares matched TCP/UDP independent loss, lower and higher stationary
  Gilbert-Elliott loss, longer bursts at the qualified stationary loss, and
  doubled RTT without changing the qualified center reference.
- Added a fingerprint-bound campaign safety latch. Clean-control acquisition
  and validation now finish before shaping, while shaping, restoration, kernel,
  and carrier safety failures stop the campaign and prevent that directory from
  being resumed or targeted.
- Made resume fail closed on campaign, selection, or cell-fingerprint drift and
  on any partial or mismatched local cell directory. Generated Python bytecode
  is excluded from source identity and deployment, so it cannot stale or
  overwrite completed evidence.

### Changed

- Calibrated user-facing meltdown wording: all clean finite-queue/RTT screening
  cells were stable, severe degradation appeared only in the deliberately
  extreme persistent-loss breadth envelope, and the unrun onset sweep prevents
  claiming an exact lower threshold or common modern-network prevalence.
- Changed accepted TCP streams to carry stable, device-local nonzero connection
  IDs through asynchronous Noise processing.
- Changed authenticated accepted carriers to release pre-authentication
  accounting and remain tracked until socket close or device teardown, while
  retaining the five-second idle, 30-second absolute, 128-entry device, and
  eight-entry per-source limits before authentication.
- Changed the TCP read worker to process complete buffered records before
  issuing another nonblocking receive and to reschedule bounded buffered work.
- Changed campaign delivery and stall scoring from iperf block-completion
  intervals to receiver tunnel-interface counters.
- Changed campaign analysis to report measurement-window sampled peak queue
  backlog in bytes and as a fraction of the configured byte limit.
- Changed the campaign topology to the implementation's supported
  dual-configured-endpoint mode and made both outer carrier tuples validity
  requirements.
- Changed TCP carrier validation to require complete 200 ms sampling coverage
  across the workload, rather than accepting isolated snapshots.
- Changed shaping cleanup to reject resources it does not own and verify exact
  qdisc restoration.
- Changed result publication to write `cell.json`, its fingerprint, and its
  completion marker only after verified shaping cleanup. Campaign aggregation
  now requires a complete manifest with every expected cell and fingerprint.
- Changed BPF collection to use a bounded traced child process, allowing END
  summaries to flush without accepting interrupted telemetry.
- Changed BPF RTO/retransmission summaries to use atomic map increments so
  concurrent CPUs cannot lose counter updates.
- Changed framing resynchronization to retain a possible seven-byte split-header
  suffix for the ordinary reader instead of issuing a separate one-shot read.
- Changed the TCP writer to drive nonblocking sends until empty, partial, or
  `EAGAIN`, then arm write-space notification for the retained exact frame.
- Changed orchestration to use pinned, identity-only workstation SSH with no
  host-to-host controller key.
- Changed orchestration to support exact `-Cell` reruns and extended sampler
  lifetime to cover ARM BPF attachment and high-RTT setup without replacing
  already-qualified cells.
- Updated the TCP transport design for authenticated temporary carriers and
  buffered-record drain ordering.
- Reconciled performance documentation with the completed mechanistic campaign,
  separating the 106-cell released selection, 162 raw executions, and the
  non-qualifying 20-cell breadth state.
- Froze the packet-correlation boundary at the prospective safety stop. The
  qualified 1/2/4-packet points produced 0/3, 1/3, and 0/3 quasi-meltdown
  episodes; the incomplete 8-packet and unrun 16-packet points do not support an
  onset threshold or release Stage 3.
- Removed plaintext VM passwords and private keys from legacy node
  documentation and its generated patch artifact.

### Fixed

- Fixed five-second rotation of an accepted stream after it had carried a valid
  Noise handshake.
- Fixed complete records being stranded in a bulk-read leftover buffer after a
  subsequent `recvmsg()` returned `EAGAIN`.
- Fixed campaign aggregation failures caused by UTF-8 BOM output.
- Fixed false multi-flow stall bins caused by synchronized iperf interval
  completion.
- Fixed measurement-window filtering and bidirectional inner-RTO normalization.
- Fixed workload-window qdisc accounting and forward-direction receiver
  selection.
- Fixed missing interface samples being interpreted as zero-delivery stalls.
- Fixed incomplete campaigns, header-only BPF traces, one-snapshot carrier
  captures, and stale resumed cells being accepted as negative meltdown
  evidence.
- Fixed competitor cells being accepted without successful, nonzero,
  sufficiently long competing traffic.
- Fixed resynchronization discarding a valid record header split across TCP
  reads while preserving captured-socket tuple reconstruction and exact
  leftover-buffer sizing from the parallel ARM lifetime work.
- Fixed qdisc time-series records being split across lines, shaped-queue
  accounting selecting the bypass queue, and samplers ending before the scored
  workload window.
- Fixed a TCP writer lost wakeup that stranded exactly 1,024 serialized frames
  under concurrent flows because a pre-send writeability gate prevented
  `EAGAIN` from arming `SOCK_NOSPACE`.
- Preserved the accepted-socket initialization handoff across the parity
  lifecycle integration so cleanup cannot free a temporary peer while the
  listener is still installing callbacks or inspecting queued data.
- Fixed concurrent BPF summary updates disagreeing with their emitted raw events.
- Completed 14/14 valid/stable clean calibration cells and all 68 initial
  screening executions. Seven exact-cell reruns replaced only the initial
  evidence-invalid repetitions, qualifying all 68 screening cells as stable
  with no degraded, near-meltdown, meltdown, or remaining invalid cells.
- Completed the four-cell 35 Mb/s/200 ms/0.25x-BDP mechanism smoke as
  valid/stable. It recorded zero queue drops and therefore correctly stopped
  the 12 broader mechanism rows at their predeclared overflow gate.
- Completed all 20 burst-breadth base executions and six exact reruns. The base
  has 14 valid and six invalid records; reruns add five valid and one remaining
  invalid record. No valid execution is formal meltdown.

### Known limitations

- The breadth phase demonstrates severe stalls, outer recovery, degradation,
  and near-meltdown behavior, but no valid execution satisfies all three formal
  conditions. AQM/ECN, dynamics, workload breadth, and endurance remain before
  any general resilience claim.
- The timed correlation study stopped after external unattended-upgrade service
  restarts consumed 8-packet UDP r3's only exact rerun. Residence 16 and all
  duration, stream-count, bandwidth, mitigation, and LTE replay stages remain
  unrun; no exact onset or modern-network prevalence claim is available.
- The latest parity/lifecycle integration passed contracts and matching ARM
  compilation but was not loaded for the recorded traffic campaign.
- At high concurrency the bounded internal writer queue can still reject new
  frames during sustained overload. This is distinct from the repaired stranded
  queue and must be reported separately from outer TCP meltdown.
- The earlier one-packet lag did not reproduce after recreating stale tunnels;
  its exact stale Noise/carrier trigger remains an endurance concern.
- TCP responder-only operation, automatic socket promotion, and automatic TCP
  roaming remain unsupported.

## 2026-07-14 parity validation

### Added

- Established project design and change logs as required release artifacts.
- Added complete TCP configuration round-trip coverage for `showconf`,
  `setconf`, `syncconf`, and a real `wg-quick` save/down/up reload, with all
  key-bearing files retained guest-locally at mode 0600.
- Added scoped link-local IPv6 endpoint, `showconf`, outer-carrier, and
  bidirectional tunnel validation.
- Added a separate `wireguard-fork-fault.ko` test artifact with root-only,
  DEBUG-gated controls and read-only counters for forced short writes,
  deterministic malformed prefixes, parser resynchronization, and queue
  pressure. Production and ordinary DEBUG artifacts reject those parameters.
- Added an isolated NAT44 namespace regression on both Hyper-V guests. It uses
  explicit SNAT, a differently numbered DNAT port, conntrack inspection,
  persistent-keepalive counters, and a forced translated-source-port change
  without modifying either guest's root firewall or forwarding state.

### Changed

- Refined the remaining roaming design around an atomic authenticated
  carrier-to-peer binding and promotion state machine instead of transferring
  temporary-peer state in place.
- Refined the TCP cookie design to require exact-carrier replies, MAC1
  validation before Noise work, cookie-response consumption, and a staged
  rollout before enforcing under-load MAC2 challenges.
- Moved fault-module load, test, and production restore into one guest-side
  command with `EXIT`/signal cleanup; the host requires an explicit restore
  acknowledgement from both guests.
- Made the writer-delay fault control one-shot so combining it with forced
  short writes cannot multiply the configured pause across suffix retries.
- Strengthened artifact reuse checks to compare live and saved `modinfo` and
  parameter manifests, recheck fault-parameter isolation, and validate the
  artifact manifest's kernel release.
- Defined carrier collision ordering around static-key direction preference
  and a future shared authenticated token; device-local connection IDs are
  only local locators and stale-work generations.

### Validated

- Passed 107 source contracts locally and in the final campaign preflight on
  both Ubuntu guests.
- Built production, ordinary DEBUG, and isolated fault-injection modules with
  kernel warnings enabled; `modinfo` verified fault-parameter isolation.
- Passed Hyper-V run `wg20260713T221904Z`: 35 PASS, 0 FAIL, 0 SKIP in
  452.476 seconds across 533 recorded commands with no kernel-log failures.
- On each guest, forced 80 short writes, injected and recovered from four
  malformed prefixes, forced more than 2,300 queue drops, and restored
  bidirectional traffic without stream corruption.
- Passed focused follow-up run `wg20260713T225629Z`: 2 PASS, 0 FAIL, 0 SKIP in
  134.149 seconds. Both guests completed a real `wg-quick` down/up reload; the
  one-shot hostile case recorded 80 short writes and four prefix recoveries on
  each guest, plus 434/441 queue drops, then acknowledged production-module
  restoration.
- Passed strengthened NAT44 run `wg20260714T005957Z`: 1 PASS, 0 FAIL, 0 SKIP
  in 57.867 seconds. Both guests carried bidirectional tunnel traffic through
  SNAT and DNAT, advanced keepalive counters while idle, recovered after the
  client mapping changed from port 41001 to 41002, and retained the configured
  forwarded dial port 52241. A live mark change then forced a reverse reconnect
  and each router observed a new SYN through that preserved forward.
- Passed final Hyper-V run `wg20260714T010310Z`: 36 PASS, 0 FAIL, 0 SKIP in
  558.520 seconds across 541 recorded commands with no kernel-log failures.
  The final isolated fault case restored the production module after recording
  80 short writes, four prefix recoveries, and 437/442 queue drops.

### Known limitations

- Authenticated carrier binding/promotion, ordinary responder-only NAT
  operation without a reverse port-forward, and deterministic stale-carrier
  retirement are not implemented. The passing NAT44 case requires a reachable
  configured endpoint in both directions.
- TCP handshakes still lack an enforced cookie-equivalent pre-authentication
  cost defense; accept caps do not prevent Noise CPU work.
- VRF and namespace move/teardown behavior, MTU accounting, physical-carrier
  loss, longer multi-flow soak, and broader kernel/topology coverage remain.

## 2026-07-13

### Added

- Added authenticated TCP dial-address learning while preserving the peer's
  configured remote listen port.
- Added route, address, netdevice, uplink, configured-endpoint, and live
  `FwMark` reconnect handling.
- Added independent IPv4 and IPv6 TCP listeners, IPv6 scope propagation, and
  runtime dual-stack coverage.
- Added deterministic simultaneous Noise-initiation role selection.
- Added device-wide and per-source provisional-accept caps, per-source
  throttling, authentication-aware accounting, and bounded deadlines.
- Added Hyper-V cases for asymmetric ports, configured migration, full-tunnel
  policy routing, live mark changes, route/source/uplink changes, IPv6, and a
  40-second authenticated carrier lifetime.

### Changed

- Kept UDP as the default, drop-in-compatible mode for the tested Linux stock
  and fork kernel/tool combinations.
- Separated configured TCP listen-port state from observed ephemeral source
  tuples and used stable accepted-connection IDs for authenticated observations.
- Routed reconnect requests through serialized cleanup and retry ownership.
- Serialized all TCP record writes through one bounded queue and write worker.
- Pinned one socket through each receive, resynchronization, synthetic-header,
  delivery, and requeue pass.
- Right-sized buffers retained for coalesced receive suffixes.
- Updated the README, TCP transport design, Hyper-V setup guide, and regression
  evidence with the implemented behavior and remaining parity boundaries.
- Narrowed the TCP-over-TCP performance language: real-world tests suggest
  meltdown may be a narrower condition than commonly expected, but do not prove
  general immunity.

### Fixed

- Fixed future reconnects continuing to use a stale authenticated peer address.
- Fixed accepted ephemeral TCP source ports being able to contaminate the
  configured dial target.
- Fixed live route, source-address, uplink, and `FwMark` changes leaving an
  established stream on obsolete network state.
- Fixed short-write handling so only the exact unsent record suffix is retried.
- Fixed parser lost-wakeup and buffered-record draining behavior.
- Fixed queue publication, callback, retry, removal, and device teardown races
  with explicit stop barriers and exact socket ownership.
- Fixed read-path use of a mutable peer socket by pinning the selected carrier.
- Fixed post-connect tuple caching so the kernel-selected source and ephemeral
  port are recorded after route selection.

### Validated

- Passed 89 source contract tests locally and on both Ubuntu guests.
- Built production and DEBUG modules and modified tools on Ubuntu 24.04 with
  Linux 6.8 and kernel build warnings enabled.
- Passed Hyper-V run `wg20260713T185138Z`: 32 PASS, 0 FAIL, 0 SKIP in
  376.109 seconds across 503 recorded commands.
- Passed all 16 stock/fork UDP kernel and tool combinations and every focused
  UDP/TCP compatibility and mobility case.
- Regenerated `BIG-WireguardTCP-Patch` and verified that applying it to stock
  WireGuard commit `edad0d6e99e5133b1e8e865d727a25fff6399cb4` reproduced the
  exact target Git tree, including symlink modes.

### Known limitations

- Authenticated accepted-socket promotion and general responder-only or NAT
  ephemeral-port roaming are not implemented.
- TCP handshakes still lack a cookie-equivalent pre-authentication cost defense.
- Hostile forced short-write, parser-resynchronization, malformed-stream, and
  queue-exhaustion runtime campaigns remain pending.
- Complete `showconf`, `setconf`, `syncconf`, and `wg-quick SaveConfig` round
  trips remain pending.
- Link-local IPv6, VRF, namespace-move, longer soak, and broader kernel and
  topology validation remain pending.
