# Changelog

All notable changes to this repository are documented here.

## Unreleased

### Added

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
- Added 100 ms receiver tunnel-interface sampling, layered BPF
  retransmission/RTO tracing, socket and qdisc sampling, clock normalization,
  carrier-tuple tracking, and cross-layer coupling metrics.
- Added predeclared meltdown classification and strict per-cell validity checks.
- Added fail-closed validation of the live netem random or Gilbert-Elliott loss
  model and its exact configured probabilities.
- Added source, runtime build, matrix-axis, repetition, cell, and campaign
  fingerprints so resumed evidence cannot cross implementation or test-plan
  boundaries.
- Added explicit socket-sampler completion records and six BPF event summaries.
  Summaries must not exceed emitted events and may trail by at most one final
  event racing tracer shutdown.
- Added focused analysis tests for BOM-prefixed JSON, diagnostic-prefixed iperf
  output, interface delivery, carrier stability, and matched UDP controls.
- Added lifecycle, roaming, and stream contracts for accepted-stream
  provenance, authenticated carrier deadlines, listener handoff, and buffered
  record draining.
- Added the interim investigation report and design decision log.
- Added compact reviewable evidence for the 14-cell clean calibration, 68-cell
  initial finite-queue/RTT screening, seven-cell qualification rerun, and final
  68-cell qualified composite, plus the 0.25x- and 0.10x-BDP mechanism smoke
  gates, the failed 0.05x-BDP outer-recovery gate, and its invalid-cell retry.
- Added a fail-closed campaign composite generator that requires complete source
  manifests, identical runtime identities and matrix axes, valid replacement
  evidence, and explicit per-cell source fingerprints.

### Changed

- Changed accepted TCP streams to carry stable nonzero IDs through asynchronous
  Noise handshake processing.
- Changed authenticated temporary receive carriers to use a 180-second
  activity-based idle deadline while retaining five-second idle, 30-second
  absolute, and 128-entry pre-authentication limits.
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
- Fixed concurrent BPF summary updates disagreeing with their emitted raw events.
- Completed 14/14 valid/stable clean calibration cells and all 68 initial
  screening executions. Seven exact-cell reruns replaced only the initial
  evidence-invalid repetitions, qualifying all 68 screening cells as stable
  with no degraded, near-meltdown, meltdown, or remaining invalid cells.
- Completed the four-cell 35 Mb/s/200 ms/0.25x-BDP mechanism smoke as
  valid/stable. It recorded zero queue drops and therefore correctly stopped
  the 12 broader mechanism rows at their predeclared overflow gate.

### Known limitations

- Most 50 Mb/s queue cells did not overflow because observed TCP delivery was
  about 47 Mb/s. Lower-rate/contention, burst, dynamics, workload, and endurance
  stages remain; no interim result should be presented as the final meltdown
  conclusion.
- At high concurrency the bounded internal writer queue can still reject new
  frames during sustained overload. This is distinct from the repaired stranded
  queue and must be reported separately from outer TCP meltdown.
- The earlier one-packet lag did not reproduce after recreating stale tunnels;
  its exact stale Noise/carrier trigger remains an endurance concern.
- TCP responder-only operation, automatic socket promotion, and automatic TCP
  roaming remain unsupported.
