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
- Added 100 ms receiver tunnel-interface sampling, layered BPF
  retransmission/RTO tracing, socket and qdisc sampling, clock normalization,
  carrier-tuple tracking, and cross-layer coupling metrics.
- Added predeclared meltdown classification and strict per-cell validity checks.
- Added source, runtime build, matrix-axis, repetition, cell, and campaign
  fingerprints so resumed evidence cannot cross implementation or test-plan
  boundaries.
- Added explicit socket-sampler completion records and six BPF event summaries
  whose RTO/retransmission counts must reconcile with emitted events.
- Added focused analysis tests for BOM-prefixed JSON, diagnostic-prefixed iperf
  output, interface delivery, carrier stability, and matched UDP controls.
- Added lifecycle, roaming, and stream contracts for accepted-stream
  provenance, authenticated carrier deadlines, listener handoff, and buffered
  record draining.
- Added the interim investigation report and design decision log.

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
- Changed framing resynchronization to retain a possible seven-byte split-header
  suffix for the ordinary reader instead of issuing a separate one-shot read.
- Changed orchestration to use pinned, identity-only workstation SSH with no
  host-to-host controller key.
- Updated the TCP transport design for authenticated temporary carriers and
  buffered-record drain ordering.

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

### Known limitations

- Fresh TCP tunnel setup can still exhibit a repeatable one-packet lag,
  approximately 104 ms RTT at 100 ms probe spacing, and final-packet loss.
- Current BPF evidence localizes that lag after successful decryption and
  endpoint reconstruction but before `napi_gro_receive()`; the exact rejecting
  branch is still under investigation.
- The endogenous impairment and endurance campaign remains gated on repeatable
  zero-loss, sub-millisecond clean TCP controls.
- No result collected so far proves or rules out classical TCP-over-TCP
  meltdown. Existing severe TCP results occurred without outer loss,
  retransmission, RTO, or recovery and are implementation-failure evidence.
- TCP responder-only operation, automatic socket promotion, and automatic TCP
  roaming remain unsupported.
