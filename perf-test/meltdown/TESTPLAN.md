# Test Plan - TCP-over-TCP Meltdown

## 1. Question

Does WireguardTCP enter classical TCP-over-TCP meltdown when congestion is
endogenous, and if so, at what queue, RTT, flow-count, and loss-recovery
boundary?

The stock UDP WireGuard mode from the same module is the control in every
scored cell. A result is about this implementation and build, not every TCP
tunnel.

## 2. Predeclared operational definition

The measurement window excludes iperf's configured warm-up. Inner delivery is
sampled at 100 ms from the selected tunnel interface's cumulative receive-byte
counter on the data receiver. This avoids treating iperf's synchronized
per-flow block-completion reports as zero-delivery intervals.

A run is **meltdown** only when all three conditions hold:

1. `stall_fraction_100ms >= 0.20`, where a stall bin has exactly zero inner
   bytes delivered;
2. `trend_drop_fraction <= -0.20` and the OLS slope t statistic is `<= -2.0`;
   the trend fraction is the fitted end-to-start change divided by mean
   goodput;
3. `inner_rto_per_flow_min >= 1.0`, measured by
   `tcp_retransmit_timer` and filtered to inner workload ports.

Classification is fixed before results:

| Class | Rule |
|---|---|
| `meltdown` | all three conditions |
| `near-meltdown` | exactly two conditions |
| `degraded` | exactly one condition, or TCP goodput is below 50% of its exact matched UDP control |
| `stable` | none of the conditions |
| `invalid` | workload or impairment validity checks fail |

The 20% thresholds require sustained rather than isolated stalls and decline.
The RTO floor requires at least one timeout per flow-minute, so a single event
does not condemn a high-concurrency run. The UDP comparison is applied only
when the same named repetition is valid for both transports.

## 3. Validity requirements

A cell is invalid rather than negative evidence if any of these apply:

- the default `strict` workload-completion policy sees a nonzero exit status,
  or fewer than 80% of expected 100 ms bins are present;
- a matrix that explicitly selects the prospective `interval_complete` policy
  lacks the exact requested connected-flow count, 99.5%-100.5% relative
  interval span and summed interval duration, at most a 20 ms interior interval
  gap, chronological non-duplicated intervals with at most 1 ms overlap and
  duration/boundary error, or 100% independent tunnel-interface delivery-bin
  coverage. Bidirectional workloads must independently satisfy every interval
  requirement for both `sum` and `sum_bidir_reverse`;
- an `interval_complete` workload emits stderr, has any exit status other than
  zero or one, lacks an explicit recorded exit status, or exits one for anything
  other than the allowlisted
  final-control errors `unable to receive results:` (optionally followed by
  `Connection reset by peer` or `Broken pipe`), the exact broken-pipe
  `unable to send control message` diagnostic, or
  `control socket has closed unexpectedly`;
- the selected tunnel did not pass a preflight ping;
- either expected TCP carrier tuple changed or disappeared, or 200 ms socket
  samples do not cover the complete workload interval;
- either endpoint sampler did not complete, BPF output lacks any of its six
  required summaries, a summary exceeds its detailed emitted-event count, or
  it trails that count by more than the one final event allowed at tracer
  shutdown. Prospectively, an attached-command marker anchors the absolute
  monotonic BPF cutoff only after every probe is attached; workload readiness
  requires that marker. Event probes stop one second before tracer exit so
  summaries run after a quiescent interval; the historical one-event allowance
  is not increased;
- the shaped class saw no packets;
- configured rate, delay, queue kind, queue bytes, loss model, or loss
  parameters do not match the manifest;
- a loss cell lacks monotonic IFB netem counters, processes no netem traffic,
  realizes no drops, or its measured loss is outside 0.5x-2x the model's
  stationary expectation;
- source, runtime build, common fixed-path endpoint iperf version and executable
  SHA-256, every selected restarted inner or competitor server process
  executable and hash, matrix-axis, repetition, cell, or campaign fingerprints
  do not match;
- controller host roles, physical addresses, or fixed local/peer TCP and UDP
  tunnel addresses do not match the declared server/client topology;
- a competing-flow cell lacks a successful, nonzero, sufficiently long
  competitor workload;
- qdisc restoration was not verified before result publication;
- endpoint clocks are not synchronized;
- a kernel warning/oops, host restart, or unrelated workload overlaps the run.

Queue overflow is reported separately from validity. A valid run with no
finite-queue drops shows that offered load did not reach the overflow regime;
it does not test the complete feedback loop.

The historical matrix fields `burst_h` and `burst_k` are passed directly as
netem's `1-H` and `1-K` arguments and are verified against those exact live
qdisc JSON keys. They are loss probabilities, not delivery probabilities.

`workload_completion` is opt-in. A missing field is `strict`, preserving all
historical validity decisions. `interval_complete` applies its flow, interval,
gap, delivery, and error checks to both matched transports. A zero exit status
still must satisfy the independent completeness checks. A nonzero status can
qualify only when every completeness check passes and the JSON error is in the
final-control allowlist. The JSON-reported client version must match the pinned
version, and stderr must be empty. Bidirectional runs validate and publish the
forward and reverse interval series independently. The analyzer publishes
policy, exit code, fallback use, error allowlisting, stderr state, version
match, connected/expected flows, interval count/span/sum, relative coverages,
maximum gap/overlap/duration error, ordering, and interface-delivery
completeness.

An exact-cell rerun remains a separate campaign when its source fingerprint
changes. A qualified composite may select it only when both source manifests
are complete, runtime module/tool identities and matrix axes match, the base
campaign explicitly attests its full non-targeted `matrix_expected_cells`, the
base cell is invalid, and the replacement is valid. Legacy bases without that
attestation are rejected. Current-format sources must also provide both iperf
identity fields. The original cell is never overwritten; the composite
records the source campaign and cell fingerprint for
every selected row, plus a SHA-256 of the selected analyzed cell document.

## 4. Bottleneck construction

Each carrier egress uses:

```text
HTB root
  test class: configured rate
    bfifo: explicit byte limit, or fq_codel with memory limit
  default class: unshaped control traffic

selective ingress
  IFB
    netem: half-RTT delay and optional random/burst loss
```

Only carrier traffic on UDP/51820, TCP/51821, and optional competing TCP/5202
enters the test class. At rate `R` Mbps and RTT `T` ms:

```text
BDP bytes = R * T * 125
queue bytes = BDP bytes * queue_bdp
```

Both endpoints receive half the emulated RTT. The physical same-VNet RTT is
recorded and remains additive. Queue depths are 0.5x, 1x, and 4x BDP.

For TCP, both peers have explicit static endpoints. This is the only static
cross-host topology supported by the current implementation because
authenticated promotion of an accepted provisional socket is deliberately
disabled. It normally creates two established outer streams, one initiated by
each peer. The harness records both streams and requires the count to remain
stable during every scored cell; responder-only topology failures are
implementation limitations, not meltdown evidence.

## 5. Measurements

Per endpoint:

- `tcp_retransmit_timer` RTO events split by inner and outer ports;
- `tcp_retransmit_skb` retransmission events split by layer;
- complete BPF status plus reconciled inner, outer, and competitor
  RTO/retransmission summaries, absolute capture cutoff, and one-second
  pre-summary quiescence;
- `ss -tinm` every 200 ms for cwnd, ssthresh, RTT, RTO, delivery rate, and
  socket queues, plus completion and full-window TCP carrier tuple stability;
- `tc -s -j qdisc/class/filter` every 200 ms;
- absolute `nstat -asz` and `/proc/net/{snmp,netstat}` before and after;
- `mpstat` each second, interface counters, kernel log, clock state, and
  module/build identity.

Per workload:

- 100 ms tunnel-interface delivery and goodput, with iperf goodput retained as
  a cross-check;
- workload-completion policy, fallback use, connected-flow count, relative
  interval span/sum, maximum interval gap, interface-delivery completeness,
  and common endpoint iperf version and executable hash;
- first/last-quartile goodput and fitted trend;
- stall fraction and longest zero-delivery run;
- inner and outer RTO/retransmission rates;
- finite-queue drops and overlimits, plus sampled peak backlog in bytes and as a
  fraction of the configured queue;
- expected, aggregate, and per-endpoint minimum/maximum realized netem loss;
- for short flows, p50/p95/p99/max completion time and failure rate.

## 6. Stages

1. `calibration`: clean matched TCP/UDP, one and 16 inner flows.
2. `queue`: 0.5x/1x/4x BDP at representative RTTs.
3. `boundary`: fine RTT sweep through 50-400 ms.
4. `mechanism-smoke`: 35 Mb/s, 200 ms, 0.25x BDP matched cells that must
   demonstrate finite-queue overflow before broader mechanism testing.
5. `adaptive-smoke`: after the 0.25x-BDP gate did not overflow, matched 35
   Mb/s/200 ms/0.10x-BDP cells. Both TCP repetitions must be valid and record
   finite-queue drops before a broader adaptive matrix is declared.
6. `adaptive-fallback`: matched 0.05x-BDP cells run only if the 0.10x-BDP gate
   does not produce drops in both TCP repetitions.
7. `recovery-smoke`: after the 0.10x-BDP gate overflowed without outer recovery,
   matched 35 Mb/s/200 ms/0.05x-BDP cells. Both TCP repetitions must be valid
   and overflow, and at least one must record an outer retransmission or RTO,
   before the `recovery` rows run.
8. `recovery`: matched 25 Mb/s/200 ms/0.05x-BDP, 35 Mb/s/400
   ms/0.05x-BDP, and competing-flow 35 Mb/s/200 ms/0.10x-BDP cells. These 12
   executions run only if `recovery-smoke` meets its outer-recovery gate.
9. `burst-smoke`: after the endogenous recovery gate failed, matched 50
   Mb/s/200 ms/1x-BDP cells with Gilbert-Elliott parameters `2/25/90/99`.
   The two TCP and two UDP executions must all be valid, including exact live
   loss-model verification on both endpoints, and at least one TCP execution
   must record an outer retransmission or RTO before broader burst testing.
10. `burst-recovery-smoke`: after `burst-smoke` failed preflight because
   `1-K=99%`, matched 50 Mb/s/200 ms/1x-BDP cells with `P=2%`, `R=25%`,
   `1-H=90%`, and `1-K=1%`. Nominal stationary loss is 7.59% per impaired
   direction. All four executions must be valid, including realized IFB loss
   within the predeclared 0.5x-2x band, and at least one TCP execution must
   record an outer retransmission or RTO before broader work.
11. `burst-qualified-smoke`: a separately fingerprinted exact four-execution
   rerun of `2/25/90/1` after the prior gate exposed final-control survivorship
   bias and tracer shutdown races. It explicitly selects
   `workload_completion=interval_complete`, fingerprints the identical
   endpoint iperf version, and uses the quiescent tracer cutoff. All four cells
   must be valid and at least one TCP execution must record an outer
   retransmission or RTO before broader work.
12. `mechanism`: matched 25/35 Mb/s, 200/400 ms, 0.25x/0.5x BDP cells. These
   original rows remain gated off by their failed 0.25x-BDP smoke.
13. `burst`: broader random-onset and Gilbert-Elliott severity cells declared
   only after `burst-qualified-smoke` meets its outer-recovery gate.
14. `endurance`: selected 10-minute clean/high-risk matched runs.
15. `dynamic`: clean-impaired-clean and 0/3% toggling epochs.
16. `workload`: short-flow FCT, bidirectional, CC sensitivity, reverse-only,
   jitter, AQM/ECN, and competing CUBIC.

Screening cells use 30-60 seconds and at least two repetitions. Key queue and
boundary cells use three repetitions. Endurance cells run 600 seconds.

## 7. Interpretation

Average outer throughput alone cannot establish meltdown. The claim requires
inner delivery, timer behavior, and temporal coupling. A robust result is:

- no full-meltdown classifications in high-risk finite-queue cells;
- bounded stalls and inner RTOs;
- no statistically significant downward trend in endurance runs;
- recovery to at least 90% of pre-impairment goodput after an epoch clears.

Conversely, phase-locked outer RTO spikes followed by inner RTO/cwnd collapse,
with increasing stall duration and declining goodput, are direct evidence of
the mechanism.
