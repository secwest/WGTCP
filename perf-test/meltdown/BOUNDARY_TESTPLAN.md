# Prospective TCP Meltdown Boundary and Mitigation Plan

Status: draft for review. No boundary, mitigation, or LTE-replay cell has run
under this plan.

This plan extends the completed campaign without changing its historical
definitions or rescoring its evidence. It is intended to answer:

1. How persistent must an adverse loss process be before a user-visible
   TCP-over-TCP episode begins?
2. How much packet-loss correlation is required at a fixed average loss rate?
3. What is the minimum inner TCP stream count associated with that episode?
4. What carrier capacity and offered-load ratio are associated with onset?
5. How much bandwidth is lost during the episode, and how long does recovery
   take after loss is removed?
6. Can a narrowly selected Linux TCP or queue setting reduce the impact without
   damaging clean-path throughput or causing premature connection failure?
7. After the laboratory boundary is known, do measured LTE traces enter that
   operating region often enough and for long enough to matter?

The completed results remain authoritative: no valid execution met the formal
three-part meltdown definition, clean finite-queue controls were stable, and
severe degradation was observed only in deliberately harsh conditions. This
new work maps the transition region; it must not assume that overloaded LTE is
the cause before LTE data are collected.

## 1. What "exact boundary" means

Loss and congestion recovery are stochastic. There may be no single universal
duration, stream count, or bitrate at which every repetition changes state.
The output will therefore be:

- the highest tested point with a low episode probability;
- the lowest tested point with a high episode probability;
- a transition interval and confidence bounds;
- any interactions that move that interval; and
- the exact tested kernel, host, transport, queue, RTT, workload, and loss
  model to which the interval applies.

For integer stream count, the campaign can identify the minimum tested count
meeting the predeclared probability rule. For time and bitrate, it will report
a bracket rather than false precision.

## 2. Preserve the existing classifications

The formal `stable`, `degraded`, `near-meltdown`, and `meltdown` definitions in
[`TESTPLAN.md`](TESTPLAN.md) remain unchanged and will be published for every
cell.

Timed clean-loss-clean cells also need an episode-level endpoint because a
connection can recover and therefore not have a declining full-run trend.
These additional labels do not replace formal classification:

| Endpoint | Predeclared rule |
|---|---|
| `mechanism_observed` | At least one outer retransmission or RTO occurs during the impairment or recovery window. |
| `user_visible_disruption` | At least one continuous zero-delivery run is 1 second or longer, or sustained recovery to 90% of baseline takes 5 seconds or longer. |
| `quasi_meltdown_episode` | `mechanism_observed`, a zero-delivery run of at least 1 second, and a 5-second rolling TCP delivery rate no greater than 50% of both its own pre-impairment rate and its valid matched UDP-transport control. |
| `formal_meltdown` | The unchanged full-run three-condition definition in `TESTPLAN.md`. |

All underlying continuous metrics will be published so readers can apply a
different application-specific latency threshold without rerunning a cell.

## 3. Cell timeline

Each dynamic cell uses one continuous inner TCP workload:

```text
iperf omitted warm-up: 10 s
clean measured baseline: 15 s
impaired epoch: D s
clean recovery observation: 60 s
```

The runner adds one unscored second after this window so command latency cannot
shorten the required 60 seconds of verified clean recovery. Recovery metrics
and right-censoring remain capped at the predeclared 60-second boundary.
Each transition must complete within 100 ms of its requested absolute time,
while the stricter inter-endpoint transition-skew bound remains 20 ms. Phase
metrics use the recorded qdisc change intervals rather than requested times.

The scored workload duration is therefore `75 + D` seconds after iperf's
omitted warm-up. Rate, RTT, finite queue, and selective traffic filters remain
installed during all three measured phases. Only the loss component changes at
the epoch boundaries. Clearing loss must not remove delay, rate limiting, or
the finite queue.

Both endpoints receive a common future wall-clock transition timestamp. A
root-owned helper applies the in-place netem change and records requested and
actual transition times in `impairment-events.jsonl`. A cell is invalid if:

- either endpoint misses a transition;
- actual start or stop skew between endpoints exceeds 20 ms;
- clock synchronization is unhealthy;
- the live qdisc before, during, or after the epoch differs from the matrix;
- loss counters do not show traffic and drops during a declared loss epoch;
- loss counters advance after the declared clean transition beyond the
  transition-race allowance fixed in the analyzer tests; or
- any existing workload, carrier, telemetry, identity, or restoration gate
  fails.

The epoch helper must modify only the already-owned IFB netem qdisc. It must not
replace an unknown qdisc or affect SSH/control traffic.

## 4. New measurements

In addition to all existing raw evidence and classifications, publish:

- pre-impairment median delivery rate;
- delivery rate during the complete impairment epoch;
- delivery in 0-1, 1-5, 5-10, 10-30, and 30-60 second post-clear windows;
- 1-second and 5-second rolling minimum goodput;
- TCP/UDP delivery ratio in each phase;
- absolute and fractional bandwidth deficit relative to pre-impairment rate;
- excess TCP deficit relative to the matched UDP-transport control;
- first delivered byte after loss clears;
- sustained recovery to 50%, 90%, and 95% of pre-impairment delivery;
- time to return below 5% stalled bins over a rolling 5-second window;
- integral of the post-clear delivery deficit in Mbit;
- zero-delivery run start/end times and boundary censoring;
- queue backlog, drops, outer cwnd, RTT/RTO, retransmissions, and inner RTOs
  aligned to both impairment transitions; and
- carrier closure/reconnect time if a mitigation deliberately permits abort.

`recovery_90_ms` is the primary recovery endpoint. It is the interval from the
recorded loss-clear transition to the first 5-second window whose delivery is
at least 90% of the pre-impairment median and whose stall fraction is at most
5%, provided the next 5 seconds also satisfy both conditions. A run that does
not recover within 60 seconds is right-censored at 60 seconds.

## 5. Reference condition

The initial boundary work holds the previously demonstrated lower-severity
profile constant except for the axis under study:

| Axis | Reference |
|---|---|
| Carrier | 50 Mb/s |
| RTT | 200 ms |
| Queue | 1x-BDP `bfifo` |
| Inner workload | Reverse-direction CUBIC bulk |
| Inner streams | 16 |
| Packet loss process | netem Gilbert-Elliott `P=1%`, `R=25%`, `1-H=90%`, `1-K=1%` |
| Nominal stationary loss | 4.42% per impaired direction |
| Mean bad-state residence | 4 packets |

One factor is varied at a time during screening. A later interaction stage
checks whether the resulting one-dimensional boundaries remain valid when
combined.

## 6. Staged matrix

Every profile is paired with the UDP WireGuard outer-transport control while
retaining the same inner TCP workload. Risk increases only after the lower
level completes without a safety stop.

### Stage 0: host and harness requalification

Before any impairment:

1. Re-establish key-only access to the two allocated ARM hosts after reboot.
2. Verify host identity, clock state, kernel, module and userspace hashes,
   loaded module, tunnel topology, two stable TCP carriers, baseline qdiscs,
   absence of IFB/marker/transient-unit residue, and no unrelated workload.
3. Inventory available congestion controls and every candidate sysctl. Record
   missing keys rather than creating or emulating them.
4. Rebuild and load one identical source tree on both hosts if reboot removed
   the test module.
5. Run matched clean 1-flow and 16-flow controls and require the established
   clean-path envelope before releasing Stage 1.

No new compute resource is required for this stage.

### Stage 1: transition-mechanism smoke

Run two TCP and two UDP repetitions with a 2-second reference loss epoch.
Require:

- both transitions within the skew limit;
- complete pre/during/post delivery coverage;
- exact qdisc and counter evidence;
- complete socket and BPF evidence;
- clean recovery observation; and
- verified restoration of all host state.

Failure stops the boundary campaign until the harness is corrected. Smoke
results cannot be promoted into the boundary estimate.

### Stage 2: packet-correlation boundary

This stage changes mean bad-state packet residence while holding nominal
stationary loss at 4.42%. The `P/R` ratio remains 0.04:

| Mean bad-state residence | P | R | 1-H | 1-K |
|---:|---:|---:|---:|---:|
| 1 packet | 4% | 100% | 90% | 1% |
| 2 packets | 2% | 50% | 90% | 1% |
| 4 packets | 1% | 25% | 90% | 1% |
| 8 packets | 0.5% | 12.5% | 90% | 1% |
| 16 packets | 0.25% | 6.25% | 90% | 1% |

Use a 16-second impaired epoch so packet correlation, not epoch truncation, is
the primary variable. Run three paired repetitions per point. If the transition
occurs between two levels, test intermediate residence values only when netem
can represent them exactly and the matrix is committed before execution.

This answers "how long is an error burst" in packet terms. It does not yet
answer how long the adverse regime must remain active.

### Stage 3: impaired-epoch duration boundary

Use the least severe packet-correlation point from Stage 2 that produces a
`quasi_meltdown_episode` in at least two of three valid TCP repetitions.

Coarse duration levels:

```text
0, 0.25, 0.5, 1, 2, 4, 8, 16 seconds
```

Run three paired repetitions per level. Once the highest low-probability and
lowest high-probability levels are known, predeclare midpoint levels until the
duration bracket is no wider than 250 ms or a 1.25 ratio, whichever is larger.

The 0-second profile is a dynamic-helper negative control and must produce no
loss counter delta or transition-related delivery deficit.

### Stage 4: minimum inner stream count

Hold the Stage 3 duration at the lowest high-probability point and sweep:

```text
1, 2, 4, 8, 12, 16, 24, 32 inner TCP streams
```

Stop escalation if clean-path CPU, memory, internal frame drops, or workload
identity gates fail. If onset lies between two tested integer counts, fill the
integer gap in a separately committed refinement matrix. The reported minimum
is the smallest count satisfying the probability rule, not the smallest count
that happened to fail once.

### Stage 5: carrier rate and offered-load boundary

Two different bandwidth questions must not be conflated.

#### 5A. Carrier-capacity sweep

Keep the queue at 1x BDP and sweep saturated aggregate inner load across:

```text
5, 10, 20, 35, 50, 75, 100 Mb/s carrier rates
```

Because queue bytes scale with rate and RTT, publish both bytes and packets.
This tests whether the failure depends on absolute packet rate or primarily on
dimensionless BDP and recovery dynamics.

#### 5B. Offered-load ratio sweep

At a fixed 50 Mb/s carrier, request aggregate inner rates of:

```text
25%, 50%, 75%, 90%, 100%, and 120% of carrier capacity
```

This arm is released only if the installed iperf binary supports TCP pacing and
a clean calibration delivers each requested aggregate rate within +/-5%
without changing stream count. If that capability gate fails, the arm remains
unrun; the campaign must not substitute a different shaper after observing
results.

Report requested rate, clean achieved rate, phase-specific delivered rate, and
the bandwidth deficit. "Minimum bitrate" refers to the clean achieved
aggregate load at the onset bracket, not merely the iperf command argument.

### Stage 6: interaction confirmation

One-factor boundaries can move when axes interact. Build a compact, separately
committed factorial around the negative and positive sides of:

- epoch duration;
- packet-correlation residence;
- stream count; and
- offered-load ratio or carrier rate.

Use no more than eight corner profiles, three paired repetitions each. If a
corner contradicts a one-factor boundary, report a response region rather than
continuing ad hoc searches.

### Stage 7: boundary confirmation

At the final negative and positive bracket points, run five valid paired
repetitions. Extend a point to at most 10 valid repetitions only when the first
five contain mixed episode outcomes.

Define:

- low probability: at most 20% episode-positive valid TCP runs;
- high probability: at least 80% episode-positive valid TCP runs;
- transition region: anything between those bounds.

Publish Wilson 95% intervals. Do not force a threshold when the final points
remain in the transition region. Each evidence-invalid cell has at most one
exact rerun in a separate immutable result directory.

## 7. Sysctl and queue mitigation arm

The mitigation question is separate from onset discovery. No sysctl changes
run until Stages 0-7 establish one below-boundary, one boundary, and one
above-boundary profile.

### 7.1 Safety and attribution

- Snapshot every candidate value on both endpoints before the campaign.
- Change only allowlisted keys that exist on both kernels.
- Verify the effective value before creating new outer carriers.
- Recreate both TCP carriers after settings that are inherited at socket
  creation.
- Change one setting family at a time.
- Restore and verify the exact snapshot after every cell, including failures.
- Stop on any restore discrepancy.
- Run a clean-path matched control for every profile.
- Reject a mitigation that reduces clean TCP goodput by more than 5%, increases
  clean p95 latency by more than 10%, causes carrier churn, or shifts loss into
  unreported internal queue drops.

Global sysctls are experimental controls here, not deployment
recommendations. If a global setting helps, prefer a later per-socket option in
WireguardTCP where Linux exposes one.

### 7.2 First-pass candidates

| Setting | Reason to test | Primary risk or limitation |
|---|---|---|
| `net.ipv4.tcp_congestion_control` | Compare the baseline CUBIC outer carrier with other algorithms already available on both hosts, especially BBR if present and correctly paced. | Applies to newly created sockets; algorithm availability and qdisc requirements vary. A different algorithm can trade fairness or latency for throughput. |
| `net.ipv4.tcp_notsent_lowat` | A lower unsent-data threshold may bound bytes trapped behind an outer loss and move backpressure closer to the WireguardTCP queue. | May increase wakeups, reduce throughput, or interact with the writer's `EAGAIN`/write-space contract. A per-socket `TCP_NOTSENT_LOWAT` would be preferable if useful. |
| `net.ipv4.tcp_limit_output_bytes` | Limits bytes queued from TCP toward the qdisc and may reduce local queue residence during recovery. | Too low can reduce clean high-BDP throughput and increase CPU overhead. |
| `net.ipv4.tcp_ecn` with `fq_codel ecn` | Tests whether early congestion signaling avoids queue overflow in overload-driven cells. | Does not repair random radio loss and requires an ECN-capable controlled path. It must not be mixed with the FIFO loss-onset arm. |
| `net.ipv4.tcp_slow_start_after_idle` | May affect ramp-up after a clean interval or blackout clears. | A saturated loss epoch is not necessarily TCP idle; disabling it can create a recovery burst. |

For numeric settings, first use the host default plus conservative values
derived from the observed socket queues and BDP. Exact candidate values will be
written into a committed matrix after Stage 0 inventory and before any
mitigation result is observed.

### 7.3 Inventory-only or later candidates

Record but do not change in the first pass:

- `net.ipv4.tcp_retries2`: reducing it may shorten a long outage by aborting the
  outer stream, but it converts recovery into reconnect and can discard
  in-flight records;
- keepalive sysctls: they do not govern an actively transmitting stalled
  stream;
- `net.ipv4.tcp_mtu_probing`: relevant to PMTU black holes, not the current
  loss mechanism;
- SACK, DSACK, timestamps, RACK/recovery, and reordering thresholds: changing
  them can create spurious retransmissions or disable established recovery
  mechanisms;
- global send/receive memory maxima: they are broad host controls, and a
  per-socket bound is preferable;
- `net.core.default_qdisc`: the harness explicitly owns the test qdisc, so this
  is not an attributable mitigation in the current topology.

`TCP_USER_TIMEOUT` is not a sysctl. It may be useful in a later
blackout/failover study, where the outcome is time to reconnect rather than
in-place recovery. It must not be presented as a throughput mitigation.

### 7.4 Mitigation decision rule

A setting is promising only if, relative to the exact default-setting pair, it:

1. lowers median `recovery_90_ms` or post-clear deficit by at least 25%;
2. does not increase the probability of a quasi-meltdown episode;
3. does not violate clean-path regression limits;
4. remains valid in at least five paired repetitions; and
5. improves both boundary and above-boundary profiles, not one isolated run.

## 8. LTE relevance and prevalence phase

Synthetic netem work establishes mechanism boundaries, not how often modern
networks cross them. LTE comparison begins only after the laboratory boundary
report is frozen.

### 8.1 Field data required

Prefer raw time series at 100 ms or finer for:

- downlink and uplink delivered bytes;
- RTT and jitter;
- packet loss or retransmission;
- outage start/end;
- handover and radio-state changes;
- RSRP, RSRQ, SINR, and available CQI/MCS;
- cell load where available; and
- modem, carrier, location class, time, and mobility state.

Public traces may supplement but not replace controlled captures unless their
sampling and loss semantics meet the replay requirements.

### 8.2 Replay

Convert an accepted trace into an immutable, timestamped impairment schedule.
Replay the same trace against TCP and UDP outer transports with identical inner
workload and repeat it at least five times. Keep synthetic and field-derived
results in separate inventories.

Report:

- fraction of trace time inside the laboratory transition region;
- count and duration of transition-region episodes;
- predicted versus replayed disruption;
- recovery distribution; and
- application-facing lost bandwidth and stall time.

Do not claim LTE prevalence from one carrier, one modem, one site, or one
outage.

### 8.3 Additional resources likely to help

The two allocated ARM hosts are sufficient for the synthetic boundary work.
For the field phase, request only after the lab bracket is known:

- two LTE/5G modems or tether-capable devices with timestamped radio metrics;
- SIMs and data allowance for at least two carriers;
- permission for stationary, loaded-cell, mobility/handover, and controlled
  outage captures;
- one stable public endpoint if neither allocated host can receive traffic from
  the modem path; and
- any existing anonymized LTE impairment traces with sub-second resolution.

No production user traffic or credentials should be captured.

## 9. Estimated execution size

The coarse plan is approximately:

| Stage | Maximum raw executions before boundary refinements |
|---|---:|
| Clean requalification | 8 |
| Transition smoke | 4 |
| Packet correlation | 30 |
| Epoch duration | 48 |
| Stream count | 48 |
| Carrier rate | 42 |
| Offered-load ratio | 36 |
| Interaction confirmation | 48 |

Boundary confirmation and mitigation repetitions are added only at selected
points. The expected total is roughly 200-300 executions, spread across
immutable staged campaigns rather than one long unreviewable run.

## 10. Deliverables and approval gates

1. **Plan approval:** review this file; no live impairment before approval.
2. **Harness review:** timed transition helper, matrix schema, analyzer metrics,
   sysctl snapshot/restore, and tests committed before deployment.
3. **Smoke report:** transition accuracy and fail-closed evidence reviewed
   before coarse sweeps.
4. **Boundary report:** duration, packet correlation, streams, rate/load,
   degradation, recovery, and confidence intervals frozen before mitigation.
5. **Mitigation report:** default-versus-candidate paired results with clean
   regressions and restoration proof.
6. **LTE resource request:** specify the smallest useful modem/trace resources
   based on the measured lab boundary.
7. **LTE replay report:** keep prevalence claims conditional on the captured
   carriers, locations, devices, and observation periods.

At every gate, incomplete, invalid, stopped, and unrun cells remain visible.
No threshold, validity rule, candidate sysctl, or retry allowance changes after
the corresponding results are inspected.
