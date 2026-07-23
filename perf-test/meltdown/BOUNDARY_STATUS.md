# TCP Meltdown Boundary Strategy and Results

## Executive summary

WireguardTCP can show severe TCP-over-TCP degradation under deliberately harsh
laboratory conditions, but the completed evidence does not show a valid formal
meltdown and does not establish that these conditions are common on modern
networks.

The historical post-repair audit contains 162 raw executions:

- 122 valid: 92 stable, 17 degraded, and 13 near-meltdown;
- zero valid formal-meltdown executions; and
- 40 evidence-invalid executions that are retained but never promoted.

The new boundary campaign was designed to locate the onset region rather than
assume one. Its timed smoke stage completed valid/stable and measured a clear
TCP recovery penalty. Stage 2 then qualified the 1-, 2-, and 4-packet
correlation points, reached the 8-packet point, and safety-stopped before that
point could qualify. Residence 16 was not run.

Qualified TCP quasi-meltdown counts were 0/3 at one packet, 1/3 at two packets,
and 0/3 at four packets. Eight packets has only two valid matched pairs; its
third UDP control consumed its one exact rerun during external package-service
interference. The prospective two-of-three onset rule was not met at any
qualified point. Stage 2 therefore establishes no defensible correlation onset
threshold and does not release Stage 3.

## Questions the campaign will answer

1. How correlated must packet loss be before a disruptive TCP-over-TCP episode
   becomes likely?
2. How long must that adverse loss regime persist?
3. What is the minimum inner TCP stream count associated with onset?
4. What carrier capacity and achieved offered load are associated with onset?
5. How much bandwidth is lost during the episode?
6. How long does delivery take to recover after loss is removed?
7. Can a narrowly selected Linux TCP or queue control reduce the impact without
   harming clean-path performance?
8. After the laboratory boundary is frozen, how often do qualified LTE traces
   actually enter that region?

Because loss recovery is stochastic, the intended result is a probability
bracket, not a single universal threshold. The campaign will report the highest
tested low-probability point, the lowest tested high-probability point, Wilson
95% intervals, and the exact environment to which those results apply.

## Outcome definitions

Historical classifications remain unchanged:

| Outcome | Rule |
|---|---|
| Formal meltdown | At least 20% zero-delivery 100 ms bins, at least a 20% significant fitted decline with slope t-statistic at most -2, and at least one inner RTO per flow-minute. |
| Near-meltdown | Two of the three formal-meltdown conditions. |
| Degraded | Exactly one formal condition, or TCP goodput below 50% of its exact matched UDP control. |
| Stable | Valid evidence without the degraded, near-meltdown, or meltdown conditions. |

Timed clean-loss-clean cells also publish episode-level endpoints:

| Endpoint | Rule |
|---|---|
| `mechanism_observed` | At least one outer retransmission or RTO during impairment or recovery. |
| `user_visible_disruption` | A continuous delivery stall of at least one second, or sustained recovery to 90% of baseline taking at least five seconds. |
| `quasi_meltdown_episode` | Outer recovery is observed, at least one continuous one-second stall occurs, and the minimum rolling five-second TCP delivery is at most 50% of both its own baseline and its valid matched UDP control. |
| `recovery_90_ms` | Time from actual loss clear to the first qualifying five-second window at least 90% of baseline with at most 5% stalled bins, provided the following five seconds also qualify. |

These episode labels supplement the formal whole-run classification; they do
not rescore historical evidence.

## Experimental design

### Matched topology

- Two private-only ARM VM pairs are available:
  `wgtcp-amp-b/a` and `wgtcp-boundary-b/a`.
- Both pairs use `Standard_D4ps_v5` hosts and kernel `6.8.0-1062-azure`.
- Both pairs run the same proven campaign runtime:
  - traffic-runtime source commit `2b9513f`;
  - timed-harness source commit `a46fa40`;
  - module srcversion `01DA86291E0FBD2CD3C940C`;
  - module SHA-256
    `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`;
  - WireGuard tool SHA-256
    `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`;
  - iperf SHA-256
    `626565d9571f0ebb9148a36944beeaafa9b7581884f11c11b7fd1cf4218f5ad4`.
- Every profile uses the same inner TCP workload over both TCP and UDP
  WireGuard outer transports.
- A matched TCP/UDP repetition stays on the same VM pair. The second pair
  increases throughput without mixing different hardware into one matched
  comparison.

### Reference condition

Unless a stage varies one of these axes, the campaign holds constant:

| Axis | Reference |
|---|---|
| Carrier rate | 50 Mb/s |
| RTT | 200 ms |
| Queue | 1x-BDP `bfifo` |
| Inner workload | Saturated reverse-direction CUBIC |
| Inner streams | 16 |
| Loss process | netem Gilbert-Elliott `P=1%`, `R=25%`, `1-H=90%`, `1-K=1%` |
| Nominal stationary loss | 4.42% per impaired direction |
| Mean bad-state residence | 4 packets |

This is an intentionally adverse synthetic condition. It combines sustained
load, high RTT, a finite queue, and correlated loss. It establishes a mechanism
boundary; it does not by itself establish prevalence on LTE or any other field
network.

### Timed cell

Each dynamic execution uses:

```text
iperf omitted warm-up:       10 s
clean measured baseline:     15 s
impaired epoch:               D s
clean recovery observation:  60 s
unscored command guard:        1 s
```

Both endpoints receive a common absolute transition time. Analysis uses the
recorded qdisc-change intervals, not the requested times.

### Fail-closed evidence

An execution is invalid if any required identity, workload, timing, impairment,
telemetry, or restoration evidence is missing or inconsistent. Important gates
include:

- transition completion within 100 ms of the requested time;
- conservative inter-endpoint transition skew no greater than 20 ms;
- healthy clocks and recorded conservative clock-error bounds;
- dense qdisc evidence before, during, and after the loss epoch;
- exact netem configuration and advancing loss counters during impairment;
- no advancing loss counter after clear beyond the fixed race allowance;
- complete receiver delivery, socket, interface, queue, and BPF coverage;
- two unchanged TCP carrier tuples throughout the execution; and
- exact restoration of baseline qdiscs with no IFB or impairment-marker residue.

Evidence-invalid executions remain visible and receive only the bounded exact
rerun allowed by the prospective plan.

## Staged strategy

| Stage | Purpose | Design | State |
|---|---|---|---|
| 0. Host requalification | Establish identical, clean test pairs. | Runtime identity, clocks, qdiscs, carriers, and clean 1/16-flow TCP/UDP controls. | Complete |
| 1. Transition smoke | Qualify absolute timing and clean-loss-clean evidence. | Two TCP and two UDP repetitions with a two-second reference epoch. | Complete and passed |
| 2. Packet correlation | Find the least correlated loss process that can produce a quasi-meltdown episode. | Mean bad-state residence of 1, 2, 4, 8, and 16 packets; 16-second epoch; three paired repetitions per point. | Stopped incomplete at 8 packets; no onset threshold |
| 3. Epoch duration | Bracket how long the adverse regime must persist. | 0, 0.25, 0.5, 1, 2, 4, 8, and 16 seconds, then prospective midpoint refinement. | Not released |
| 4. Stream count | Find the minimum tested inner-stream count meeting the high-probability rule. | 1, 2, 4, 8, 12, 16, 24, and 32 streams, with integer refinement if needed. | Not run |
| 5A. Carrier rate | Separate absolute packet-rate effects from BDP-scaled behavior. | 5, 10, 20, 35, 50, 75, and 100 Mb/s with a 1x-BDP queue. | Not run |
| 5B. Offered load | Find the achieved load ratio associated with onset. | 25%, 50%, 75%, 90%, 100%, and 120% of a 50 Mb/s carrier, gated on pacing calibration. | Not run |
| 6. Interactions | Check whether one-factor boundaries move when combined. | No more than eight prospectively committed corner profiles. | Not run |
| 7. Confirmation | Estimate outcome probability at the final negative and positive brackets. | Five valid pairs per point, extended to at most ten only for mixed outcomes. | Not run |
| Mitigation | Measure selected TCP/sysctl/qdisc controls after the boundary is frozen. | Default-versus-candidate matched runs with clean-path regression limits. | Not run |
| LTE qualification/replay | Evaluate field relevance without extrapolating from synthetic loss. | Qualified sub-second traces or controlled modem captures, then matched TCP/UDP replay. | Not run |

Low probability is predeclared as at most 20% episode-positive valid TCP runs;
high probability is at least 80%. Mixed results remain a transition region
rather than being forced into a threshold.

## Results so far

### Historical campaign

The complete post-repair audit contains:

| Inventory | Total | Valid | Stable | Degraded | Near-meltdown | Meltdown | Invalid |
|---|---:|---:|---:|---:|---:|---:|---:|
| All post-repair raw executions | 162 | 122 | 92 | 17 | 13 | 0 | 40 |

Clean finite-queue controls were stable. The lowest demonstrated severe
reference was 50 Mb/s, 200 ms RTT, a 1x-BDP FIFO, 16 reverse CUBIC streams, and
the `1/25/90/1` Gilbert-Elliott process. Across nine valid logical TCP breadth
cells, longest continuous zero-delivery runs ranged from 0.7 to 40.2 seconds
with a 6.3-second median. No valid execution simultaneously met the stall,
declining-goodput, and inner-RTO requirements for formal meltdown.

These results establish that severe degradation is possible in a deliberately
extreme corner. They do not yet identify the lower onset boundary or show how
often real networks enter it.

### Stage 0: host requalification

Both VM pairs reproduced the same runtime hashes and module srcversion. They
were clean, synchronized, free of IFB/impairment residue, and maintained two
TCP carriers per endpoint.

Unshaped clean-path sanity checks were closely matched:

| Outer transport | Inner flows | Original pair | Secondary pair |
|---|---:|---:|---:|
| TCP | 1 | 2,151 Mb/s | 2,197 Mb/s |
| TCP | 16 | 2,926 Mb/s | 3,064 Mb/s |
| UDP | 1 | 4,232 Mb/s | 4,251 Mb/s |
| UDP | 16 | 3,713 Mb/s | 3,824 Mb/s |

These are host-capacity checks, not shaped boundary results. Both pairs have
ample headroom above the 50 Mb/s test carrier.

### Stage 1: timed transition smoke

All four executions were valid/stable:

| Execution | Pair | Impaired mean | Longest stall | Recovery to 90% | Deficit | Outer recovery | Episode result |
|---|---|---:|---:|---:|---:|---:|---|
| TCP r1 | Original | 31.400 Mb/s | 0.4 s | 14.049 s | 520.605 Mbit | 26 | mechanism and user-visible recovery delay; no quasi-meltdown |
| UDP r1 | Original | 42.392 Mb/s | 0 s | 4.148 s | 122.839 Mbit | 0 | no disruption endpoint |
| TCP r2 | Secondary | 44.784 Mb/s | 0.2 s | 9.848 s | 175.833 Mbit | 32 | mechanism and user-visible recovery delay; no quasi-meltdown |
| UDP r2 | Secondary | 41.035 Mb/s | 0 s | 4.748 s | 154.911 Mbit | 0 | no disruption endpoint |

Other smoke gates:

- actual loss epochs were 1.990-1.996 seconds;
- maximum transition skew was 9.564 ms;
- maximum conservative clock-error bound was 0.032 ms;
- delivery coverage was complete;
- both TCP carriers remained present with unchanged tuples; and
- all four hosts restored their baseline `mq`/`fq_codel` state.

The TCP executions recovered 2.07-3.39 times more slowly than their matched UDP
controls. That is a measurable transient TCP-over-TCP penalty, but neither TCP
execution had the required one-second stall, and neither was a quasi-meltdown
or formal meltdown.

Compact smoke evidence is in
[`results/2026-07-16-boundary-stage1-smoke/`](results/2026-07-16-boundary-stage1-smoke/).

### Stage 2: packet-correlation boundary

The frozen logical and raw inventories are:

| Inventory | Planned | Reached | Selected valid | Invalid raw | Stopped | Unrun |
|---|---:|---:|---:|---:|---:|---:|
| Stage 2 | 30 | 24 | 23 | 8 | 1 | 6 |

There were 31 analyzable executions: 23 valid and eight invalid. Seven invalid
cells received one successful exact rerun. The eighth, 8-packet UDP r3,
safety-stopped during its sole exact rerun and remains unresolved.

| Mean bad-state residence | Selected valid | Matched pairs | Qualified TCP quasi episodes | Formal meltdown | State |
|---:|---:|---:|---:|---:|---|
| 1 packet | 6/6 | 3/3 | 0/3 | 0 | Qualified |
| 2 packets | 6/6 | 3/3 | 1/3 | 0 | Qualified; below onset rule |
| 4 packets | 6/6 | 3/3 | 0/3 | 0 | Qualified |
| 8 packets | 5/6 | 2/3 | 0/2 | 0 | Incomplete |
| 16 packets | 0/6 | 0/3 | N/A | 0 | Unrun |

The sole episode-positive execution was 2-packet TCP r2: a 1.8-second stall,
0.139 Mb/s minimum five-second delivery versus 4.605 Mb/s for UDP, 162 outer
recovery events, and 11.551-second recovery to 90%. The other TCP stalls were:

- 0.2-0.3 seconds at one packet;
- 0.3 and 0.8 seconds in the other two-packet repetitions;
- 0.3-0.7 seconds at four packets; and
- 0.4/0.7 seconds in the two qualified eight-packet pairs.

The valid eight-packet TCP r3 replacement stalled for 1.4 seconds, reached a
1.996 Mb/s minimum five-second delivery rate, recorded 126 outer-recovery
events, and recovered in 12.451 seconds. Its matched UDP r3 control is
unresolved, so it cannot receive a qualified quasi-meltdown label.

The safety stop was caused by Ubuntu `apt-daily-upgrade`, which began at
06:59:59 UTC and restarted the active Python impairment helper and sampler at
07:01:12 UTC after upgrading Python. The helper correctly rejected its
now-past absolute schedule. Partial endpoint evidence, systemd/package journals,
and the post-stop four-host validation are hash-bound in the compact provenance.
All four hosts then passed exact runtime and cleanup checks, retained two
carriers each, and delivered 40/40 TCP plus 40/40 UDP probes without loss.

Compact evidence is in
[`results/2026-07-16-boundary-stage2-correlation/`](results/2026-07-16-boundary-stage2-correlation/).

## Frozen disposition

The prospective retry budget is exhausted for UDP r3. No additional retry,
8-packet repair, 16-packet execution, or Stage 3 duration work may be added to
this frozen selection. A future independent replication would require a new
prospective plan and package-maintenance isolation; it cannot retroactively
repair or extend this Stage 2 estimate.

## Independent replications

On 2026-07-19 the four matched ARM endpoints were reallocated to complete a
fresh correlation study. The frozen result above remains unchanged. The new
campaign uses a distinct stage identity and a complete 30-cell matrix, disables
package-maintenance triggers for the bounded test window, and starts from no
historical cell evidence. Its prospective rules and exact matrix are:

- [`BOUNDARY_REPLICATION_TESTPLAN.md`](BOUNDARY_REPLICATION_TESTPLAN.md)
- [`matrix-boundary-correlation-replication.csv`](matrix-boundary-correlation-replication.csv)

The replication must qualify independently before it can release Stage 3.

That replication separately safety-stopped on 2026-07-20 during its
eight-packet UDP r3 cell. The cell's workload, carrier, loss, delivery, and
recovery evidence completed, but its conservative impairment-start skew was
44.49 ms, above the fixed 20 ms maximum. Its 23 selected valid/stable cells,
six interval-duration-invalid attempts, and stopped raw cell are retained
without pooling into the earlier frozen selection. Residence 16 was not run;
the replication does not establish an onset threshold or release Stage 3.

On 2026-07-21, a third, independently predeclared full replication was
authorized. It uses a new stage identity while preserving the 30-cell matrix,
all outcome definitions, the 20 ms transition bound, and terminal safety-stop
rule. The time-critical impairment process now uses an absolute
`clock_nanosleep` deadline and a short-lived `SCHED_FIFO` priority-50 systemd
unit; this strengthens deadline delivery without weakening timing evidence.
Its prospective protocol and matrix are:

- [`BOUNDARY_RT_REPLICATION_TESTPLAN.md`](BOUNDARY_RT_REPLICATION_TESTPLAN.md)
- [`matrix-boundary-correlation-replication-rt.csv`](matrix-boundary-correlation-replication-rt.csv)

That replication safety-stopped during preflight before any workload or impairment
cell ran. The secondary pair met all runtime, maintenance, tunnel, clock, qdisc,
carrier, and priority-50 `SCHED_FIFO` qualifications. The primary pair retained
two carriers but one carrier's source tuple reconnected about every 30 seconds,
preventing the required 80 consecutive unchanged 500 ms samples within the
120-second qualification window. The original FIFO probe's shell-PID quoting
defect and an immediately post-install `apt-get` observation were retained as
invalid preflight attempts; neither is used to relax the fixed gate. After the
corrected probe, all four endpoints demonstrated priority-50 `SCHED_FIFO`;
the primary carrier tuple failure is the terminal safety latch. No third-
replication cell evidence exists, all four endpoints were restored to baseline
qdiscs and deallocated, and any future execution requires another independent
prospectively predeclared replication.

On 2026-07-22, a separate no-netem primary-pair diagnostic repeated passive,
synchronized two-carrier activation four times. Every endpoint recording reached
the full 80 unchanged 500 ms samples (40 seconds) with exactly two carriers;
no WireGuard kernel warning or error was recorded. This shows that the earlier
tuple churn is intermittent rather than a reproducible 30-second timeout. It
does not reopen or repair the terminal third replication, and it does not
justify changing the unauthenticated-carrier lifetime bound. The primary
endpoints and forwarding gateway were deallocated after the capture.

A matching namespace regression, `symmetric-carrier-lifetime`, configures both
listeners before concurrent endpoint activation, sets keepalive to five seconds
on both peers, and checks the exact two-carrier set continuously for 40 seconds.
It passed once on each primary ARM endpoint under the exact qualified runtime;
the temporary test namespaces were removed before the hosts were deallocated.
The strengthened asymmetric `carrier-lifetime` regression, which now performs
the same continuous exact-two-carrier check, also passed once on each endpoint.

On 2026-07-22, a fourth independent correlation replication was authorized. It
has a distinct stage identity and immutable 30-cell matrix while retaining the
unchanged 20 ms timing bound, priority-50 FIFO prerequisite, 40-second carrier
gate, and terminal-stop policy:

- [`BOUNDARY_RT2_REPLICATION_TESTPLAN.md`](BOUNDARY_RT2_REPLICATION_TESTPLAN.md)
- [`matrix-boundary-correlation-replication-rt2.csv`](matrix-boundary-correlation-replication-rt2.csv)

Both pairs subsequently passed the exact runtime, package-maintenance
isolation, clean TCP/UDP control, baseline qdisc, and 80-sample unchanged
carrier qualifications, including the priority-50 FIFO proof. The campaign
then terminally safety-stopped in its first residence-1 TCP wave. Secondary
TCP r2 (`boundary-correlation-replication-rt2-ge-res1-d16-r200-q1-16f-tcp-r2`)
could not retrieve its pre-impairment ping artifact through the port-2233 SCP
path. This is a `baseline_preflight` safety stop: no impaired result from that
cell qualifies and no fourth-replication matrix cell may be retried or added.

The independently scheduled primary TCP r1 workload completed with
`workload.rc = 0`, but its later full raw-tree collection through port 2223 also
failed. Immediate manual SCP recovery of the immutable remote client and server
trees succeeded, confirming a transient collection-path failure rather than a
measured transport result. That partial shard remains incomplete and
unclassified; it cannot be promoted from recovered raw files. No fourth UDP
cell or later residence was run. The preserved fourth campaign therefore
contributes no selected valid cell, quasi-meltdown outcome, formal meltdown
outcome, or onset inference.

The runner now performs three bounded SCP download attempts with one- and
two-second delays and retains the final error output. This hardening applies
only to a future independently predeclared campaign; it does not reopen,
repair, or extend the stopped fourth campaign.

On 2026-07-23, a fifth independent correlation replication was prospectively
predeclared. Its immutable 30-cell scientific matrix uses a new stage identity
and a SHA-256 of
`d3a91e81fa997407d8d0ab66e662378bc26bfb06bf7c4283ece678c0e87b1bbc`;
it cannot pool or repair the prior stopped campaign. The fifth plan preserves
all timing, carrier, maintenance, matched-control, and terminal-stop rules,
binds the hardened runner hash, and serializes cell dispatch until each prior
cell has fully collected, analyzed, restored, and passed its safety-latch
check:

- [`BOUNDARY_RT3_REPLICATION_TESTPLAN.md`](BOUNDARY_RT3_REPLICATION_TESTPLAN.md)
- [`matrix-boundary-correlation-replication-rt3.csv`](matrix-boundary-correlation-replication-rt3.csv)

The fifth campaign's first primary TCP cell completed its workload but failed
during final raw-tree collection. The resulting destination for a client
artifact was exactly 260 characters long, exceeding the Windows OpenSSH path
boundary; this was a local evidence-path failure, not a transport outcome.
The remote client and server trees were immediately recovered to a short local
root and are bound by recovery manifest SHA-256
`621fd98adfc45f314cad9976867dd73de0d4e1f7ee063e2db49ef92fe1f41151`.
The failed logical cell cannot be rerun, so a complete three-repetition
selection is no longer possible. No later fifth-campaign cell was run, and the
campaign contributes no selected valid result or onset inference.

The runner now rejects a Windows collection path at or beyond 260 characters
before starting a workload. This prevention and the short local raw root apply
only to a future independently predeclared campaign; they do not repair,
reclassify, or extend the fifth campaign.

## Interpretation limits

- The Stage 1 sample is deliberately small and qualifies the harness; it does
  not estimate event probability.
- Synthetic netem loss establishes mechanism boundaries, not network
  prevalence.
- The reference profile is intentionally harsh and should not be described as
  representative LTE behavior without qualified field traces.
- No claim about LTE prevalence will be made from one carrier, modem, location,
  outage, or public trace.
- Invalid evidence is never converted into a positive or negative result.
- The incomplete 8-packet point and unrun 16-packet point prevent a correlation
  onset or probability bracket from being claimed.
- The final boundary applies only to the recorded kernel, runtime, topology,
  workload, RTT, queue, loss model, and carrier configuration.

The authoritative prospective rules remain in
[`BOUNDARY_TESTPLAN.md`](BOUNDARY_TESTPLAN.md). Historical interpretation and
replication guidance are in [`../../docs/TCP_MELTDOWN.md`](../../docs/TCP_MELTDOWN.md).
