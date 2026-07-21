# Real-Time Correlation Replication Plan

## Purpose

This is a third, independent prospective correlation replication authorized on
2026-07-21. It does not repair, extend, reclassify, or pool either frozen
correlation campaign. Its purpose is to obtain one complete five-point
selection under the unchanged outcome and validity rules.

## Immutable matrix and environment

- Matrix: [`matrix-boundary-correlation-replication-rt.csv`](matrix-boundary-correlation-replication-rt.csv)
- Stage identity: `boundary-correlation-replication-rt`
- Matrix SHA-256:
  `571ce640768f4d309ca06c71beb92ef5d36c98af3016c7dd6173247ce7cd3b0f`
- Kernel, module, WireGuard tool, iperf, matched VM pairs, transport-aware
  evidence rules, 50 Mb/s carrier, 200 ms RTT, 1x-BDP FIFO, 16 reverse CUBIC
  streams, 15-second clean baseline, 16-second loss epoch, and 60-second clean
  recovery are unchanged from the prior independent replication.
- The matrix contains 30 logical cells: residences 1, 2, 4, 8, and 16
  packets; TCP and matched UDP; three repetitions per point.

## Timing hardening

The second replication safety-stopped because one UDP start transition had a
44.49 ms conservative inter-endpoint skew, above the unchanged 20 ms limit.
This replication keeps every timing threshold unchanged and changes only the
launch mechanism:

1. Each timed impairment waits for its shared wall-clock deadline with
   `clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME)` rather than bounded
   relative sleeps.
2. Each short-lived impairment unit runs with `SCHED_FIFO` priority 50. The
   process remains bounded to its two qdisc transitions and has no network
   listener or persistent privilege.
3. Both endpoints still record requested, command, qdisc-change, and
   clock-error timestamps. A transition completion later than 100 ms, a
   conservative start or stop skew above 20 ms, an invalid 16-second overlap,
   or any failed timing evidence invalidates the cell and is a terminal safety
   stop for this replication.

Host qualification also requires a successful ephemeral `SCHED_FIFO` unit on
each endpoint before the first live cell. This checks the unit capability only;
the recorded qdisc timing evidence remains the sole validity decision.

## Host qualification

Before the first cell, all four endpoints must satisfy the existing runtime,
clock, qdisc, package-maintenance isolation, carrier, and zero-loss TCP/UDP
controls. TCP interfaces are passively constructed, activated at a common
absolute target, warmed bidirectionally, and must retain exactly two unchanged
carrier tuples in every 500 ms sample for 40 consecutive seconds within a
120-second bounded settlement window.

Runtime masks on package maintenance remain in place until closeout. Any
package activity, service restart, runtime identity change, failed systemd
unit, unexpected qdisc state, or tuple loss is a safety stop.

## Execution and retry rules

The residence order is 1, 2, 4, 8, then 16 packets. Pair assignments match
the prior independent matrix: primary r1/r3 at residences 1/4/16 and r2 at
2/8; secondary takes the complementary repetitions. A matched TCP/UDP pair
never crosses VM pairs.

Every raw attempt is retained. A logical cell has at most one exact rerun, only
after evidence-invalid execution and only with the same matrix row, assigned
pair, runtime identity, campaign fingerprint, and cell fingerprint. A valid,
failed, or safety-stopped attempt is never rerun. A safety stop is terminal:
no later shard or residence may execute.

## Release and closeout

After all five waves independently qualify, the least-correlated point with
`quasi_meltdown_episode` in at least two of three valid matched TCP
repetitions releases the separately committed duration stage. Otherwise Stage
3 remains blocked. No incomplete point or result from either frozen campaign
can contribute to this decision.

Final composition must retain every attempt, logical selection, and audit
record with SHA-256 bindings. Closeout removes package masks and temporary
access services, restores baseline qdiscs, and deallocates idle endpoints.
