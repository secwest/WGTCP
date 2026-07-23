# Fifth Real-Time Correlation Replication Plan

## Purpose

This is a fifth, independent prospective correlation replication authorized on
2026-07-23. It does not repair, extend, reclassify, retry, or pool any result
from the frozen 2026-07-16, 2026-07-20, 2026-07-21, or 2026-07-22 campaigns.
Its purpose is to obtain one complete five-point selection under the already
established outcome and validity rules.

## Immutable inputs

- Matrix:
  [`matrix-boundary-correlation-replication-rt3.csv`](matrix-boundary-correlation-replication-rt3.csv)
- Stage identity: `boundary-correlation-replication-rt3`
- Matrix SHA-256:
  `d3a91e81fa997407d8d0ab66e662378bc26bfb06bf7c4283ece678c0e87b1bbc`
- Runtime source: `2b9513f`
- Campaign runner SHA-256:
  `031d9dba54dc3030a8463160301451d0eecab04452148d9bd8db49ef58abf52f`
- Kernel: `6.8.0-1062-azure`
- Module srcversion: `01DA86291E0FBD2CD3C940C`
- Module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- Tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- iperf SHA-256:
  `626565d9571f0ebb9148a36944beeaafa9b7581884f11c11b7fd1cf4218f5ad4`

The formal-meltdown, quasi-meltdown, matched-control, validity, cleanup, and
timing definitions in [`BOUNDARY_TESTPLAN.md`](BOUNDARY_TESTPLAN.md) are
unchanged.

## Matrix and pair assignment

The matrix contains 30 logical cells: residences 1, 2, 4, 8, and 16 packets;
TCP and matched UDP; and three repetitions. Every cell retains the 50 Mb/s
carrier, 200 ms RTT, 1x-BDP FIFO, 16 reverse CUBIC streams, 15-second clean
baseline, 16-second loss epoch, and 60-second clean recovery.

| Residence | Primary pair | Secondary pair |
|---:|---|---|
| 1 packet | r1, r3 | r2 |
| 2 packets | r2 | r1, r3 |
| 4 packets | r1, r3 | r2 |
| 8 packets | r2 | r1, r3 |
| 16 packets | r1, r3 | r2 |

TCP and UDP for a repetition must use the same assigned pair. No evidence may
cross campaign, pair, runtime, runner, or cell fingerprints.

## Timing and host qualification

Each impairment uses the existing absolute
`clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME)` scheduler and a bounded
priority-50 `SCHED_FIFO` systemd unit. Requested, command, qdisc-change, and
clock-error timestamps remain the sole timing evidence. A transition completion
later than 100 ms, conservative start or stop skew above 20 ms, invalid overlap,
or missing timing evidence invalidates the cell and terminally stops this
replication.

Before any live cell, all four endpoints must independently pass exact runtime,
package-maintenance isolation, zero failed units, clock, baseline-qdisc,
no-residue, zero-loss TCP/UDP, two-carrier, and priority-50 FIFO qualifications.
TCP interfaces are constructed passively and activated against one absolute
target. Each endpoint must then retain exactly two unchanged carrier tuples in
80 consecutive 500 ms samples within a 120-second settlement window.

The 2026-07-22 symmetric and asymmetric lifetime regressions are qualification
coverage only. They do not relax, replace, or shorten the live 40-second carrier
gate. Package-maintenance masks stay active until campaign closeout.

## Execution, collection, and retry rules

Run residences in the committed order: 1, 2, 4, 8, then 16. Finish validity and
restoration review for one wave before starting the next. Within every wave,
globally serialize cell dispatch: do not start another pair's cell until the
prior cell has completed its baseline preflight, full raw-tree collection,
analysis, restoration, and safety-latch check. The fixed pair allocation remains
unchanged; serialization prevents a collection safety stop from leaving another
shard in flight.

- Retain every raw attempt.
- The bound runner retries each failed SCP download at most twice after its
  initial attempt, with one- and two-second delays. A third failure remains a
  fail-closed collection error.
- Permit at most one exact rerun of a logical cell, only after evidence-invalid
  execution with the same matrix row, pair, runtime, runner, campaign
  fingerprint, and cell fingerprint.
- Never rerun valid, failed, or stopped evidence.
- Treat every safety stop as terminal. Do not run later shards or residences.
- Never convert invalid evidence into a transport outcome.

## Release and closeout

After all five waves independently qualify, the least severe residence with a
`quasi_meltdown_episode` in at least two of three valid matched TCP repetitions
releases the separately predeclared duration stage. Otherwise Stage 3 remains
blocked. No frozen campaign result can contribute to this release decision.

Final composition retains all attempts and logical states, binds raw and audit
trees by SHA-256, and publishes compact CSV/JSON evidence. Closeout restores
qdiscs, removes package masks and temporary access services, and deallocates
idle VMs.
