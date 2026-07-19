# TCP Meltdown Boundary Replication Plan

## Purpose

This is a new prospective replication authorized on 2026-07-19. It does not
repair, extend, or reclassify the frozen 2026-07-16 Stage 2 campaign. That
campaign remains an incomplete result with an exhausted retry budget.

The replication reruns the complete five-point packet-correlation matrix using
fresh stage and cell identities. Its purpose is to obtain one independently
qualified correlation selection that can either release the duration boundary
or close that gate without an onset claim.

## Immutable inputs

- Matrix:
  [`matrix-boundary-correlation-replication.csv`](matrix-boundary-correlation-replication.csv)
- Matrix SHA-256:
  `4e9b5b9258365cfce0e544ab018492c810a31623220e2349b0a7616e7cc6fc15`
- Runtime source: `2b9513f`
- Timed harness: `a46fa40`
- Kernel: `6.8.0-1062-azure`
- Module srcversion: `01DA86291E0FBD2CD3C940C`
- Module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- Tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- iperf SHA-256:
  `626565d9571f0ebb9148a36944beeaafa9b7581884f11c11b7fd1cf4218f5ad4`

The existing formal-meltdown, quasi-meltdown, validity, timing, cleanup, and
matched-control definitions in
[`BOUNDARY_TESTPLAN.md`](BOUNDARY_TESTPLAN.md) remain unchanged.

## Matrix

The stage identity is `boundary-correlation-replication`. The matrix contains
30 logical cells: five mean bad-state residence points, TCP and UDP, and three
paired repetitions.

| Mean bad-state residence | P | R | Nominal stationary loss |
|---:|---:|---:|---:|
| 1 packet | 4% | 100% | 4.42% |
| 2 packets | 2% | 50% | 4.42% |
| 4 packets | 1% | 25% | 4.42% |
| 8 packets | 0.5% | 12.5% | 4.42% |
| 16 packets | 0.25% | 6.25% | 4.42% |

All cells use:

- 50 Mb/s carrier rate;
- 200 ms RTT;
- 1x-BDP FIFO queue;
- 16 reverse CUBIC streams;
- 15 seconds of measured clean baseline;
- 16 seconds of timed impairment;
- 60 seconds of scored clean recovery;
- matched TCP and UDP controls on the same VM pair.

## Pair assignment

Pair assignment is fixed before execution:

| Residence | Primary pair | Secondary pair |
|---:|---|---|
| 1 packet | r1, r3 | r2 |
| 2 packets | r2 | r1, r3 |
| 4 packets | r1, r3 | r2 |
| 8 packets | r2 | r1, r3 |
| 16 packets | r1, r3 | r2 |

TCP and UDP for one repetition must remain on the assigned pair. Evidence may
not be paired across pair campaign fingerprints.

## Host and maintenance qualification

Before the first impairment cell:

1. Wait for any package operation already triggered by VM startup to finish.
2. Record active package units, timers, locks, and recent package journals.
3. Apply runtime-only masks to `apt-daily.service`,
   `apt-daily-upgrade.service`, `apt-daily.timer`, and
   `apt-daily-upgrade.timer` on all four endpoints.
4. Confirm no package process or lock remains after masking.
5. Verify exact runtime identities, synchronized clocks, baseline qdiscs,
   absence of IFB/marker/transient residue, two TCP carriers per endpoint, and
   zero-loss TCP/UDP controls.

Runtime masks remain in place through Stage 2 replication and are removed
during campaign closeout. A package operation, service restart, runtime
identity change, clock failure, or unexplained host transition is a safety stop.

## Execution and retry rules

Run residence points in the committed order: 1, 2, 4, 8, then 16 packets.
Each wave must finish validity and restoration review before the next begins.

- Every original attempt is retained.
- A logical cell receives at most one rerun.
- A rerun is allowed only after evidence-invalid execution.
- A rerun must use the exact original matrix row, repetition, pair, campaign
  fingerprint, cell fingerprint, runtime identity, and workload.
- Valid, failed, or safety-stopped evidence is never rerun.
- A safety stop is terminal for the replication. No later shard may add an
  attempt.
- Invalid evidence is never converted into a positive or negative transport
  result.

## Release decision

After all five waves qualify, select the least severe residence point with a
`quasi_meltdown_episode` in at least two of three valid matched TCP
repetitions.

- If such a point exists, it releases the separately committed Stage 3
  duration matrix.
- If no point satisfies the rule, the replication completes without a
  correlation-onset bracket and Stage 3 remains blocked.
- A single episode, an incomplete point, or a non-monotonic pattern does not
  release Stage 3.

No result from the frozen campaign is pooled into the replication probability
decision. The two campaigns may be compared only as independent sensitivity
evidence.

## Later stages

Duration, stream-count, carrier-rate, offered-load, interaction, confirmation,
sysctl mitigation, and LTE replay stages retain the ordering and release gates
in `BOUNDARY_TESTPLAN.md`. Every data-dependent matrix must be committed before
its first live cell. Synthetic results alone cannot establish LTE prevalence.

## Publication and closeout

The final composition must preserve every attempt and logical state, bind raw
evidence and audit bundles with SHA-256, and publish compact CSV/JSON evidence.
After evidence is pushed, remove runtime package masks and temporary gateway
proxy units/rules, restore host state, and deallocate idle VMs.
