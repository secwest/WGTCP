# Carrier Stability Diagnostic CT2

## Purpose and independence

CT2 is a new, independent no-impairment carrier-stability diagnostic authorized
after CT1 terminally stopped before host qualification. CT1's invalid status,
its 23 unrun rows, and RT4's incomplete carrier-gate result remain immutable.
CT2 does not retry, repair, reclassify, or pool any prior observation.

CT2 asks whether any predeclared combination of dual-interface activation and
persistent-keepalive cadence retains two exact authenticated TCP carriers for
120 seconds on both VM pairs. It produces no TCP-meltdown result and cannot
release Stage 3 directly.

## Immutable inputs

- Matrix:
  [`matrix-carrier-stability-diagnostic-ct2.csv`](matrix-carrier-stability-diagnostic-ct2.csv)
- Stage identity: `carrier-stability-diagnostic-ct2`
- Matrix SHA-256:
  `8df67b25905b9b079fe89f7438cd94c89b40cfc2fcd14a89f593ff677ad4b983`
- Diagnostic sampler:
  [`harness/diagnose-carrier-stability.sh`](harness/diagnose-carrier-stability.sh)
- Diagnostic sampler SHA-256:
  `39c8db3a11a53abbce7aca681ce0608e14d1464fc2f221660cc6686deb8ffc94`
- Activation helper:
  [`harness/synchronized-setup.sh`](harness/synchronized-setup.sh)
- Activation helper SHA-256:
  `76b6cacd4177301ff90e34f83c6debcf7a8184f8b540feb9d1e9471bdfba20d8`
- Runtime source: `2b9513f`
- Kernel: `6.8.0-1062-azure`
- Module srcversion: `01DA86291E0FBD2CD3C940C`
- Module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- Tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`

## Matrix

The immutable matrix contains 24 observations: primary and secondary endpoint
pairs, four arms, and three repetitions per pair/arm. Each observation uses
the exact RT4 runtime, host qualification, passive TCP interface construction,
two configured outer TCP carriers, an 8-second bidirectional warm-up, and a
120-second observation at 500 ms cadence.

| Arm | Activation | Persistent keepalive | Question |
|---|---|---:|---|
| `sync-k5` | Both passive interfaces receive endpoint updates at one absolute target. | 5 s | RT4-equivalent baseline. |
| `sync-k0` | Both peers disable persistent keepalive with their initial endpoint update. | 0 s | Does keepalive traffic drive churn? |
| `sync-k1` | Both peers use one-second persistent keepalive with their initial endpoint update. | 1 s | Does the period determine churn cadence? |
| `staggered-k5` | The second passive interface receives its endpoint update five seconds after the first. | 5 s | Does dual activation timing drive churn? |

No inner workload, qdisc impairment, source change, or module change occurs
after warm-up.

## Launch eligibility and evidence

Before an observation name exists, the paired dispatcher must confirm pinned-key
SSH reachability to all four endpoints. Each pair runner also requires an
explicit `-Execute` switch and a successful pinned-key no-op SSH probe to both
of its endpoints before it creates its observation directory or changes a
remote host. A disconnected or unallocated fleet therefore fails launch
eligibility, not a named CT2 observation, and may be restored and checked again.

After a named runner creates its directory, both endpoints must pass the RT4
host qualification: exact runtime identity, no maintenance activity, baseline
qdiscs, no tunnel/helper residue, zero failed units, synchronized clocks, and
clean TCP/UDP controls. Package-maintenance isolation stays active during the
observation.

The diagnostic samples the exact sorted established-tuple set whose local or
remote port is 51821 and whose remote physical address matches the peer. It
requires exactly two tuples across 240 samples and retains:

- every tuple sample and each tuple/count transition;
- `ss -tin` and last-80-line kernel snapshots on every transition;
- two-sided FIN/RST captures for TCP port 51821;
- setup, warm-up, qualification, restoration, and capture-session logs; and
- SHA-256 manifests for all retained files.

Tuple replacement or count change is an observed outcome. Missing timing,
capture, host-qualification, runtime, collection, or restoration evidence
invalidates a named CT2 observation, terminally stops CT2, and permits no
rerun of that name.

## Execution and disposition

Run rows in matrix order. The pair-specific rows sharing arm and repetition may
run concurrently only after the all-four-endpoint launch gate passes. Later rows
wait for collection and restoration from both pairs.

After CT2:

1. Publish all outcomes, invalid/unrun rows, captures, and a compact
   manifest-bound ledger.
2. Preserve RT4 and CT1 unchanged.
3. Only if an arm has three clean observations on both pairs, predeclare a
   seventh independent five-residence correlation matrix bound to that setup.
4. If no arm qualifies, publish the carrier-stability limitation and do not run
   further correlation, duration, mitigation, or LTE work on this runtime.

Closeout restores baseline qdiscs and tunnel state, removes maintenance masks
and temporary capture processes, then deallocates idle VMs.
