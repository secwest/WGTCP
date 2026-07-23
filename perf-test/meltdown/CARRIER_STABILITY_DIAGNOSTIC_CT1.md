# Carrier Stability Diagnostic CT1

## Purpose

This prospective diagnostic studies the TCP carrier tuple churn that terminally
closed the sixth real-time correlation replication (RT4). It does not repair,
extend, reclassify, retry, or pool any cell from RT4 or an earlier correlation
campaign. It contains no impairment and produces no TCP-meltdown result.

The goal is to distinguish whether the observed approximately five-second
carrier replacement is associated with the synchronous dual activation, the
configured persistent-keepalive cadence, or neither. Its result may motivate a
new independently predeclared correlation campaign, but it cannot itself
release Stage 3.

## Immutable inputs

- Matrix:
  [`matrix-carrier-stability-diagnostic-ct1.csv`](matrix-carrier-stability-diagnostic-ct1.csv)
- Stage identity: `carrier-stability-diagnostic-ct1`
- Matrix SHA-256:
  `cfa393ecb821c6eaef14056c998e4c79a5eac1bb1f78251abad2b24894f732fd`
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

The immutable matrix contains 24 observations: the primary and secondary
endpoint pairs, four arms, and three repetitions per pair/arm. Each observation
uses the exact RT4 runtime, clean host qualification, passive TCP interface
construction, two configured outer TCP carriers, an 8-second bidirectional
warm-up, and a 120-second observation at 500 ms cadence.

| Arm | Activation | Persistent keepalive | Question |
|---|---|---:|---|
| `sync-k5` | Both passive interfaces receive endpoint updates at one absolute target. | 5 s | RT4-equivalent baseline. |
| `sync-k0` | As above, then both peers disable persistent keepalive before observation. | 0 s | Does keepalive traffic drive churn? |
| `sync-k1` | As above, then both peers use a one-second persistent keepalive. | 1 s | Does the period determine the churn cadence? |
| `staggered-k5` | Passive interfaces receive one endpoint update, then the other after a fixed five-second delay. | 5 s | Does synchronous dual activation drive churn? |

No inner workload, qdisc impairment, or source/module change occurs after
warm-up. The bound activation helper applies each arm's keepalive interval with
its initial endpoint update; the configured address and TCP listen port remain
unchanged.

## Qualification and evidence

Before each observation, both endpoints must pass the RT4 host qualification:
exact runtime identity, no maintenance activity, baseline qdiscs, no tunnel or
helper residue, zero failed units, synchronized clocks, and clean TCP/UDP
controls. Package-maintenance isolation remains active for the study.

The diagnostic samples the exact sorted set of established tuples whose local
or remote port is 51821 and whose remote physical address matches the assigned
peer. It requires exactly two tuples at every one of 240 samples. It retains:

- every tuple sample and each tuple or count transition;
- `ss -tin` snapshots and the last 80 kernel-log lines on every transition;
- simultaneous 51821 TCP FIN/RST packet captures from both endpoints;
- setup, warm-up, host-qualification, and restoration logs; and
- SHA-256 manifests for every retained file.

A carrier-count change or tuple replacement is an observed diagnostic outcome,
not an execution failure. Missing timing, capture, host qualification, runtime
identity, collection, or restoration evidence invalidates the observation and
stops CT1 without retrying it. No executed observation is retried.

## Execution and disposition

Execute rows in matrix order. The two pair-specific rows with the same arm and
repetition may run concurrently; all later rows wait for full collection and
restoration of both. The source of truth is the 120-second tuple observation,
not a momentary count of two sockets.

After CT1:

1. Publish all 24 outcomes, invalid/unrun rows, packet captures, and a compact
   manifest-bound ledger.
2. Preserve the RT4 terminal result unchanged.
3. If an arm has three clean 120-second observations on both pairs, predeclare
   a seventh independent five-residence correlation matrix that binds that
   exact setup. Do not select or alter the future campaign setup in-place.
4. If no arm qualifies, stop and publish the carrier-stability limitation; do
   not run more correlation, duration, mitigation, or LTE work on this runtime.

Closeout restores the baseline qdiscs and tunnel state, removes maintenance
masks and temporary capture processes, and deallocates idle VMs.
