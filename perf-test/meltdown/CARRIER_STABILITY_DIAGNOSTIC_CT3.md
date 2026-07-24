# Carrier Stability Diagnostic CT3

## Purpose and independence

CT3 is a new independent no-impairment carrier-stability diagnostic authorized
after CT2 terminally stopped. CT1 and CT2 retain their invalid/unrun
dispositions, RT4 remains incomplete, and no prior diagnostic observation is
retried, repaired, reclassified, or pooled.

CT3 retains the predeclared 24-row activation/keepalive design to determine
whether an arm can hold two exact authenticated TCP carriers for 120 seconds
on both pairs. It produces no TCP-meltdown result and cannot directly release
Stage 3.

## Immutable inputs

- Matrix:
  [`matrix-carrier-stability-diagnostic-ct3.csv`](matrix-carrier-stability-diagnostic-ct3.csv)
- Stage identity: `carrier-stability-diagnostic-ct3`
- Matrix SHA-256:
  `3ba54e36831a86fbf32a0b805ff8718c41474e83673724c1a53fcf704b65464a`
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

The immutable matrix has primary and secondary pairs, the four activation arms,
and three repetitions per pair/arm. Each observation uses the exact RT4
runtime, two outer TCP carriers, an 8-second bidirectional warm-up, and a
120-second sample at 500 ms cadence.

| Arm | Activation | Persistent keepalive | Question |
|---|---|---:|---|
| `sync-k5` | Both passive interfaces receive endpoint updates at one absolute target. | 5 s | RT4-equivalent baseline. |
| `sync-k0` | Both peers disable persistent keepalive with their initial endpoint update. | 0 s | Does keepalive traffic drive churn? |
| `sync-k1` | Both peers use one-second persistent keepalive with their initial endpoint update. | 1 s | Does the period determine churn cadence? |
| `staggered-k5` | The second passive interface receives its endpoint update five seconds after the first. | 5 s | Does dual activation timing drive churn? |

No inner workload, qdisc impairment, source change, or module change occurs
after warm-up.

## Launch, qualification, and closeout

Before a CT3 observation name exists, the paired dispatcher must confirm
pinned-key SSH reachability and absence of active package processes or package
locks on all four endpoints. A pair runner likewise requires `-Execute`, a
pinned-key no-op probe, and that passive package/lock check on both endpoints
before it creates its observation directory. A failing launch check creates no
named CT3 evidence and may be retried after the fleet is clean.

After a directory is created, both endpoints must pass the RT4 host
qualification: exact runtime, baseline qdiscs, no tunnel/helper residue, no
failed units, synchronized clocks, and clean TCP/UDP controls. Package
maintenance is isolated only after those launch checks pass.

Each observation retains all sorted port-51821 carrier-tuple samples, transition
`ss -tin` and kernel snapshots, two-sided FIN/RST captures, setup/warm-up/
qualification/restoration logs, and SHA-256 manifests. It requires exactly two
tuples at every one of 240 samples. A tuple/count change is an observed outcome.

The runner's closeout first removes tunnels, stops the inner-iperf, competitor,
and HTTP temporary services, clears failed units, restores maintenance, and
then verifies baseline qdiscs, zero port-51821 carriers, no `tcpdump`, inactive
temporary services, and enabled maintenance. Any missing qualification,
collection, timing, runtime, capture, or closeout evidence invalidates the
named CT3 observation, stops CT3, and permits no rerun of that name.

## Execution and disposition

Execute rows in matrix order. The pair-specific rows sharing an arm and
repetition may run concurrently only after the all-four-endpoint launch gate.
Later rows wait for complete collection and closeout of both pairs.

After CT3:

1. Publish all outcomes, invalid/unrun rows, packet captures, and a compact
   manifest-bound ledger.
2. Preserve RT4, CT1, and CT2 unchanged.
3. Only if an arm has three clean observations on both pairs, predeclare a
   seventh independent five-residence correlation matrix bound to that setup.
4. If no arm qualifies, publish the carrier-stability limitation and do not run
   further correlation, duration, mitigation, or LTE work on this runtime.

Closeout deallocates the gateway and endpoints after restoration.
