# Carrier Stability Diagnostic CT4

## Purpose and independence

CT4 is a new independent no-impairment carrier-stability diagnostic authorized
after CT3 terminally stopped. RT4 and CT1 through CT3 retain their published
dispositions; no prior observation is retried, repaired, reclassified, or
pooled.

CT3 proved that its immediate pair-filtered carrier-count check did not
guarantee a carrier-free passive activation: its secondary setup saw a
port-51821 carrier after that check and before synchronized activation. CT4
therefore tests the same 24-row activation/keepalive design while removing
active-control preparation from the interval preceding a named observation.
It produces no TCP-meltdown result and cannot directly release Stage 3.

## Immutable inputs

- Matrix:
  [`matrix-carrier-stability-diagnostic-ct4.csv`](matrix-carrier-stability-diagnostic-ct4.csv)
- Stage identity: `carrier-stability-diagnostic-ct4`
- Matrix SHA-256:
  `0ad1136a994ef171f6449bb356ef7b942a8f66012659821d62e0440708b7a4b9`
- Diagnostic sampler:
  [`harness/diagnose-carrier-stability.sh`](harness/diagnose-carrier-stability.sh)
- Activation helper:
  [`harness/synchronized-setup.sh`](harness/synchronized-setup.sh)
- Idle normalization helper:
  [`harness/normalize-idle-host.sh`](harness/normalize-idle-host.sh)
- Idle normalization helper SHA-256:
  `6fab5b5e6997be5eac1799038bb78d02ecb63d60b0320a513a2b5f9af9f389f5`
- Idle qualification helper:
  [`harness/qualify-idle-host.sh`](harness/qualify-idle-host.sh)
- Idle qualification helper SHA-256:
  `43fc50cae9e02c59860cb29439e2162130e050fa90cb085ac1f987c5f1627847`
- Runtime source: `2b9513f`
- Kernel: `6.8.0-1062-azure`
- Module srcversion: `01DA86291E0FBD2CD3C940C`
- Module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- Tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`

## Design

The immutable matrix has the primary and secondary pairs, the four CT3
activation arms, and three repetitions per pair/arm. Each observation uses two
outer TCP carriers, an 8-second bidirectional warm-up, and a 120-second sample
at 500 ms cadence.

| Arm | Activation | Persistent keepalive | Question |
|---|---|---:|---|
| `sync-k5` | Both passive interfaces receive endpoint updates at one absolute target. | 5 s | RT4-equivalent baseline. |
| `sync-k0` | Both peers disable persistent keepalive with their initial endpoint update. | 0 s | Does keepalive traffic drive churn? |
| `sync-k1` | Both peers use one-second persistent keepalive with their initial endpoint update. | 1 s | Does the period determine churn cadence? |
| `staggered-k5` | The second passive interface receives its endpoint update five seconds after the first. | 5 s | Does dual activation timing drive churn? |

No inner workload, qdisc impairment, source change, or module change occurs
after warm-up.

## Separate preparation and named observation

Before any named observation, each pair may run one non-observation active
control preparation to verify the exact runtime, clean TCP/UDP controls, and
two-carrier operation. It then normalizes both endpoints concurrently with
`normalize-idle-host.sh`. The preparation receipt is retained separately and
is not a matrix attempt.

After normalization, each endpoint must pass `qualify-idle-host.sh`: exact
runtime identity, baseline qdiscs, no tunnel interfaces, no temporary services
or capture, no package activity or lock, no failed unit, runtime-masked
maintenance, and **ten consecutive 500 ms samples with no established or
listening TCP port-51821 socket of any peer**. The gate is all-port rather than
pair-filtered. Failure creates no named CT4 observation and may be retried only
as fleet launch ineligibility after collecting its receipt.

No active `PrepareOnly` or active-tunnel reconstruction may occur after the
final successful quiescence sample and before named passive activation. Each
named runner repeats idle qualification before creating its directory, then
uses only passive synchronized setup. It starts the scoped inner-iperf service
only after that passive setup succeeds.

Each named observation retains sorted carrier tuples, transition `ss -tin` and
kernel snapshots, two-sided FIN/RST captures, setup/warm-up/qualification/
restoration logs, the pre-named idle-qualification receipt, and SHA-256
manifests. Exactly two unchanged tuples are required at every one of 240
samples. A tuple/count change is an observed outcome.

Closeout removes tunnels, stops the inner-iperf, competitor, and HTTP temporary
services, clears failed units, restores maintenance, and verifies baseline
qdiscs, zero port-51821 carriers, no `tcpdump`, inactive temporary services,
and enabled maintenance. Any missing qualification, collection, timing,
runtime, capture, or closeout evidence invalidates the named observation,
stops CT4, and permits no rerun of that name.

## Execution and disposition

The all-four pinned-key launch gate must pass before the first paired matrix
row. Execute rows in matrix order; pair-specific rows sharing an arm and
repetition may run concurrently only after both have passed the pre-named idle
gate. Later rows wait for complete collection and closeout of both pairs.

After CT4, publish all receipts and outcomes with a manifest-bound ledger. Only
an arm with three clean observations on both pairs may justify a fresh,
independently predeclared correlation campaign. If no arm qualifies, publish
the carrier-stability limitation and do not run correlation, duration,
mitigation, or LTE work on this runtime. Closeout deallocates the gateway and
endpoints after restoration.
