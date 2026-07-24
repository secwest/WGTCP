# Carrier Stability Diagnostic CT5

## Purpose and independence

CT5 is a new independent no-impairment carrier-stability diagnostic. CT4
terminally stopped without a named matrix observation when its primary active
control preflight failed TCP tunnel control twice after clean restoration. CT5
does not repair, retry, reclassify, or pool CT4 or any earlier diagnostic.

CT5 keeps CT4's 24 named activation/keepalive observations but replaces its
active `PrepareOnly` launch control. This avoids reconstructing an active TCP
carrier between the final quiescence check and a named passive activation.

## Immutable inputs

- Matrix:
  [`matrix-carrier-stability-diagnostic-ct5.csv`](matrix-carrier-stability-diagnostic-ct5.csv)
- Stage identity: `carrier-stability-diagnostic-ct5`
- Matrix SHA-256:
  `e4629ca3663eb130f5b566232812ae3e7938d210832c0aed38735f02acda967c`
- Diagnostic sampler:
  [`harness/diagnose-carrier-stability.sh`](harness/diagnose-carrier-stability.sh)
- Diagnostic sampler SHA-256:
  `39c8db3a11a53abbce7aca681ce0608e14d1464fc2f221660cc6686deb8ffc94`
- Passive activation helper:
  [`harness/synchronized-setup.sh`](harness/synchronized-setup.sh)
- Passive activation helper SHA-256:
  `76b6cacd4177301ff90e34f83c6debcf7a8184f8b540feb9d1e9471bdfba20d8`
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

## Matrix

The immutable matrix has both pairs, the four prior activation arms, and three
repetitions per pair/arm. Each named observation uses two outer TCP carriers,
an 8-second bidirectional warm-up, and a 120-second sample at 500 ms cadence.

| Arm | Activation | Persistent keepalive | Question |
|---|---|---:|---|
| `sync-k5` | Both passive interfaces receive endpoint updates at one absolute target. | 5 s | RT4-equivalent baseline. |
| `sync-k0` | Both peers disable persistent keepalive with their initial endpoint update. | 0 s | Does keepalive traffic drive churn? |
| `sync-k1` | Both peers use one-second persistent keepalive with their initial endpoint update. | 1 s | Does the period determine churn cadence? |
| `staggered-k5` | The second passive interface receives its endpoint update five seconds after the first. | 5 s | Does dual activation timing drive churn? |

No inner workload, qdisc impairment, source change, or module change occurs
after warm-up.

## Static and passive launch qualification

Before any named observation, all four endpoints must pass pinned-key SSH,
package/lock eligibility, and `qualify-idle-host.sh`. This static gate requires
the exact runtime identity, baseline qdiscs, no tunnel or helper residue,
runtime-masked maintenance, and ten consecutive 500 ms samples with no
established or listening TCP port-51821 socket of any peer.

Each pair then performs one **non-observation passive functional control**:
passive synchronized setup at keepalive five, TCP and UDP tunnel controls, and
an 8-second bidirectional inner-iperf warm-up. It is not a matrix observation.
The pair concurrently runs `normalize-idle-host.sh` afterward and again passes
the all-port ten-sample idle gate. That second gate is the final action before
named passive activation.

No active `PrepareOnly`, active-tunnel setup, or active carrier construction
may occur in CT5. A launch-eligibility failure retains its receipt but creates
no named CT5 observation and may be retried only after clean restoration.

Each named runner re-applies maintenance isolation, repeats static idle
qualification before creating a directory, uses only passive synchronized
setup, then starts its scoped inner-iperf service. It retains sorted tuples,
transition `ss -tin` and kernel snapshots, two-sided FIN/RST captures, all
setup/warm-up/qualification/restoration logs, and a SHA-256 manifest. Exactly
two unchanged tuples are required at every one of 240 samples.

Closeout removes tunnels, stops all temporary services, clears failed units,
restores maintenance, and verifies baseline qdiscs, zero port-51821 carriers,
no `tcpdump`, inactive temporary services, and enabled maintenance. Any named
evidence failure invalidates that observation, terminally stops CT5, and
permits no rerun.

## Execution and disposition

The paired dispatcher requires successful CT5 preflight receipts from both
pairs before it launches the first paired matrix row. Execute in matrix order;
later rows wait for complete collection and closeout of both pairs.

Only an arm with three clean observations on both pairs can justify a fresh,
independently predeclared correlation campaign. CT5 itself produces no
TCP-meltdown result and cannot directly release Stage 3. Closeout deallocates
the gateway and endpoints.
