# Carrier Stability Diagnostic CT6

## Purpose and independence

CT6 is a new independent no-impairment carrier-stability diagnostic. CT5
terminally stopped before passive setup because a cold allocation left the exact
module unloaded and the static gate correctly refused an unsubstantiated
loaded-runtime claim. CT6 does not repair, retry, reclassify, or pool CT5 or
any earlier diagnostic.

CT6 retains CT5's 24 named activation/keepalive observations and its
passive-only topology. It adds a hash-bound module-preparation step before the
idle qualification gate: load the exact module, attest its loaded srcversion,
and prove this action created neither an interface nor a port-51821 socket.

## Immutable inputs

- Matrix:
  [`matrix-carrier-stability-diagnostic-ct6.csv`](matrix-carrier-stability-diagnostic-ct6.csv)
- Stage identity: `carrier-stability-diagnostic-ct6`
- Matrix SHA-256:
  `7605a178f9c709f3c4a70982180caae2f630ef97875b2be43527ae62f0b99da4`
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
- Idle runtime preparation helper:
  [`harness/prepare-idle-runtime.sh`](harness/prepare-idle-runtime.sh)
- Idle runtime preparation helper SHA-256:
  `1a2ec5230cc6aecd0e7c7296cf3f78b58475eb0184da90bb4ce79a2af07de80c`
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

No inner workload, qdisc impairment, source change, module change, or regional
topology change occurs after warm-up.

## Cold-start, static, and passive qualification

Before any named observation, every endpoint must pass pinned-key SSH and
package/lock eligibility. After concurrent normalization, each endpoint runs
`prepare-idle-runtime.sh`, which verifies the built module hash and srcversion,
refuses any existing WireGuard interface, unloads any no-interface module,
loads the exact built module and dependencies, verifies the loaded srcversion,
and rejects a newly created tunnel interface, listener, or established
port-51821 socket.

Only then does `qualify-idle-host.sh` attest exact runtime identity, baseline
qdiscs, no tunnel/helper residue, runtime-masked maintenance, and ten
consecutive 500 ms samples with no established or listening port-51821 socket
of any peer. Failure retains its preflight receipt but creates no named CT6
observation; it may be retried only as launch ineligibility after restoration.

Each pair then performs one **non-observation passive functional control**:
passive synchronized setup at keepalive five, TCP and UDP tunnel controls, and
an 8-second bidirectional inner-iperf warm-up. The pair concurrently runs
`normalize-idle-host.sh`, re-runs the exact module preparation, and passes a
final all-port ten-sample idle gate. That gate is the final action before named
passive activation.

No active `PrepareOnly`, active-tunnel setup, active carrier construction, or
regional topology mutation may occur in CT6. Physical-region latency is
therefore explicitly held constant; it may be a separately predeclared
topology study only after this current-topology qualification question closes.

Each named runner applies maintenance isolation, repeats module preparation and
static idle qualification before creating its directory, uses only passive
synchronized setup, then starts its scoped inner-iperf service. It retains
sorted tuples, transition `ss -tin` and kernel snapshots, two-sided FIN/RST
captures, all setup/warm-up/qualification/restoration logs, and a SHA-256
manifest. Exactly two unchanged tuples are required at every one of 240
samples.

Closeout removes tunnels, stops all temporary services, clears failed units,
restores maintenance, and verifies baseline qdiscs, zero port-51821 carriers,
no `tcpdump`, inactive temporary services, and enabled maintenance. Any named
evidence failure invalidates that observation, terminally stops CT6, and
permits no rerun.

## Execution and disposition

The paired dispatcher requires successful CT6 preflight receipts from both
pairs before it launches the first paired matrix row. Execute in matrix order;
later rows wait for complete collection and closeout of both pairs.

Only an arm with three clean observations on both pairs can justify a fresh,
independently predeclared correlation campaign. CT6 itself produces no
TCP-meltdown result and cannot directly release Stage 3. Closeout deallocates
the gateway and endpoints.
