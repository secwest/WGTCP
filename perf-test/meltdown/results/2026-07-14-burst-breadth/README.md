# Burst-Breadth Base Campaign

This is the complete 20-execution breadth campaign released by the qualified
transport-aware burst gate. It keeps the fixed 50 Mb/s, 1x-BDP, 16-flow,
60-second design and varies loss correlation, stationary loss, burst duration,
and RTT under campaign fingerprint
`4d0c179c8aaee73a6b05b2aaf663d7a5a6a2468175e2d4a5b80e3228f49b1dfb`.

| Classification | Executions |
|---|---:|
| stable | 0 |
| degraded | 7 |
| near-meltdown | 7 |
| meltdown | 0 |
| invalid | 6 |

The 14 valid executions contain seven degraded and seven near-meltdown
outcomes. No valid execution meets all three formal meltdown conditions. All
20 scheduled executions completed, `failed_cells` remained empty at the
orchestration layer, and no campaign safety latch was raised. Evidence-invalid
classifications are counted separately above.

The six invalid records remain immutable. They were rerun once, exactly and
separately, under the predeclared retry bound; see
[`../2026-07-14-burst-breadth-rerun/`](../2026-07-14-burst-breadth-rerun/).

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- iperf SHA-256:
  `626565d9571f0ebb9148a36944beeaafa9b7581884f11c11b7fd1cf4218f5ad4`
