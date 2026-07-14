# Corrected Burst-Recovery Invalid-Cell Rerun

This separate campaign reran only the three invalid executions from the
completed `2/25/90/1` burst-recovery smoke. It retained the exact campaign,
cell, runtime, matrix, and impairment fingerprints. None of the original
records was overwritten.

All three reruns remained invalid:

| Execution | Goodput | Stalls | Trend | Inner RTO/flow-min | Invalid reason |
|---|---:|---:|---:|---:|---|
| TCP r1 | 0.073 Mb/s | 93.7% | significant decline | 1.31 | workload finalization |
| TCP r2 | 0.81 Mb/s | 64.0% | positive | 1.19 | workload finalization; realized loss |
| UDP r2 | 3.76 Mb/s | 0.7% | positive | 7.19 | tracer summary mismatch |

TCP r1 exhibited all three formal meltdown conditions and recorded 29 outer
retransmissions plus 17 outer RTOs. It remains unscored because iperf completed
59.9 of 60.0 seconds of interval output but could not receive its final in-band
results. TCP r2 reproduced the same finalization failure. UDP r2 reproduced a
three-event raw-minus-summary discrepancy. These results are evidence for the
next prospective harness design, not a basis for post-hoc rescoring.

Post-rerun checks found two carriers per endpoint, no impairment marker, IFB,
restoration failure, or transient unit, and zero-loss TCP/UDP controls.

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- campaign fingerprint:
  `9eafa9f42d7ee71e2b0b96d32811b298c1db6b32751fb9b14b22c56a0327878b`
