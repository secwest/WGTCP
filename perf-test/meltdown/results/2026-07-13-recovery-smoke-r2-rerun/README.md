# Outer-Recovery Smoke Invalid-Cell Retry

This separate exact-cell campaign reran
`recovery-smoke-r35-q005-r200-16f-tcp-r2` without replacing the original
invalid record.

The failure reproduced. The retry delivered 2.93 Mb/s with 34.5%
zero-delivery bins and 624 queue drops. Iperf again completed its measurement
intervals but could not receive the final results and exited nonzero. The
server trace also had two more raw inner retransmission events than its END
summary, exceeding the one-event shutdown allowance. The retry is therefore
invalid for both workload and telemetry reasons.

Neither the original execution nor the retry recorded a scored outer
retransmission or RTO. This repeated severe degradation is retained as
diagnostic evidence, but it cannot qualify the cell or support a meltdown
classification.

The campaign and cell fingerprints match the original exact cell:

- campaign fingerprint:
  `f18533c06e354f62aac4d48daf9774fa4368437632da3a889fa385511c1758c8`
- cell fingerprint:
  `9f4c3c50e042c30f9aa59a51e642e973936baa6d84c050f4e4c9d6a0246d1e45`
