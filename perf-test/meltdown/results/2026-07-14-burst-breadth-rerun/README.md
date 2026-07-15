# Burst-Breadth Exact Invalid-Cell Rerun

This targeted campaign reran only the six evidence-invalid base executions,
using the original campaign and cell fingerprints. It is intentionally marked
`targeted_selection=true` and `qualifying_complete=false`; it cannot become a
new base campaign.

| Classification | Executions |
|---|---:|
| stable | 0 |
| degraded | 3 |
| near-meltdown | 2 |
| meltdown | 0 |
| invalid | 1 |

Five reruns are valid: three degraded and two near-meltdown. Random-loss TCP r1
remains invalid because its interval-duration evidence missed the fixed
completion contract by about 200 ms. It delivered 0.220 Mb/s, stalled in 54.7%
of 100 ms bins, recorded 162 outer-recovery events, and had no inner RTO. The
validity gate and sole-rerun limit were not relaxed after observing it.

Consequently, the logical 20-cell breadth selection is 19 valid (10 degraded
and nine near-meltdown), zero meltdown, and one invalid. The fail-closed merger
cannot produce an all-valid qualified composite, and no further exact retry is
allowed.

Runtime identity and campaign fingerprint are identical to the base campaign.
