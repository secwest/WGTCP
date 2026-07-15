# Final Execution Audit

This inventory separates selected release evidence from every post-repair raw
execution. Composites are selections of existing cells and are not counted
again in the raw-execution audit. The superseded 14-cell pre-writer-repair
calibration is also excluded.

| Inventory | Total | Valid | Stable | Degraded | Near-meltdown | Meltdown | Invalid |
|---|---:|---:|---:|---:|---:|---:|---:|
| Released selection before breadth | 106 | 98 | 92 | 5 | 1 | 0 | 8 |
| All post-repair raw executions | 162 | 122 | 92 | 17 | 13 | 0 | 40 |
| Breadth base | 20 | 14 | 0 | 7 | 7 | 0 | 6 |
| Exact breadth reruns | 6 | 5 | 0 | 3 | 2 | 0 | 1 |
| Logical breadth state after allowed reruns | 20 | 19 | 0 | 10 | 9 | 0 | 1 |

These rows are different views, not addends: the 26 breadth executions are
already included in the 162-row raw audit, and the logical breadth row is a
deduplicated replacement view.

The 106-cell released selection remains the last all-gates-qualified inventory.
The breadth campaign adds valid individual evidence to the 162-execution audit,
but its all-valid composite is permanently disqualified because random-loss
TCP r1 consumed its sole rerun while remaining invalid.

Among the nine valid logical TCP breadth cells, every execution has severe
stalls (52.8%-94.0%) and outer recovery (56-150 events). Two pair stalls with a
significant decline but no qualifying inner-RTO rate; three pair stalls with a
qualifying inner-RTO rate but no significant decline; four meet only the stall
condition. No valid execution combines all three formal meltdown conditions.

This is evidence of severe TCP-over-TCP degradation and near-meltdown behavior,
not evidence of immunity. One earlier invalid corrected-burst rerun met all
three conditions, but invalid evidence is never promoted.

[`campaigns.csv`](campaigns.csv) records every included raw campaign and the
three excluded duplicate or superseded inventories.
