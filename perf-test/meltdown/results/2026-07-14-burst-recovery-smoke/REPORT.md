# Generated TCP Meltdown Results

Generated: 2026-07-14T07:08:58.191865+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 0 |
| degraded | 1 |
| near-meltdown | 0 |
| meltdown | 0 |
| invalid | 3 |

Near-meltdown cells: 0. Valid cells: 1 / 4.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| burst-recovery-smoke-ge2-25-90-1-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.95 | 0.577 | -1.126 | 0.00 | 0 | invalid |
| burst-recovery-smoke-ge2-25-90-1-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.03 | 0.967 | 2.130 | 1.56 | 0 | invalid |
| burst-recovery-smoke-ge2-25-90-1-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 4.10 | 0.002 | -0.040 | 5.69 | 0 | degraded |
| burst-recovery-smoke-ge2-25-90-1-r200-q1-16f-udp-r2 | udp | 200 | 1 | 16 | 3.77 | 0.000 | -0.469 | 6.25 | 0 | invalid |
