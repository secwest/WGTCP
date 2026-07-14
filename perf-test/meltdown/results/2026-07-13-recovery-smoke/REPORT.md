# Generated TCP Meltdown Results

Generated: 2026-07-14T00:53:56.347968+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 2 |
| degraded | 1 |
| near-meltdown | 0 |
| meltdown | 0 |
| invalid | 1 |

Near-meltdown cells: 0. Valid cells: 3 / 4.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| recovery-smoke-r35-q005-r200-16f-tcp-r1 | tcp | 200 | 0.05 | 16 | 14.54 | 0.143 | 2.902 | 0.00 | 273 | degraded |
| recovery-smoke-r35-q005-r200-16f-tcp-r2 | tcp | 200 | 0.05 | 16 | 2.79 | 0.427 | 0.006 | 0.00 | 528 | invalid |
| recovery-smoke-r35-q005-r200-16f-udp-r1 | udp | 200 | 0.05 | 16 | 33.18 | 0.000 | 0.025 | 0.00 | 654 | stable |
| recovery-smoke-r35-q005-r200-16f-udp-r2 | udp | 200 | 0.05 | 16 | 33.05 | 0.000 | 0.026 | 0.00 | 672 | stable |
