# Generated TCP Meltdown Results

Generated: 2026-07-14T00:00:35.384408+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 4 |
| degraded | 0 |
| near-meltdown | 0 |
| meltdown | 0 |
| invalid | 0 |

Near-meltdown cells: 0. Valid cells: 4 / 4.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| mechanism-smoke-r35-q025-r200-16f-tcp-r1 | tcp | 200 | 0.25 | 16 | 32.80 | 0.000 | 0.002 | 0.00 | 0 | stable |
| mechanism-smoke-r35-q025-r200-16f-tcp-r2 | tcp | 200 | 0.25 | 16 | 33.08 | 0.000 | 0.001 | 0.00 | 0 | stable |
| mechanism-smoke-r35-q025-r200-16f-udp-r1 | udp | 200 | 0.25 | 16 | 34.02 | 0.000 | 0.000 | 0.00 | 0 | stable |
| mechanism-smoke-r35-q025-r200-16f-udp-r2 | udp | 200 | 0.25 | 16 | 34.02 | 0.000 | -0.000 | 0.00 | 0 | stable |
