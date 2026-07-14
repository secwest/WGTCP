# Generated TCP Meltdown Results

Generated: 2026-07-14T00:31:39.796180+00:00

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
| adaptive-smoke-r35-q010-r200-16f-tcp-r1 | tcp | 200 | 0.1 | 16 | 27.75 | 0.040 | 0.444 | 0.00 | 60 | stable |
| adaptive-smoke-r35-q010-r200-16f-tcp-r2 | tcp | 200 | 0.1 | 16 | 29.05 | 0.000 | 0.572 | 0.00 | 5 | stable |
| adaptive-smoke-r35-q010-r200-16f-udp-r1 | udp | 200 | 0.1 | 16 | 33.94 | 0.000 | 0.006 | 0.00 | 749 | stable |
| adaptive-smoke-r35-q010-r200-16f-udp-r2 | udp | 200 | 0.1 | 16 | 33.98 | 0.000 | 0.003 | 0.00 | 718 | stable |
