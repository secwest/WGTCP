# Generated TCP Meltdown Results

Generated: 2026-07-14T07:29:10.433270+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 0 |
| degraded | 0 |
| near-meltdown | 0 |
| meltdown | 0 |
| invalid | 3 |

Near-meltdown cells: 0. Valid cells: 0 / 3.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| burst-recovery-smoke-ge2-25-90-1-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.07 | 0.937 | -3.488 | 1.31 | 0 | invalid |
| burst-recovery-smoke-ge2-25-90-1-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.81 | 0.640 | 0.930 | 1.19 | 0 | invalid |
| burst-recovery-smoke-ge2-25-90-1-r200-q1-16f-udp-r2 | udp | 200 | 1 | 16 | 3.76 | 0.007 | 0.580 | 7.19 | 0 | invalid |
