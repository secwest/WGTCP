# Generated TCP Meltdown Results

Generated: 2026-07-14T22:47:21.275840+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 0 |
| degraded | 3 |
| near-meltdown | 2 |
| meltdown | 0 |
| invalid | 1 |

Near-meltdown cells: 2. Valid cells: 5 / 6.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| burst-breadth-ge1-25-90-1-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 5.53 | 0.000 | -0.268 | 1.31 | 0 | near-meltdown |
| burst-breadth-ge2-25-90-1-r400-q1-16f-tcp-r2 | tcp | 400 | 1 | 16 | 0.86 | 0.708 | 0.375 | 0.69 | 0 | degraded |
| burst-breadth-ge4-25-90-1-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.24 | 0.940 | 1.382 | 1.19 | 0 | near-meltdown |
| burst-breadth-random7p5-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.22 | 0.547 | 0.129 | 0.00 | 0 | invalid |
| burst-breadth-random7p5-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.25 | 0.528 | -0.029 | 0.12 | 0 | degraded |
| burst-breadth-random7p5-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 3.04 | 0.000 | 0.122 | 2.75 | 0 | degraded |
