# Generated TCP Meltdown Results

Generated: 2026-07-14T21:39:02.201409+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 0 |
| degraded | 7 |
| near-meltdown | 7 |
| meltdown | 0 |
| invalid | 6 |

Near-meltdown cells: 7. Valid cells: 14 / 20.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| burst-breadth-ge1-12p5-90-1-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.48 | 0.937 | 2.991 | 0.00 | 0 | degraded |
| burst-breadth-ge1-12p5-90-1-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.25 | 0.915 | -0.920 | 1.94 | 0 | near-meltdown |
| burst-breadth-ge1-12p5-90-1-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 4.42 | 0.000 | -0.029 | 7.88 | 0 | degraded |
| burst-breadth-ge1-12p5-90-1-r200-q1-16f-udp-r2 | udp | 200 | 1 | 16 | 4.50 | 0.002 | 0.070 | 6.19 | 0 | degraded |
| burst-breadth-ge1-25-90-1-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 1.09 | 0.528 | 1.018 | 0.00 | 0 | degraded |
| burst-breadth-ge1-25-90-1-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.73 | 0.622 | -1.024 | 0.00 | 0 | near-meltdown |
| burst-breadth-ge1-25-90-1-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 5.92 | 0.000 | 0.084 | 1.44 | 0 | invalid |
| burst-breadth-ge1-25-90-1-r200-q1-16f-udp-r2 | udp | 200 | 1 | 16 | 5.81 | 0.000 | 0.169 | 1.06 | 0 | degraded |
| burst-breadth-ge2-25-90-1-r400-q1-16f-tcp-r1 | tcp | 400 | 1 | 16 | 0.51 | 0.717 | -1.563 | 0.00 | 0 | near-meltdown |
| burst-breadth-ge2-25-90-1-r400-q1-16f-tcp-r2 | tcp | 400 | 1 | 16 | 0.49 | 0.790 | -2.792 | 0.00 | 0 | invalid |
| burst-breadth-ge2-25-90-1-r400-q1-16f-udp-r1 | udp | 400 | 1 | 16 | 2.39 | 0.007 | -0.219 | 2.38 | 0 | near-meltdown |
| burst-breadth-ge2-25-90-1-r400-q1-16f-udp-r2 | udp | 400 | 1 | 16 | 2.37 | 0.010 | -0.030 | 2.62 | 0 | degraded |
| burst-breadth-ge4-25-90-1-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.07 | 0.892 | -0.097 | 1.00 | 0 | near-meltdown |
| burst-breadth-ge4-25-90-1-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.00 | 0.993 | -0.444 | 2.31 | 0 | invalid |
| burst-breadth-ge4-25-90-1-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 1.34 | 0.040 | -0.740 | 15.38 | 0 | near-meltdown |
| burst-breadth-ge4-25-90-1-r200-q1-16f-udp-r2 | udp | 200 | 1 | 16 | 1.78 | 0.020 | -1.021 | 14.38 | 0 | near-meltdown |
| burst-breadth-random7p5-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.31 | 0.510 | -0.109 | 0.00 | 0 | invalid |
| burst-breadth-random7p5-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 0.34 | 0.503 | -0.259 | 0.06 | 0 | invalid |
| burst-breadth-random7p5-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 3.01 | 0.000 | 0.010 | 3.12 | 0 | invalid |
| burst-breadth-random7p5-r200-q1-16f-udp-r2 | udp | 200 | 1 | 16 | 2.88 | 0.000 | 0.119 | 2.81 | 0 | degraded |
