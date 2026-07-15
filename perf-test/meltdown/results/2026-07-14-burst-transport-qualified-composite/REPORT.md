# Generated TCP Meltdown Results

Generated: 2026-07-14T18:03:20.803221+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 0 |
| degraded | 3 |
| near-meltdown | 1 |
| meltdown | 0 |
| invalid | 0 |

Near-meltdown cells: 1. Valid cells: 4 / 4.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| burst-transport-qualified-smoke-ge2-25-90-1-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.24 | 0.732 | -2.051 | 0.06 | 0 | near-meltdown |
| burst-transport-qualified-smoke-ge2-25-90-1-r200-q1-16f-tcp-r2 | tcp | 200 | 1 | 16 | 1.09 | 0.733 | 2.703 | 0.69 | 0 | degraded |
| burst-transport-qualified-smoke-ge2-25-90-1-r200-q1-16f-udp-r1 | udp | 200 | 1 | 16 | 3.91 | 0.000 | -0.043 | 5.12 | 0 | degraded |
| burst-transport-qualified-smoke-ge2-25-90-1-r200-q1-16f-udp-r2 | udp | 200 | 1 | 16 | 3.82 | 0.000 | 0.174 | 5.69 | 0 | degraded |
