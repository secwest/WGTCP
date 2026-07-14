# Generated TCP Meltdown Results

Generated: 2026-07-14T18:08:22.765472+00:00

Full meltdown observed under the predeclared definition: **NO**.

| classification | cells |
|---|---:|
| stable | 0 |
| degraded | 0 |
| near-meltdown | 1 |
| meltdown | 0 |
| invalid | 0 |

Near-meltdown cells: 1. Valid cells: 1 / 1.

| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| burst-transport-qualified-smoke-ge2-25-90-1-r200-q1-16f-tcp-r1 | tcp | 200 | 1 | 16 | 0.24 | 0.732 | -2.051 | 0.06 | 0 | near-meltdown |
