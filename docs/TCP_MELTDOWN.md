# TCP-over-TCP Meltdown: Measured Scope and Reproduction

## Bottom line

The completed WireguardTCP campaign did **not** produce a valid formal
TCP-over-TCP meltdown result. None of 122 valid post-repair executions crossed
all three predeclared conditions for sustained zero delivery, significant
goodput decline, and inner TCP timeouts.

The campaign did produce severe TCP-specific stalls, but only inside a
deliberately harsh laboratory envelope combining:

- 16 continuously backlogged inner CUBIC flows;
- a 50 Mb/s carrier and a 1x-BDP FIFO;
- 200-400 ms configured RTT;
- persistent random or Gilbert-Elliott burst loss; and
- 60-second reverse-direction bulk workloads.

That conjunction is not representative of a healthy, well-managed wired or
datacenter path. Similar conditions can occur transiently on congested mobile,
interfered Wi-Fi, satellite, mobility-handoff, or overloaded tunnel paths, so
the mechanism remains operationally relevant. The campaign measures a failure
mode, not its prevalence.

The evidence supports this precise statement:

> Within the tested matrix, severe TCP-over-TCP degradation appeared only in
> deliberately extreme loss, latency, queue, and concurrency combinations.
> Formal meltdown was not established. The lower onset threshold was not
> measured, so the results do not prove either universal immunity or that every
> possible pathological case requires exactly this envelope.

## Stable controls

The patched transport completed 82 clean calibration and finite-queue/RTT
screening cells as valid/stable. Representative 16-flow TCP controls were:

| Carrier condition | Result |
|---|---|
| 50 Mb/s, 200 ms RTT, 0.5x/1x/4x-BDP FIFO, no induced loss | 46.74-47.28 Mb/s, no zero-delivery stalls |
| 50 Mb/s, 400 ms RTT, 1x-BDP FIFO, no induced loss | 47.20-47.23 Mb/s, no zero-delivery stalls |
| 100-400 ms no-loss RTT sweep | Stable; one 250 ms repetition had isolated 100 ms zero-delivery bins |

High RTT, a finite FIFO, and 16 flows therefore did not trigger the measured
pathology by themselves. Every valid logical TCP breadth execution with at
least 52.8% stalled bins also recorded outer recovery.

## Lowest demonstrated severe profile

The lowest-severity profile that produced valid severe TCP degradation used:

| Axis | Value |
|---|---|
| Carrier rate | 50 Mb/s |
| Configured RTT | 200 ms |
| Queue | 1x-BDP `bfifo` |
| Inner workload | 16 CUBIC flows for 60 seconds |
| Loss model | netem Gilbert-Elliott `P=1%`, `R=25%`, `1-H=90%`, `1-K=1%` |
| Nominal stationary loss | 4.42% per impaired direction |
| Mean bad-state residence | approximately four packets |

The two valid TCP repetitions delivered:

| Repetition | Goodput | Zero-delivery bins | Longest continuous stall | Outer recovery events |
|---|---:|---:|---:|---:|
| r1 | 1.09 Mb/s | 52.8% | 0.7 s | 145 |
| r2 | 0.73 Mb/s | 62.2% | 6.3 s | 134 |

TCP self-clocking made realized netem drop fractions adaptive: aggregate
measured loss was 1.65%-1.95%, while per-endpoint extrema across the two
repetitions ranged from 1.15% to 4.60%. The configured stochastic model, not a
single observed percentage, is the reproducible impairment input.

This profile is the **lowest demonstrated point**, not an onset threshold. A
planned 0.3% random-loss onset row remained disabled and was never executed.
The campaign therefore bounds the transition only between stable no-loss
controls and the 4.42%-nominal burst profile.

## Stall persistence

A stall is a 100 ms receiver interval with exactly zero delivered inner bytes.
Across the nine valid logical TCP breadth cells, the longest uninterrupted
stall in each 60-second execution was:

```text
0.7 s, 1.1 s, 1.3 s, 2.2 s, 6.3 s, 13.2 s, 25.0 s, 29.6 s, 40.2 s
```

The median longest stall was 6.3 seconds. The most persistent profile used
longer Gilbert-Elliott bad-state residence and produced 29.6-40.2 second
continuous stalls. The 40.2-second run resumed; the 29.6-second run reached the
end of its 60-second measurement window and is right-censored, so its duration
is a lower bound. The campaign did not test whether a longer impairment would
remain bounded.

Matched UDP controls delivered 1.34-5.81 Mb/s with 0%-4% zero-delivery bins,
while the valid TCP cells delivered 0.07-1.09 Mb/s with 52.8%-94.0% stalled
bins. This difference is evidence of outer-stream head-of-line amplification,
not evidence that ordinary paths commonly enter that state.

## Formal classification

The fixed definition is in
[`perf-test/meltdown/TESTPLAN.md`](../perf-test/meltdown/TESTPLAN.md). A valid
execution is formal `meltdown` only when all three conditions hold:

1. at least 20% of 100 ms delivery bins stall;
2. fitted goodput declines by at least 20% with slope t statistic at most -2;
3. inner TCP records at least one RTO per flow-minute.

No valid execution met all three. Several met one or two conditions and are
reported as `degraded` or `near-meltdown`; invalid evidence is never promoted.

## Reproduce and inspect

The complete harness, immutable matrices, validity rules, compact results, and
run instructions live under
[`perf-test/meltdown/`](../perf-test/meltdown/README.md). Start with:

- [`README.md`](../perf-test/meltdown/README.md) for host preparation, execution,
  reanalysis, and stall-timeline commands;
- [`TESTPLAN.md`](../perf-test/meltdown/TESTPLAN.md) for fixed definitions and
  validity gates;
- [`INVESTIGATION_STATUS.md`](../perf-test/meltdown/INVESTIGATION_STATUS.md) for
  the complete engineering record;
- [`results/2026-07-14-final-audit/`](../perf-test/meltdown/results/2026-07-14-final-audit/)
  for the 162-execution ledger; and
- the breadth base and rerun `cells.csv` files for published stall fractions,
  longest stalls, loss counters, recovery events, and classifications.

Raw per-cell series are intentionally not committed. A reproduced campaign
retains `interface-series.csv`, qdisc, socket, BPF, iperf, and counter artifacts
under its gitignored `results/<campaign>/cells/<cell>/` directory. The harness
can regenerate classifications and export every contiguous zero-delivery
interval without changing the historical evidence.

## Limits

- The traffic evidence belongs to its recorded campaign runtime. The current
  source separately passes 213 local tests plus focused NAT/recovery and
  hostile-stream gates; those correctness results do not retroactively alter
  the historical performance cells.
- AQM/ECN, jitter, reordering, blackout, competing traffic, bidirectional
  traffic, alternate inner congestion controls, short-flow completion, and
  multi-hour endurance remain untested.
- Two configured outer carriers were present in this campaign. The current
  implementation supports single-private, responder-only operation, but this
  historical traffic result is not silently reclassified as a measurement of
  that later topology.
- This campaign establishes neither a production SLA nor the frequency of the
  tested impairment combination on deployed networks.
