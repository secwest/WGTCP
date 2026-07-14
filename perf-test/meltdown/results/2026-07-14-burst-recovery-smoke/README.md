# Corrected Gilbert-Elliott Burst-Recovery Smoke

This campaign ran the four predeclared matched TCP/UDP executions at 50 Mb/s,
200 ms, 1x BDP, and 16 inner flows with netem Gilbert-Elliott arguments
`2/25/90/1`. Nominal stationary loss is 7.59% per impaired direction. The gate
required all four executions to be valid and at least one TCP repetition to
record an outer retransmission or RTO.

An earlier launch under the same fingerprint stopped 0/4 before workload
because the server-side inner iperf service was absent. Its incomplete
directory remains diagnostic evidence and is not counted as a cell execution.
The preparation-only path restored the service, matching runtime, two carriers,
and clean controls before this complete retry.

The gate demonstrated outer recovery but failed validity:

| Execution | Validity/class | Goodput | Stalls | Inner RTO | Outer retrans/RTO |
|---|---|---:|---:|---:|---:|
| TCP r1 | invalid | 0.95 Mb/s | 57.7% | 0 | 181 / 25 |
| TCP r2 | invalid | 0.027 Mb/s | 96.7% | 25 | 33 / 13 |
| UDP r1 | valid/degraded | 4.10 Mb/s | 0.2% | 91 | 4 / 0 |
| UDP r2 | invalid | 3.77 Mb/s | 0% | 100 | 2 / 0 |

TCP r1 failed workload finalization and one endpoint's realized-loss band. TCP
r2 failed workload finalization and had a two-event tracer summary mismatch.
UDP r2 had a four-event tracer summary mismatch. TCP r1 had stalls and a
significant negative trend but no inner RTO; TCP r2 had stalls and inner RTOs
but a positive trend. No valid execution met the full meltdown definition.

All three invalid cells were retained and rerun exactly in a separate campaign.
Post-campaign checks found two carriers per endpoint, restored qdiscs, no
impairment or transient units, and zero-loss TCP/UDP controls.

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- campaign fingerprint:
  `9eafa9f42d7ee71e2b0b96d32811b298c1db6b32751fb9b14b22c56a0327878b`
