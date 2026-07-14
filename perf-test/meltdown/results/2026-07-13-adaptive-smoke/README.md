# Adaptive Queue Smoke

This campaign ran the four predeclared matched TCP/UDP executions at 35 Mb/s,
200 ms, 0.10x BDP, and 16 inner flows. All four cells are valid/stable.

Both TCP repetitions met the gate by recording finite-queue overflow: 60 and 5
drops. TCP delivered 27.75-29.05 Mb/s versus 33.94-33.98 Mb/s for the matched
UDP controls. No cell recorded an inner or outer RTO, outer retransmission,
outer recovery event, or negative goodput trend. The first TCP repetition had
4.0% zero-delivery bins and a 100 ms longest stall, below the predeclared 20%
threshold.

The 0.05x-BDP fallback was therefore not run. This evidence permits a separately
predeclared broader adaptive mechanism matrix; it does not release the original
12 rows gated by the failed 0.25x-BDP smoke.

Runtime identity:

- source checkpoint: `2b9513fb04de2b59bfe0ce305b9d2bb8bed82548`
- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- campaign fingerprint:
  `3a9925c1ec5b8867e51c2624931aa44411db3bb37a14f84d8781cf0bee0bb0cd`

`cells.csv` includes measurement-window sampled peak backlog. TCP peaked at
66,408-66,804 of 87,500 bytes (75.9-76.3%); UDP peaked at 85,158 bytes (97.3%).
Discrete samples need not observe the instantaneous full queue, so the
monotonic drop counters remain the overflow gate.
