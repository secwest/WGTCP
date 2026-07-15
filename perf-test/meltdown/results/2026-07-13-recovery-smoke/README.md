# Outer-Recovery Smoke

This campaign ran the four predeclared matched TCP/UDP executions at 35 Mb/s,
200 ms, 0.05x BDP, and 16 inner flows. The gate required both TCP repetitions
to be valid and overflow, with at least one outer retransmission or RTO.

The gate failed:

- TCP repetition 1 is valid/degraded: 14.54 Mb/s versus 33.18 Mb/s for its UDP
  control, a 0.438 goodput ratio, 14.3% zero-delivery bins, and 273 queue
  drops. It met none of the three primary meltdown conditions and had no outer
  retransmission or RTO.
- TCP repetition 2 delivered 2.79 Mb/s with 42.7% zero-delivery bins and 528
  queue drops, but is invalid because iperf could not receive its final results
  and exited nonzero. It had no scored outer retransmission or RTO.
- Both UDP controls are valid/stable at 33.05-33.18 Mb/s with zero stalls.

The invalid TCP repetition was retained and rerun in a separate campaign. The
12 broader recovery executions were not run.

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- campaign fingerprint:
  `f18533c06e354f62aac4d48daf9774fa4368437632da3a889fa385511c1758c8`
