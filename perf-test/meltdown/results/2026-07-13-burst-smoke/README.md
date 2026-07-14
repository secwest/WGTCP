# Gilbert-Elliott Burst-Recovery Smoke

This campaign ran the four predeclared matched TCP/UDP executions at 50 Mb/s,
200 ms, 1x BDP, and 16 inner flows with netem Gilbert-Elliott arguments
`2/25/90/99`. The gate required all four executions to be valid and at least
one TCP repetition to record an outer retransmission or RTO.

The gate failed before workload:

- the live qdisc on both endpoints exactly matched the declared loss model and
  probabilities in every cell;
- all four tunnel preflight probes had 100% loss, so no workload delivery
  interval began;
- all four cells are invalid and provide no meltdown or outer-recovery
  evidence;
- no broader burst rows were released.

Netem's final two Gilbert-Elliott arguments are `1-H` and `1-K`, not `H` and
`K`. The declared `1-K=99%` therefore means 99% loss even in the good state.
With `P=2%`, `R=25%`, and `1-H=90%`, the nominal stationary loss is about
98.3% per impaired direction. A corrected severity must be predeclared under a
new fingerprint rather than changing this completed campaign.

The severe preflight retired one TCP carrier per endpoint. No impairment or
transient sampler remained, and the preparation-only recovery path restored two
carriers per endpoint plus zero-loss TCP and UDP controls.

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- campaign fingerprint:
  `b2078458ae90eb235273939234ae39b58367cdc1ab73f65b713d4ade74184a64`
