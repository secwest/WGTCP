# Lower-Rate Mechanism Smoke

This campaign ran the four predeclared matched TCP/UDP smoke executions at
35 Mb/s, 200 ms, 0.25x BDP, and 16 inner flows. All four cells are valid/stable,
with zero queue drops, stalls, inner/outer RTOs, or outer recovery events.

The gate for the 12 broader mechanism executions was observed finite-queue
overflow. It was not met, so those rows were not run.

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `05d0d5830adb04dfb16d80797b891a9cb1b45cc36bc6fd5eb82790aa372bbd6a`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- campaign fingerprint:
  `a9927e52a1a1a05f9ddb33c2357dcade3e711b4151032e3d82481324a008d24b`

`queue-occupancy.csv` is a supplemental diagnostic computed over each exact
measurement window. The sender-side sampled peak was 130,548 of 218,750 bytes
(59.7%); the other sender-side peaks were 11.0%, 47.1%, and 46.4%. HTB
overlimits show rate-shaper deferrals and are not packet drops.
