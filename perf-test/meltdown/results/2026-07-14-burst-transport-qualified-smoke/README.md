# Transport-Aware Burst Qualification Base

This is the complete four-cell base campaign for the bounded transport-aware
qualification gate. It retained the exact 50 Mb/s, 200 ms, 1x-BDP, 16-flow,
60-second Gilbert-Elliott `2/25/90/1` operating point and campaign fingerprint
`fa67fca2da8eccc0636d5b7a6898a7765067cf2bce308f60d14157077806ebed`.

Three cells are valid/degraded. TCP r2 is the first valid TCP execution with
forced outer recovery:

| Execution | Validity/class | Goodput | Stalls | Inner RTO/flow-min | Outer recovery |
|---|---|---:|---:|---:|---:|
| TCP r1 | invalid | n/a | n/a | 0 | 0 |
| TCP r2 | valid/degraded | 1.092 Mb/s | 73.3% | 0.688 | 129 |
| UDP r1 | valid/degraded | 3.908 Mb/s | 0% | 5.125 | 1 |
| UDP r2 | valid/degraded | 3.822 Mb/s | 0% | 5.688 | 7 |

TCP r1 stopped before meaningful workload evidence and failed workload
completion, delivery-bin coverage, queue-counter coverage, and shaped-class
usage. The fixed protocol allowed one exact rerun of this invalid cell. No
other cell was rerun.

All four clean pre-impairment controls passed 10/10 with zero loss and
0.238-0.339 ms mean RTT. The source campaign's eight endpoint traces contain
5,127 sequence-bearing event rows across 74 event/layer/CPU streams, all
reconciled through their terminal values.

Runtime identity:

- module srcversion: `01DA86291E0FBD2CD3C940C`
- module SHA-256:
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`
- tool SHA-256:
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`
- iperf SHA-256:
  `626565d9571f0ebb9148a36944beeaafa9b7581884f11c11b7fd1cf4218f5ad4`
