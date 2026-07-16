# Timed Boundary Stage 1 Smoke

The four predeclared transition-smoke executions completed across two matched
ARM VM pairs. All four were valid/stable, all timed-transition and telemetry
gates passed, and no execution met the quasi-meltdown or formal-meltdown
endpoint. These smoke executions qualify the harness but are excluded from the
boundary estimate.

| Execution | Pair | Impaired rate | Longest stall | Recovery to 90% | Outer recovery | Result |
|---|---|---:|---:|---:|---:|---|
| TCP r1 | `wgtcp-amp-b/a` | 31.400 Mb/s | 0.4 s | 14.049 s | 26 | valid/stable |
| UDP r1 | `wgtcp-amp-b/a` | 42.392 Mb/s | 0 s | 4.148 s | 0 | valid/stable |
| TCP r2 | `wgtcp-boundary-b/a` | 44.784 Mb/s | 0.2 s | 9.848 s | 32 | valid/stable |
| UDP r2 | `wgtcp-boundary-b/a` | 41.035 Mb/s | 0 s | 4.748 s | 0 | valid/stable |

The two-second reference epoch produced user-visible recovery delay in both TCP
outer-transport repetitions, but neither produced the required one-second
zero-delivery stall. TCP sustained recovery was 2.07-3.39 times slower than its
matched UDP control. The maximum observed transition skew was 9.564 ms, the
maximum conservative clock-error bound was 0.032 ms, and the realized epochs
were 1.990-1.996 seconds. Both carriers remained present with unchanged tuples,
and all four hosts restored their baseline `mq`/`fq_codel` state with no IFB or
impairment marker residue.

The pair-specific campaign fingerprints are
`f6b9c9647efd0ec35cb5f37fe94aaceb4a2fd376db8f4a05a2d994dca313bc52`
for r1 and
`9623a87bfc38c615ef114030a235f1ccbeae3125d81fea3a9e38e69210525576`
for r2. Both used:

- module srcversion `01DA86291E0FBD2CD3C940C`;
- module SHA-256
  `771057ae270ae379e90bc9c31f8f8777e54556d8acbb71b8717e6a950dca275e`;
- tool SHA-256
  `80455e74d7dc4b5fc22cdfcfadaf5addcad603cf54a70bb298a558c6fe65c4a3`;
  and
- iperf SHA-256
  `626565d9571f0ebb9148a36944beeaafa9b7581884f11c11b7fd1cf4218f5ad4`.

[`cells.csv`](cells.csv) is the compact cross-pair inventory. Raw endpoint,
qdisc, socket, BPF, transition, and workload evidence remains in the two
immutable campaign artifact directories.
