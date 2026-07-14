# Transport-Aware Exact TCP Rerun

This targeted campaign is the single predeclared exact rerun of the base gate's
invalid TCP r1 cell. It preserves campaign fingerprint
`fa67fca2da8eccc0636d5b7a6898a7765067cf2bce308f60d14157077806ebed`
and cell fingerprint
`d60c5672360879c10f74da17a1e4b18d1386f4aecbf372e59adb2f1ac32baaba`.

The rerun is valid/near-meltdown:

- 0.236 Mb/s receiver delivery;
- 73.2% zero-delivery bins and an 8-second longest stall;
- 20.5% fitted goodput decline with slope `t=-6.91`;
- 143 outer-recovery events;
- 0.0625 inner RTO events per flow-minute.

It does not meet the formal meltdown definition because the inner RTO rate is
below 1 per flow-minute. The full 59.9-second interval series, allowlisted
final-control fallback, clean 10/10 baseline control, exact impairment and
counter evidence, carrier coverage, and CPU-sequence telemetry all passed.
This exhausts the bounded retry allowance.
