# WireguardTCP Baseline Performance Test Campaign

This directory contains the **design**, **test harness**, and **orchestration**
for the comprehensive performance benchmark of WireguardTCP-baseline (TCP
transport in the kernel module) against stock WireGuard (UDP), across multiple
geographies, architectures, and packet-loss conditions.

**Latest results: see [`REPORT.md`](REPORT.md)** — TCP-base tunnel vs UDP
tunnel, per workload × per link-distance tier, with throughput / latency /
CPU and TCP-vs-UDP percentage deltas.

For the separate physical-carrier TCP-over-TCP stress campaign, calibrated
conclusions, and raw-stall workflow, see
[`../docs/TCP_MELTDOWN.md`](../docs/TCP_MELTDOWN.md) and
[`meltdown/README.md`](meltdown/README.md). That campaign is a causal
corner-case investigation, not a statement that ordinary modern paths
typically enter meltdown.

While a campaign is in flight, run `harness/refresh-report.ps1` in a side
terminal to keep `REPORT.md` and `matrix.csv` updated as cells finish:

```powershell
.\harness\refresh-report.ps1 `
    -ResultsDir <campaign>\results\baseline-1.0.0-p2p `
    -RepoRoot   <local-clone-of-this-repo> `
    -IntervalSeconds 600
```

It re-runs `aggregate.py` + `summary-report.py` on a timer and commits +
pushes any diffs.

---

## Files

```
perf-test/
  README.md              # this file (campaign overview + how to run)
  TESTPLAN.md            # full test design — measurement matrix, methodology,
                         # statistical model, repeatability rules
  harness/
    run-cell.sh          # runs ONE matrix cell (one workload, one loss rate)
                         # on a (server, client) pair already provisioned
    workloads/
      short-transfer.sh  # 1 KB / 64 KB / 1 MB curl rounds
      long-transfer.sh   # 1 GB iperf3 stream (TCP) / 1 GB UDP iperf3
      web-mix.sh         # synthetic HTTP mixed-size pull (h2load)
      ssh-interactive.sh # 60s of small RTT echo measurements (ping over wg + ssh keystroke RTT)
    setup-tunnel.sh      # idempotent — brings up wg-udp0 + wg-tcp0 between two peers
    setup-netem.sh       # applies tc netem loss to the wg/eth interface
    collect-metrics.sh   # pulls iperf3 JSON, tc -s qdisc stats, mpstat, per-test logs
    aggregate.py         # parses raw cell JSON outputs into one matrix CSV
  orchestrator/
    deploy-fleet.ps1     # provisions hub + spoke VMs in 4 regions, x64 + arm64
    run-campaign.ps1     # walks the full matrix, calls run-cell.sh on each pair
    teardown-fleet.ps1   # deletes everything (RG-scoped)
  results/               # per-version subdir; raw JSON + final CSV/markdown report
    v1.0.0/
    v<next>/
  REPORT-TEMPLATE.md     # pasteable structure for the final per-version report
```

---

## High-level flow

1. **Read** [`TESTPLAN.md`](./TESTPLAN.md) — describes the matrix, methodology,
   and what "good" means.
2. **Provision the fleet:**
   ```pwsh
   .\orchestrator\deploy-fleet.ps1 `
       -Subscription <id> -ResourceGroup rg-wgtcp-perf `
       -ImageVersion 1.0.0 `
       -RegionsX64 canadacentral,westus3,australiaeast,southafricanorth `
       -RegionsArm canadacentral,westus3,australiaeast,southafricanorth
   ```
3. **Run the matrix:**
   ```pwsh
   .\orchestrator\run-campaign.ps1 -ResultsDir .\results\v1.0.0
   ```
   Expect ≈ 24h on the default settings.
4. **Aggregate + report:**
   ```pwsh
   python .\harness\aggregate.py .\results\v1.0.0 -o .\results\v1.0.0\matrix.csv
   ```
   Use [`REPORT-TEMPLATE.md`](./REPORT-TEMPLATE.md) to write the
   per-version analysis. Commit the report.
5. **Teardown:**
   ```pwsh
   .\orchestrator\teardown-fleet.ps1 -ResourceGroup rg-wgtcp-perf
   ```

---

## Comparing versions

Each module/userland change should produce a fresh image version. The
historical parent repository's image-build runbook is not included in this
standalone tree; use the gallery prerequisites in [`RUNBOOK.md`](RUNBOOK.md).
To compare versions:

1. Build & publish a new gallery image (`<ver+1>`).
2. Re-run the campaign against the same RG with `-ImageVersion <ver+1>`,
   storing under `results/v<ver+1>/`.
3. Diff the matrix CSVs (`harness/diff-matrices.py results/v<a>/matrix.csv
   results/v<b>/matrix.csv > results/diff-<a>-vs-<b>.md`).

Identical region/size/loss/workload definitions across runs is the only way
to make the comparison meaningful — **do not** vary the deployment
parameters between versions.

---

## What the campaign measures

For each (region-pair, architecture, tunnel-type, workload, loss-rate) cell:

- **Throughput**: goodput (Mbps) for bulk; req/s for short/web; cps for ssh.
- **Latency**: p50 / p95 / p99 / max RTT (ms).
- **Jitter**: stdev of RTT (ms).
- **Tunnel CPU cost**: % CPU on the encrypting endpoint, per Mbps.
- **Retransmits / loss recovery time**: from `ss -ti` and netem stats.
- **First-byte latency** (web/short): time-to-first-byte (ms).

Baseline = same network path, NO tunnel (raw TCP/UDP), under the same
netem loss. Every tunnel measurement is reported as both absolute and as
a ratio over baseline ("tunnel overhead").

See `TESTPLAN.md` §5 for the full metric list and §7 for the analysis model.
