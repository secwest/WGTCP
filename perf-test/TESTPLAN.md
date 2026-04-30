# Test Plan — WireguardTCP-FAST vs WireGuard UDP

## 1. Goals

1. Quantify how WireguardTCP-FAST (TCP transport with adaptive CC + DSACK +
   four-zone tuning) compares against stock WireGuard (UDP) in workloads that
   stress the tunnel differently:
   - bulk goodput (long file transfers),
   - small-RTT-bound traffic (short transfers, ssh keystrokes),
   - mixed bursty (web).
2. Map the comparison across **distance** (same DC → intercontinental) and
   **packet loss** (clean → 20%) — the conditions where TCP transport is
   hypothesized to outperform UDP.
3. Repeat across **x86_64** and **ARM64** to confirm CPU-bound behaviour
   is consistent.
4. Produce a CSV matrix that survives version bumps so improvements (or
   regressions) can be tracked over time.

## 2. Hypotheses

H1. **Short distance, clean link**: UDP and TCP transports perform
    indistinguishably; tunnel overhead dominates the WireGuard work, not
    the transport.

H2. **Long distance, clean link**: TCP transport adds connection-setup latency
    but matches UDP throughput once warm. ssh interactive jitter slightly
    higher for TCP transport (head-of-line blocking).

H3. **Any distance, ≥ 1% loss**: TCP transport's congestion control + DSACK
    recovers faster than UDP-WireGuard's "reset & rekey" behaviour on
    sustained loss. Goodput crossover expected near 1–3% loss.

H4. **Heavy loss (≥ 10%)**: Stock UDP WireGuard collapses (effective goodput
    < 10% of clean baseline). TCP transport degrades gracefully to ~50%.

H5. **ARM64 vs x86_64**: At the same loss/distance, ARM64 (Cobalt 100)
    achieves ≥ 80% of x86_64 (D2s_v5) throughput at less than 80% of the
    CPU cost.

These hypotheses dictate **what the matrix must measure** to either confirm
or refute. Reporting must include success/failure of each.

## 3. Independent variables (the matrix)

| Axis | Values | n |
|---|---|---|
| **Workload** | short-transfer, long-transfer, web-mix, ssh-interactive | 4 |
| **Tunnel** | wireguard-udp (stock), wireguard-tcp-fast | 2 |
| **Architecture** | x86_64 (D2s_v5), arm64 (D2ps_v6) | 2 |
| **Region pair** | LAN (intra-canadacentral, peered VNets), MED (cc↔westus3), HIGH (cc↔australiaeast), MAX (cc↔southafricanorth or qatarcentral, whichever has greater RTT) | 4 |
| **Loss** (applied at server egress, both directions) | 0%, 0.5%, 1%, 2%, 3%, 5%, 10%, 20% | 8 |

Total cells: **4 × 2 × 2 × 4 × 8 = 512**.
Plus baseline (no tunnel) at the same 4 workloads × 4 region pairs × 2 archs ×
8 loss = 256 baseline cells. **Grand total: 768 cells.**

### Tunnel and arch are nested under "VM pair"
Each VM pair runs both UDP and TCP tunnels (different `wg-quick` interfaces).
Arch is fixed at deploy time per VM pair. The eight loss rates are applied
sequentially on the same pair.

## 4. Fixed parameters (controls)

- **VM size**: x64 = `Standard_D2s_v5` (2 vCPU, 8 GB, AccelNet on);
  arm64 = `Standard_D2ps_v6` (2 vCPU, 8 GB, AccelNet on).
- **Image**: gallery image `wireguardtcp-fast-ubuntu24-tls/<ver>` (x64) or
  `wireguardtcp-fast-ubuntu24-arm64-tls/<ver>` (arm64). Trusted Launch + SB on.
- **Kernel**: `6.8.12-wgtcp-wgtcp` (custom). UDP path uses the same module
  with `transport=udp`; TCP path uses `transport=tcp`. We are **not** using
  Canonical's stock wireguard; this isolates WG-implementation differences.
- **NIC**: AccelNet enabled (`--accelerated-networking true`); MTU 1500.
- **Tunnel MTU**: 1420 (WG default). Same for UDP and TCP.
- **CC algorithm**: TCP transport defaults — `wg_tcp_cc=cubic`,
  `wg_tcp_mode=adaptive`, `wg_tcp_zones_enabled=1`. Documented in the run.
- **iperf3**: version pinned via `apt show iperf3` log per cell.
- **Time of day**: campaign duration is uncontrolled — note start/end
  timestamps per cell; campaigns ≥ 24h smear diurnal effects.
- **Single-threaded encryption**: each tunnel pinned to one core via
  `taskset` to make CPU-cost measurements comparable.

## 5. Measured (dependent) variables

Per cell:

| Metric | Source | Aggregation |
|---|---|---|
| `goodput_mbps` | iperf3 JSON `end.streams.[].sender.bits_per_second / 1e6` | mean of 3 runs, also p50 |
| `cpu_pct_sender` | mpstat -P ALL 1 60, average over the run | mean |
| `cpu_pct_receiver` | mpstat on receiver | mean |
| `rtt_p50_ms`, `rtt_p95_ms`, `rtt_p99_ms`, `rtt_max_ms` | hping3 / fping over the tunnel during the test | percentiles |
| `jitter_stdev_ms` | std-dev of RTT samples | scalar |
| `retrans_count` | `ss -ti` snapshots every 5s during run | sum |
| `ttfb_ms` (web/short) | curl `time_starttransfer` | mean |
| `req_per_sec` (web/short) | h2load summary | mean |
| `connect_time_ms` (web) | curl `time_connect` | mean |
| `tx_bytes_on_wire` | `ip -s link show <wgN>` before/after | scalar |
| `goodput_overhead_pct` | `(tx_bytes_on_wire - payload_bytes) / payload_bytes * 100` | scalar |
| `tunnel_cpu_per_mbps` | `cpu_pct_sender / goodput_mbps` | scalar |
| `recovery_time_ms` (loss > 0) | time from netem-loss-applied to first goodput sample within 90% of clean | scalar |
| `kernel_log_anomalies` | grep dmesg for `wg-tcp|wireguard|panic|warning` since boot | int + sample lines |

Each cell is run **3 times**. Report mean + stddev; if stddev > 15% of mean,
the cell is flagged for re-run with sample size 5.

## 6. Workloads

### 6.1 short-transfer (`workloads/short-transfer.sh`)
- 200 sequential HTTPS GETs of 1 KB, 64 KB, 1 MB objects (3 sizes interleaved).
- Server: nginx serving static files.
- Reports: req/s, p50/p95 TTFB, mean connect time, total wall.
- Why: stresses connection-establishment + header overhead in tunnel.

### 6.2 long-transfer (`workloads/long-transfer.sh`)
- TCP path: `iperf3 -c <peer> -t 60 -P 4 -O 5 --json`.
- UDP path: `iperf3 -c <peer> -u -b 0 -t 60 -O 5 --json` with `-l 1200`.
- One run per direction (both A→B and B→A).
- Reports: goodput, retransmits, lost-percentage, jitter (UDP).
- Why: bulk goodput is the headline number.

### 6.3 web-mix (`workloads/web-mix.sh`)
- `h2load -n 5000 -c 50 -m 10 https://<peer>:8443/` against an nginx
  serving a synthetic mixed-size object set (10 KB to 500 KB, Zipf-distributed).
- Reports: req/s, p50/p95 latency, total bytes.
- Why: realistic mixed bursty pattern.

### 6.4 ssh-interactive (`workloads/ssh-interactive.sh`)
- Custom: opens an ssh ControlMaster session to peer, then sends 1000
  Enter keystrokes at 50ms intervals through that session, measuring
  echo-back time per keystroke.
- Also captures `ping -i 0.05 -c 1000 <peer>` over the tunnel for
  baseline RTT distribution.
- Reports: keystroke RTT p50/p95/p99/max, ping p99 jitter.
- Why: tail latency under interactive load is what WG users care about
  for ssh sessions over high-loss links.

## 7. Statistical model

- **Three-run mean** per cell. Outlier rejection: drop the run that has
  the largest absolute deviation from the median if it differs by > 25%.
  If after rejection only one run remains, schedule a re-run.
- Confidence intervals: 95% CI = mean ± 1.96 × (stddev / √n). Reported but
  not used for filtering at n=3.
- **Cell repeatability check**: every campaign starts and ends with the
  same canary cell (cc↔cc, x64, long-transfer-tcp, 0% loss). If end-canary
  differs from start by > 10%, the entire campaign is suspect and flagged
  in the report.

## 8. Network topology

```
                                   Hub: rg-wgtcp-perf-cc (canadacentral)
                                   ┌─────────────────────────────┐
                                   │  hub-x64    hub-arm         │
                                   │   (D2s_v5)  (D2ps_v6)       │
                                   │   wg-udp0   wg-tcp0         │
                                   └───┬─────────────────────────┘
                                       │ VNet peering (transit) +
                                       │ Public IP fallback
       ┌───────────────────────────────┼───────────────────────────────┐
       │                               │                               │
  ┌────▼──────────┐             ┌──────▼───────┐               ┌───────▼──────┐
  │ spoke-westus3 │             │ spoke-aus-east│               │ spoke-saf-n  │
  │  x64 + arm    │             │   x64 + arm   │               │   x64 + arm  │
  └───────────────┘             └───────────────┘               └──────────────┘
```

- All VMs in the same RG `rg-wgtcp-perf` for trivial teardown.
- Each region has its own VNet (10.10.0.0/16, 10.20.0.0/16, 10.30.0.0/16,
  10.40.0.0/16). VNets are peered to the hub for **intra-RG** routing on
  private IPs (avoids public Internet for the long-haul tests where we
  control conditions). Public-IP fallback exists for cells we want to
  measure over the public path explicitly.
- Each VM has a **single** primary NIC with one public IP (for
  orchestrator SSH only — perf traffic is entirely on the peering link).
- AccelNet on every NIC.

### Why VNet peering not VPN
We're trying to measure **WG over the underlying network**. Adding an
Azure VPN gateway would obscure the result. Peering gives us the
underlying inter-region path with no MS-managed encrypted overlay.

### Loss simulation
`tc qdisc add dev <wgN> root netem loss <X>% delay <Y>ms` is applied at
the **wg interface** (not eth) on the receiving side. This way the loss
sits *inside* the tunnel for the tunnel test (modelling endpoint-induced
packet loss like wifi, kernel drops) and at the **eth interface** for the
baseline (modelling raw network loss). Each cell records which mode it
used. Default for the matrix: **tunnel-internal** (wgN), since this is
the loss scenario WireGuard's CC actually has to react to.

## 9. Cell execution sequence

For each cell:

1. Reset: `tc qdisc del dev wg-udp0 root; tc qdisc del dev wg-tcp0 root`.
2. Bring up only the tunnel under test (down the other one to avoid
   contention).
3. Warm 5 seconds (tail of `iperf3 -O 5`, or 50 throwaway requests).
4. Apply netem loss (if > 0).
5. Record `t0`. Run workload. Record `t1`.
6. Snapshot `ip -s link show wg-X`, `ss -ti`, `tc -s qdisc show`,
   `mpstat`, `dmesg --since=t0`.
7. Tear down netem.
8. Sleep 5s.
9. Repeat from step 1 with next cell (or next run of same cell if n<3).

## 10. Run schedule

To finish in ≤ 24h:
- 768 cells × 90s = 19.2h pure run time.
- Add 10s overhead per cell (resets, snapshotting) → 21.3h.
- Add 30 min cumulative for orchestrator switching pairs → 21.8h.
- Run pairs **in parallel** (4 region pairs × 2 archs = 8 parallel pair
  campaigns), each running its own ~96 cells (8 loss × 4 workloads × 2
  tunnels × 1 arch × 1 region-pair × 3 runs = 192 actual measurements;
  192 × 90s = 4.8h with good parallelism).

Actual wall-clock target: **5–8 hours of measurement** + 30 min
provision/teardown.

## 11. Output format

Each cell emits **one JSON file** to `results/<version>/cells/`:

```
{
  "cell_id": "ccp-cc-x64-tcp-long-loss03-run2",
  "version": "1.0.0",
  "deployed_at": "2026-04-28T03:14:00Z",
  "ran_at": "2026-04-28T11:42:13Z",
  "axes": {
    "region_pair": "canadacentral-canadacentral",
    "arch": "x86_64",
    "tunnel": "wireguard-tcp-fast",
    "workload": "long-transfer",
    "loss_pct": 3.0,
    "run_index": 2
  },
  "controls": {
    "vm_size": "Standard_D2s_v5",
    "kernel": "6.8.12-wgtcp-wgtcp",
    "tunnel_cc": "cubic",
    "tunnel_mtu": 1420,
    "tunnel_mode": "adaptive",
    "iperf3_version": "3.16",
    "client_ip": "10.10.0.4",
    "server_ip": "10.10.0.5"
  },
  "metrics": {
    "goodput_mbps": 720.4,
    "rtt_p50_ms": 1.2, "rtt_p95_ms": 3.4, "rtt_p99_ms": 8.1, "rtt_max_ms": 19.2,
    "cpu_pct_sender": 64.2, "cpu_pct_receiver": 58.9,
    "retrans_count": 412,
    "ttfb_ms": null,
    "tx_bytes_on_wire": 5402345111,
    "tunnel_cpu_per_mbps": 0.089
  },
  "raw": {
    "iperf3_json_path": "raw/iperf3-…json",
    "ss_snapshots_path": "raw/ss-…txt",
    "mpstat_log_path":   "raw/mpstat-…log",
    "dmesg_excerpt":     ["wg-tcp: cc-zone transition C->B at 12.3s", …]
  },
  "anomalies": []
}
```

`aggregate.py` flattens these into one CSV with one row per cell, three
runs averaged into a single row (separate rows for std-dev fields).

## 12. Replication for future agents

To replicate this campaign with a different module version:

1. **Build a new gallery image** following `azure-image/RUNBOOK.md`. Use
   the same image-definition names (`-tls` and `-arm64-tls`) so this
   harness works unchanged.
2. **Update** the `-ImageVersion` parameter in `deploy-fleet.ps1`.
3. **DO NOT** change matrix axes between version runs — comparisons
   require identical cells. If a new axis is needed (e.g., a new CC
   algorithm), append it; never reuse an old cell ID with new semantics.
4. **DO** record the kernel build's signing-cert fingerprint in
   `results/<ver>/manifest.json` so the data is provably tied to a
   specific binary.
5. **Compare** with `harness/diff-matrices.py results/<a>/matrix.csv
   results/<b>/matrix.csv`. Flag any cell where the absolute change
   exceeds 10% AND the change exceeds 2σ of either run's intra-cell
   variance — that's a real, statistically significant difference.

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Quota exhaustion mid-run | Pre-flight quota check in `deploy-fleet.ps1`; fail fast |
| Public-Internet weather affects long-haul cells | Re-run flagged cells in a fresh time window; report median over re-runs |
| netem loss simulation diverges from real loss patterns | Note in report; the loss model is iid Bernoulli, not bursty/correlated |
| One region's underlying network is degraded | Canary cell at start + end of every region campaign; 10% delta = abort |
| Cost overrun | Hard cap: each spoke VM has an Azure budget alert at $5; auto-stop on hit |
| Time-of-day effects | Run start times logged; campaigns ≥ 24h smear effects |
| Cobalt 100 (arm64) availability in some regions | Pre-check size availability per region; downgrade to `D2ps_v5` (Ampere Altra) if v6 not available — note in cell `controls` |

## 14. Out-of-scope (deferred)

- IPv6 path testing.
- MTU sweep (1280, 1380, 1420, 1500). Possible follow-up.
- Multi-stream WireGuard (one peer, many flows). The current module is
  tested per-flow.
- Real-world loss patterns (bursty, correlated). netem `loss random` is
  iid Bernoulli; `loss gemodel` would be a follow-up.
- Encrypted-vs-cleartext baseline: we measure **WG vs WG** and **WG vs
  raw**, not "encryption overhead per se".
- Multi-region simultaneous client load (testing relay limits).
- Long-duration soak tests (> 1h continuous flow). Follow-up campaign.

## 15. Acceptance criteria for "campaign succeeded"

- ≥ 95% of the 768 planned cells produced a valid JSON output (the rest
  documented in `results/<ver>/failed-cells.txt` with reason).
- Both canary cells (start + end) within 10% of each other.
- One CSV at `results/<ver>/matrix.csv` with all expected rows.
- One markdown report at `results/<ver>/REPORT.md` with the
  H1-H5 hypothesis disposition + 4 headline charts.
- Provisioning/teardown is idempotent (re-running deploy on existing RG
  is a no-op; teardown leaves zero billable resources).
