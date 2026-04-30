# Performance Report — WireguardTCP-FAST v<VERSION>

> Template. Fill in for each version. Commit the completed report under
> `perf-test/results/v<VERSION>/REPORT.md`.

**Version under test**: `<VERSION>`
**Image source**: `wireguardtcp-ubuntu24-tls/<VERSION>` (x64),
                 `wireguardtcp-ubuntu24-arm64-tls/<VERSION>` (arm64)
**Kernel**: `<uname -r>`
**Module signing-cert fingerprint (SHA256)**: `<...>`
**Campaign date**: `<YYYY-MM-DD .. YYYY-MM-DD>`
**Total cells executed**: `<N>` of `<planned>` (`<%>`)
**Canary delta (start vs end)**: `<X>%`

---

## 1. Headline numbers

| Region pair | Workload | Stock UDP (Mbps) | TCP-FAST (Mbps) | Delta | Loss tolerance crossover |
|---|---|---|---|---|---|
| LAN | long-transfer | | | | |
| MED | long-transfer | | | | |
| HIGH | long-transfer | | | | |
| MAX | long-transfer | | | | |

> "Loss tolerance crossover" = lowest loss% at which TCP-FAST goodput
> exceeds UDP goodput by more than the noise floor.

## 2. Hypothesis disposition

(See TESTPLAN.md §2 for hypothesis statements.)

| H | Statement (short) | Outcome | Evidence |
|---|---|---|---|
| H1 | Short distance, clean: parity | confirm/refute | cite cells |
| H2 | Long distance, clean: parity | confirm/refute | cite cells |
| H3 | ≥1% loss: TCP-FAST wins | confirm/refute | cite cells |
| H4 | ≥10% loss: UDP collapses, TCP graceful | confirm/refute | cite cells |
| H5 | ARM64 ≥ 80% throughput at <80% CPU | confirm/refute | cite cells |

## 3. Charts

(Embed PNGs / mermaid diagrams generated from `matrix.csv`.)

- Goodput vs loss%, by region, both tunnels (one chart per workload).
- p99 RTT vs loss%, by region.
- CPU per Mbps vs loss%, by arch.
- Recovery time vs loss%, only for tunnel cells.

## 4. Notable anomalies

| Cell | Anomaly | Disposition |
|---|---|---|
| | | |

## 5. Comparison with previous version (if any)

| Metric | v<prev> | v<this> | Δ | Significance |
|---|---|---|---|---|
| LAN long-transfer goodput (TCP-FAST) | | | | |
| HIGH long-transfer goodput at 5% loss | | | | |
| ARM64 web-mix req/s | | | | |

## 6. Failed cells

```
<paste contents of failed-cells.txt>
```

## 7. Recommendations / follow-ups

- ...
