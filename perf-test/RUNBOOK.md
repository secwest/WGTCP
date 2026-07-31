# Performance Campaign RUNBOOK

End-to-end recipe for an LLM agent (or human operator) to reproduce the
WireguardTCP performance test campaign from a clean Azure subscription.

The campaign measures four workloads (`short-transfer`, `long-transfer`,
`web-mix`, `ssh-interactive`) over two tunnel modes (stock UDP, TCP baseline),
across four latency tiers (LAN / MED / HIGH / MAX) and two CPU
architectures (x64, arm64), at eight packet-loss rates (0, 0.5, 1, 2, 3,
5, 10, 20%) with three runs per cell.

**Authoritative design** lives in [`TESTPLAN.md`](./TESTPLAN.md).
**Report skeleton** lives in [`REPORT-TEMPLATE.md`](./REPORT-TEMPLATE.md).

---

## 1. Prerequisites

### Tooling on the operator workstation

| Tool | Purpose | Version tested |
|---|---|---|
| Azure CLI (`az`) | All cloud control-plane | 2.60+ |
| OpenSSH (`ssh`, `scp`, `ssh-keygen`) | Provisioning / remote exec | bundled with Win10/11 |
| Python 3 | `aggregate.py` post-processing | 3.10+ |
| PowerShell 7 (`pwsh`) | Orchestrator scripts | 7.4+ |
| Git | Cloning / pushing the repo | 2.40+ |

The orchestrator (`smoke-test.ps1`, `run-full-campaign.ps1`) is written
in PowerShell and is regularly exercised on Windows; the harness scripts
themselves run on Linux.

### Azure subscription

- Owner or Contributor on at least one subscription.
- Region enrolment in `canadacentral`, `westus3`, `australiaeast`,
  `southafricanorth` (default for any commercial Azure tenant).
- Quotas — see Section 4. We file requests via REST below.

### Source artefacts

- `wireguardtcp_gallery` Shared Image Gallery in `RG-WIREGUARDTCP`
  containing image versions for both architectures, replicated to all
  four target regions:
  - `wireguardtcp-ubuntu24-tls` (x64) ≥ v1.0.2
  - `wireguardtcp-ubuntu24-arm64-tls` ≥ v1.0.0
- See [`azure-images/RUNBOOK.md`](../azure-images/RUNBOOK.md) for how to
  build these from scratch.

---

## 2. Network topology

```
                 +---------------- canadacentral ----------------+
                 |                                               |
                 |   cc-x64-A (hub)   <----- LAN ----->  cc-x64-B|
                 |   cc-arm-A (hub)   <----- LAN ----->  cc-arm-B|
                 |        ^   ^   ^                              |
                 +--------|---|---|------------------------------+
                          |   |   |
                   MED    |   |   | HIGH
              westus3-x64 |   |   | australiaeast-x64
              westus3-arm |   |   | australiaeast-arm
                          |   |   |
                          |   |   |
                              |
                              | MAX
                              | southafricanorth-x64
                              | southafricanorth-arm
```

- Two **hubs** in canadacentral (one x64, one arm64) each terminate one
  LAN peer and three cross-region peers concurrently.
- Each peer pair runs over a **distinct WireGuard /30** and **distinct
  UDP port pair** (`51820+2N` for stock UDP, `51821+2N` for TCP baseline,
  with `N = pair index`):

| Pair | Hub iface | Spoke | Hub /30 IP | Spoke /30 IP | UDP port | TCP port |
|---|---|---|---|---|---|---|
| LAN-x64    | wg-udp0/wg-tcp0 | cc-x64-B            | 10.99.0.1  | 10.99.0.2  | 51820 | 51821 |
| MED-x64    | wg-udp1/wg-tcp1 | westus3-x64         | 10.99.1.1  | 10.99.1.2  | 51822 | 51823 |
| HIGH-x64   | wg-udp2/wg-tcp2 | australiaeast-x64   | 10.99.2.1  | 10.99.2.2  | 51824 | 51825 |
| MAX-x64    | wg-udp3/wg-tcp3 | southafricanorth-x64| 10.99.3.1  | 10.99.3.2  | 51826 | 51827 |
| LAN-arm    | wg-udp0/wg-tcp0 | cc-arm-B            | 10.99.0.1  | 10.99.0.2  | 51820 | 51821 |
| MED-arm    | wg-udp1/wg-tcp1 | westus3-arm         | 10.99.1.1  | 10.99.1.2  | 51822 | 51823 |
| HIGH-arm   | wg-udp2/wg-tcp2 | australiaeast-arm   | 10.99.2.1  | 10.99.2.2  | 51824 | 51825 |
| MAX-arm    | wg-udp3/wg-tcp3 | southafricanorth-arm| 10.99.3.1  | 10.99.3.2  | 51826 | 51827 |

The arm and x64 hubs are independent (separate VMs) so port numbers
can repeat across them safely. **Total VMs: 10** (2 LAN-x64, 2
LAN-arm, 6 cross-region spokes).

NSGs allow:
- TCP/22 from operator IP (or 0.0.0.0/0 if pre-authenticated)
- UDP/51820–51827 from peer public IPs
- TCP/51820–51827 from peer public IPs (TCP baseline uses TCP for the
  outer transport)

---

## 3. VM sizes

| Arch | SKU | vCPU | RAM | NIC | Trusted Launch | Family quota |
|---|---|---|---|---|---|---|
| x64   | `Standard_D2s_v5`  | 2 | 8 GB  | AccelNet | yes | StandardDSv5Family |
| arm64 | `Standard_D2ps_v6` | 2 | 8 GB  | AccelNet | yes | StandardDpsv6Family |

Both SKUs support TrustedLaunch + SecureBoot + vTPM, which the gallery
images require. AccelNet keeps the host kernel from being the
bottleneck for line-rate runs.

---

## 4. Quota provisioning

Quota requirements for the full 10-VM fleet:

| Region | Family | Cores needed | Default | Action |
|---|---|---|---|---|
| canadacentral    | DSv5  | 4   | 288 | none |
| canadacentral    | Dpsv6 | 4   | 2   | request → 10 |
| westus3          | DSv5  | 2   | 100 | none |
| westus3          | Dpsv6 | 2   | 0   | request → 10 |
| australiaeast    | DSv5  | 2   | 100 | none |
| australiaeast    | Dpsv6 | 2   | 0   | request → 10 |
| southafricanorth | DSv5  | 2   | 100 | none |
| southafricanorth | Dpsv6 | 2   | 0   | request → 10 |

ARM (Dpsv6) quota is filed via Microsoft.Quota REST. Auto-approval is
fast (under a minute in our experience). Repeat per region:

```pwsh
$sub = "<your-sub-id>"
$body = '{\"properties\":{\"limit\":{\"value\":10,\"limitObjectType\":\"LimitValue\"},\"name\":{\"value\":\"StandardDpsv6Family\"},\"resourceType\":\"dedicated\"}}'
foreach ($loc in @("canadacentral","westus3","australiaeast","southafricanorth")) {
    az rest --method put --url "https://management.azure.com/subscriptions/$sub/providers/Microsoft.Compute/locations/$loc/providers/Microsoft.Quota/quotas/StandardDpsv6Family?api-version=2023-02-01" --body $body
}
```

Verify:

```pwsh
foreach ($loc in @("canadacentral","westus3","australiaeast","southafricanorth")) {
    az vm list-usage -l $loc --query "[?name.value=='StandardDpsv6Family'].[currentValue,limit]" -o tsv
}
```

If a region declines auto-approval, scope arm64 down to LAN-only and
file a support ticket; the campaign can run with arm64 LAN + x64 full
matrix.

---

## 5. Image replication

The gallery image versions must exist in every campaign region:

```pwsh
foreach ($img in @("wireguardtcp-ubuntu24-tls","wireguardtcp-ubuntu24-arm64-tls")) {
    $ver = if ($img -match "arm64") { "1.0.0" } else { "1.0.2" }
    az sig image-version update -r wireguardtcp_gallery -g RG-WIREGUARDTCP -i $img -e $ver `
        --target-regions "Canada Central" "West US 3" "Australia East" "South Africa North" `
        --no-wait
}
```

Replication is ~30–60 minutes per region per definition. Verify:

```pwsh
az sig image-version show -r wireguardtcp_gallery -g RG-WIREGUARDTCP `
    -i wireguardtcp-ubuntu24-tls -e 1.0.2 `
    --query "publishingProfile.targetRegions[].name" -o tsv
```

---

## 6. Run the campaign

```pwsh
git clone https://github.com/secwest/WireguardTCP.git
cd WireguardTCP
git checkout tcp

# Smoke test first (recommended; ~$0.50, ~30 min) — proves the harness is good.
./perf-test/smoke/smoke-test.ps1

# Full campaign (~10 VMs, ~$80–120, ~5 h wall-clock).
./perf-test/orchestrator/run-full-campaign.ps1 `
    -ResourceGroup rg-wgtcp-perf `
    -ImageVersionX64 1.0.2 `
    -ImageVersionArm 1.0.0 `
    -ResultsDir perf-test/results/v1.0.2

# Optional subsetting:
./perf-test/orchestrator/run-full-campaign.ps1 -Pairs LAN-x64,MED-x64
./perf-test/orchestrator/run-full-campaign.ps1 -LossPercents 0,5,20 -RunsPerCell 1
```

The orchestrator:
1. Provisions one resource-group and an NSG/VNet per region.
2. Deploys all VMs (`-no-wait`, then `az vm wait`).
3. Pushes the harness, runs `bootstrap-server.sh` on each hub and
   `bootstrap-client.sh` on each spoke.
4. Generates per-pair WireGuard keys and brings up each tunnel pair on
   distinct ifaces / ports.
5. Starts one PowerShell ThreadJob per spoke; each job iterates
   `workload × tunnel × loss × run` and ssh-execs `run-cell.sh`.
6. Pulls cell artefacts back via scp.
7. Runs `aggregate.py` to produce `matrix.csv`.
8. Optionally tears down (`-KeepResources` to keep the fleet for
   debugging).

Key outputs:

```
perf-test/results/v1.0.2/
├── inventory.json              # VM names, IPs, regions
├── cells/<pair>/<run-id>/      # raw iperf3 / curl / h2load / ping / mpstat / dmesg
├── matrix.csv                  # flattened per-cell summary
└── REPORT.md                   # to be hand-written from REPORT-TEMPLATE.md
```

---

## 7. Comparing two module versions

To regression-test a new TCP build:

1. Build a new gallery image-version (see `azure-images/RUNBOOK.md`).
2. Replicate to all four regions.
3. Run with `-ImageVersionX64 <new>` (and / or `-ImageVersionArm <new>`),
   pointed at a different `-ResultsDir` (e.g.
   `perf-test/results/v1.0.3`).
4. Diff `matrix.csv` between the two result directories. The TESTPLAN
   defines the metrics that matter for each workload; pay particular
   attention to:
   - `long-transfer.tcp_throughput_mbps` (loss=0–5%)
   - `short-transfer.ttfb_p99_ms`
   - `web-mix.req_per_sec` and `mean_ms`
   - `ssh-interactive.ping_max_ms` and `ssh_round_ms_p99`

---

## 8. Adding a new region pair

1. Confirm DSv5 / Dpsv6 quota in the new region (Section 4).
2. Replicate the gallery image-version into the region (Section 5).
3. Edit `run-full-campaign.ps1`'s `$pairTable` to add a new pair row
   with a unique `Index` (drives port and /30 allocation).
4. Re-run.

---

## 9. Troubleshooting cookbook

### A. SSH key passphrase trap on Windows

`ssh-keygen -N '""' -f path -q` from PowerShell creates a key with a
*literal* `""` passphrase, which then breaks every subsequent `ssh -i`.
Always use:

```pwsh
cmd /c "ssh-keygen -t ed25519 -N """" -f ""$keyPath"" -q"
```

Symptom: `Enter passphrase for key:` prompts during automation.

### B. Bash CRLF line endings

Files copied from Windows often arrive with CRLF; bash chokes on
`#!/bin/bash\r` with `bad interpreter`. Normalize before scp:

```pwsh
$c = [IO.File]::ReadAllText($f) -replace "`r`n","`n"
[IO.File]::WriteAllText($f, $c, [Text.UTF8Encoding]::new($false))
```

### C. apt-install nuking the SSH session

`needrestart` triggers a NIC service restart and disconnects the
session mid-install. Always wrap installs:

```bash
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -y install ...
```

If it does happen, `az vm restart -g <rg> -n <vm>` recovers; the
VM is otherwise fine.

### D. `wg-quick up` "RTNETLINK already exists"

A stale `ip link` object remains even after `wg-quick down` failed.
The harness already does this defensively; if you script it manually:

```bash
sudo wg-quick down wg-tcp0 2>/dev/null || true
sudo ip link delete wg-tcp0 2>/dev/null || true
sudo wg-quick up wg-tcp0
```

### E. `ip -s link` shows zero bytes for tcp-base

The TCP baseline module forwards via a different code path; `ip -s link`
under-reports. Use `wg show <iface> dump` for accurate counters.

### F. dmesg false-positive anomalies

The TCP baseline module emits informational `wireguard:` lines that look
scary but are normal handshake traces. `parse-cell.py` regex is tuned
to require `error|fail|drop|reject|timeout` to flag.

### G. Image not in target region

`Image '/subscriptions/.../images/...' was not found` — replication
hasn't completed. `az sig image-version show ... --query
publishingProfile.targetRegions[].name` to verify, then wait or
re-trigger.

### H. perfuser SSH key denied for ssh-interactive workload

`ssh-interactive.sh` uses `perfuser` over the tunnel.
`bootstrap-server.sh` creates the account but the public key has to be
injected by the orchestrator. Verify on the server:

```bash
sudo cat /home/perfuser/.ssh/authorized_keys
```

If empty: re-run the perfuser key-injection block in the orchestrator.

---

## 10. Teardown

```pwsh
az group delete -n rg-wgtcp-perf --yes --no-wait
```

The campaign image gallery (`RG-WIREGUARDTCP`) is *not* deleted —
it's the long-lived artefact. Only the per-campaign RG is recycled.
