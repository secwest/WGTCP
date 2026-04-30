# Cost Estimate — Performance Test Campaign

> Estimates use Azure pay-as-you-go retail pricing as observed for the
> `BareMetalFuzzer` subscription in 2026Q2. Actual costs vary with EA
> agreements, reservations, and region pricing changes — re-confirm
> against `az pricing` or the Pricing Calculator before committing.

---

## 1. Resources provisioned

| Component | Count | Notes |
|---|---|---|
| **Hub VMs** (canadacentral) | 2 (1× D2s_v5, 1× D2ps_v6) | Always-on during campaign |
| **Spoke VMs** | 6 (3 regions × 2 archs) | One pair per remote region: westus3, australiaeast, southafricanorth |
| **OS disks** | 8 × 30 GB Premium SSD | Default with `--security-type TrustedLaunch` |
| **Public IPs** | 8 × Standard | One per VM for orchestrator SSH only |
| **VNet peerings** | 3 hub-spoke peerings (bidirectional = 6 links) | Free to create; charged per GB transit |
| **NSGs** | 8 | Free |
| **Compute Gallery** | 1 (already exists) + 3 region replicas | Storage cost ~$0.05/GB/mo per region |

> Note: We **do not** use Azure VPN Gateway or ExpressRoute. Cross-region
> traffic rides VNet peering, which is charged at peering-egress rates
> (cheaper than public-Internet egress).

---

## 2. Compute cost

### Single campaign run (~30h budget end-to-end)

| Region | Size | $/hr (retail) | Hours | $ |
|---|---|---|---|---|
| canadacentral | D2s_v5 | $0.099 | 30 | $2.97 |
| canadacentral | D2ps_v6 | $0.0792 | 30 | $2.38 |
| westus3 | D2s_v5 | $0.096 | 30 | $2.88 |
| westus3 | D2ps_v6 | $0.0768 | 30 | $2.30 |
| australiaeast | D2s_v5 | $0.106 | 30 | $3.18 |
| australiaeast | D2ps_v6 | $0.0848 | 30 | $2.54 |
| southafricanorth | D2s_v5 | $0.105 | 30 | $3.15 |
| southafricanorth | D2ps_v6 | $0.0840 | 30 | $2.52 |
| **Subtotal** | | | | **$21.92** |

**30h budget rationale**: actual measurement is 5–8h (per `TESTPLAN.md`
§10), but we leave headroom for provisioning, debugging, and any
re-runs of flagged cells. If the campaign actually takes the planned 8h
runtime, compute drops to ~$6.

### Storage (OS disks)
- 30 GB Premium SSD ≈ $4.62/mo per disk → **$0.20 per disk for 30h**.
- 8 disks × $0.20 = **$1.60**.

### Public IPs
- Standard Static IP: $0.005/hr × 8 × 30h = **$1.20**.

---

## 3. Bandwidth cost (the large variable)

This is **the dominant cost** and depends entirely on how much data the
long-transfer workload pushes. Estimate breakdown:

### 3.1 Long-transfer (iperf3 60s, both TCP & UDP tunnels)

| Region pair | # cells | Avg goodput per cell | Data per cell | Total data |
|---|---|---|---|---|
| LAN (cc↔cc) | 96 | 5 Gbps | 37.5 GB | 3,600 GB |
| MED (cc↔westus3) | 96 | 1 Gbps | 7.5 GB | 720 GB |
| HIGH (cc↔aus) | 96 | 200 Mbps | 1.5 GB | 144 GB |
| MAX (cc↔saf) | 96 | 100 Mbps | 0.75 GB | 72 GB |

(Goodput estimates: clean-link rates get reduced by netem at higher loss
levels — many cells under 5–20% loss will move <100 MB.)

**Actual averaging**: Half the cells run at < 1% loss (full link rate);
the other half are progressively choked by 0.5–20% loss. Multiply by ~0.5
to get realistic data movement:

- LAN: 1,800 GB **(intra-region, peering free or very cheap — ~$0.01/GB)**
- MED: 360 GB cross-region North America peering: ~$0.02/GB
- HIGH: 72 GB cross-continent peering: ~$0.08/GB
- MAX: 36 GB intercontinental peering: ~$0.181/GB

| Pair | GB | $/GB | $ |
|---|---|---|---|
| LAN | 1,800 | $0.01 (intra-region peering) | $18.00 |
| MED (NA→NA) | 360 | $0.02 | $7.20 |
| HIGH (NA↔Oceania) | 72 | $0.08 | $5.76 |
| MAX (NA↔Africa) | 36 | $0.181 | $6.52 |
| **Subtotal long-transfer** | | | **$37.48** |

### 3.2 Other workloads
- short-transfer: ~200 MB/cell × 384 cross-region cells ≈ 75 GB.
  Distributed across the 3 cross-region pairs ≈ ~$3.
- web-mix: ~500 MB/cell × 384 = 192 GB across pairs ≈ ~$8.
- ssh-interactive: ~10 MB/cell. Negligible (<$0.50).

### 3.3 Baseline (no-tunnel) measurements
Runs the same workload set without tunnel — adds ~50% to total bytes
across the wire (because the long-transfer baseline reaches higher
goodput than the tunnel does).

**Bandwidth subtotal** (incl. baseline): **$37 + $11 + 50% = ~$72**.

---

## 4. Image gallery replication

Replicating a TrustedLaunchSupported image version to 3 extra regions:
- ~3 GB OS disk per region × 3 regions × $0.05/GB-month storage ≈ $0.50/mo.
- Replication transfer: 3 GB × 3 = 9 GB × $0.087/GB ≈ $0.78 (one-time).
- **Subtotal: ~$1.30 first month, $0.50/mo thereafter.**

---

## 5. Total per single campaign

| Bucket | Estimate |
|---|---|
| Compute (all VMs, 30h) | $22 |
| Storage (OS disks, 30h) | $2 |
| Public IPs (8 × 30h) | $1 |
| Bandwidth (cross-region) | $72 |
| Image replication (one-time) | $1 |
| **Total per campaign** | **≈ $98** |
| Conservative ceiling (incl. re-runs, slower-than-plan) | **$150** |
| Hard cap if everything goes wrong (long campaign, public-IP egress) | **$250** |

> Per-version comparisons: each subsequent campaign costs the same ~$98
> (image replication is one-time but disk storage between campaigns is
> negligible if VMs are torn down).

---

## 6. Cost-control levers (in order of effectiveness)

1. **Run measurement campaign in 8h block** — drops compute from $22 to $6.
2. **Skip MAX (cc↔saf) region** — drops bandwidth by ~$7, removes the
   most-expensive bytes. Loses the highest-RTT data point.
3. **Use D2ps_v5 in southafricanorth** instead of D2ps_v6 — D2ps_v6 may
   not be available in all regions yet. (Falls back to Standard
   security, but only matters for the smoke deploy, not the perf test.)
4. **Reduce long-transfer time from 60s → 30s** — halves bandwidth bill
   (drops to ~$36) at small statistical cost.
5. **Sample loss levels** (run 0%, 1%, 5%, 20% only) — drops to 50% of
   cells, halves bandwidth.
6. **Skip MAX region until results from other regions warrant it.**

---

## 7. Quota check (BareMetalFuzzer subscription, observed 2026-04-27)

| Region | DSv5 (cores) used/limit | DPSv5 (cores) used/limit | DPSv6 (cores) used/limit | OK? |
|---|---|---|---|---|
| canadacentral | 14/288 | 12/100 | 2/100 | ✅ |
| westus3 | 0/100 | 0/100 | 0/100 | ✅ |
| australiaeast | 0/100 | 0/100 | 0/100 | ✅ |
| southafricanorth | 0/100 | 0/100 | 0/100 | ✅ |

Each region needs 2 cores DSv5 + 2 cores DPSv6. All regions have ample
headroom.

> **Pre-flight requirement**: `deploy-fleet.ps1` should re-check quotas
> at execution time and abort with a clear message if any region is
> short. Don't mid-run a partial fleet.

---

## 8. Setting an Azure cost alert

Recommended for safety:

```bash
# At RG level, $200 monthly budget with email alert at 50%, 80%, 100%
az consumption budget create \
    --budget-name wgtcp-perf-budget \
    --resource-group rg-wgtcp-perf \
    --amount 200 --time-grain Monthly \
    --start-date $(date +%Y-%m-01) \
    --end-date $(date -d '+12 months' +%Y-%m-01) \
    --notification-key alert-50 \
        --threshold 50 --operator GreaterThan --contact-emails ops@example.com
```

(Repeat for 80% and 100% thresholds; the Azure Portal Cost Management UI
is faster for setting up multi-threshold alerts.)
