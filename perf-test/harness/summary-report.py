#!/usr/bin/env python3
"""TCP-base vs UDP-tunnel scenario summary, per workload × per tier.

Per-workload metrics available (from current harness):
  long-transfer  : goodput_tcp_mbps, goodput_udp_mbps, retrans_count, cpu_pct_mean
                   (no RTT; iperf3 doesn't ping during transfer)
  ssh-interactive: rtt_{min,mean,max,mdev}_ms, observed_loss_pct, cpu_pct_mean
  short-transfer : ttfb_p50/p95/p99_ms, req_per_sec, cpu_pct_mean
  web-mix        : req_per_sec  (h2load summary; CPU/latency not parsed yet)

Comparison is TCP-tunnel vs UDP-tunnel for the same inner-traffic class.
"""
import json, sys, statistics
from pathlib import Path
from collections import defaultdict

ROOT = Path(sys.argv[1])
OUT_MD = Path(sys.argv[2])

cells_dir = ROOT / 'cells'
groups = defaultdict(list)
for cj in cells_dir.rglob('cell.json'):
    pair = cj.relative_to(cells_dir).parts[0]
    try: doc = json.loads(cj.read_text())
    except Exception: continue
    ax = doc.get('axes', {})
    tun = ax.get('tunnel','?').replace('wireguard-tcp-fast','wireguard-tcp-base')
    key = (pair, tun, ax.get('workload','?'), ax.get('loss_pct','?'))
    groups[key].append(doc.get('metrics', {}))

def m(vals):
    vals = [v for v in vals if v is not None]
    return statistics.fmean(vals) if vals else None

data = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
for (pair, tun, wl, loss), runs in groups.items():
    if not runs: continue
    agg = {}
    for k in ('cpu_pct_mean','goodput_tcp_mbps','goodput_udp_mbps',
              'rtt_mean_ms','rtt_max_ms','rtt_mdev_ms','observed_loss_pct',
              'req_per_sec','ttfb_p50_ms','ttfb_p95_ms','retrans_count'):
        agg[k] = m([r.get(k) for r in runs])
    agg['n'] = len(runs)
    data[pair][wl][loss][tun] = agg

TIERS  = ['LAN','MED','HIGH','MAX']
ARCHES = ['x64','arm']

def pct(a, b):
    if a is None or b is None or b == 0: return ''
    return f"{(a-b)/b*100:+.1f}%"

def fmt(v, nd=1):
    if v is None: return '—'
    return f"{v:.{nd}f}" if isinstance(v, float) else str(v)

def loss_sort(x):
    try: return float(x)
    except: return -1

L = []
L.append("# Baseline 1.0.0 — TCP-base tunnel vs UDP tunnel, per workload × tier")
L.append("")
L.append("Image: `wireguardtcp-ubuntu24-tls/1.0.0` (x64) · `wireguardtcp-ubuntu24-arm64-tls/1.0.0` (arm64). Topology: p2p, 8 isolated pairs, ports 51820/UDP + 51821/TCP. VM sizes: D2s_v5 (x64) / D2ps_v6 (arm).")
L.append("")
L.append("Tunnel labels: `wireguard-tcp-base` = baseline TCP transport; `wireguard-udp` = UDP control. Δ% is `(tcp_tun - udp_tun) / udp_tun × 100`.")
L.append("")
L.append("Tiers: **LAN** = same-region (canadacentral ↔ canadacentral, ~0.4 ms RTT). **MED** = cross-continent (canadacentral ↔ westus2, ~56 ms RTT). **HIGH** = trans-Atlantic (canadacentral ↔ westeurope, ~195 ms RTT). **MAX** = trans-Pacific via SE Asia (canadacentral ↔ southeastasia, ~227 ms RTT).")
L.append("")
L.append("Loss values 0/0.5/1/2/3/5/10/20% are injected on the carrier link with `tc netem`. Each cell = mean over 3 runs.")
L.append("")
L.append("### Reading the long-transfer columns")
L.append("")
L.append("Each long-transfer cell runs **two iperf3 probes back-to-back** through the chosen tunnel:")
L.append("")
L.append("1. `iperf3 -c PEER -t 60 -P 4`        → records `goodput_tcp_mbps` (a TCP application probe)")
L.append("2. `iperf3 -c PEER -u -b 1G -l 1200`  → records `goodput_udp_mbps` (a UDP application probe, rate-capped at 1 Gbps)")
L.append("")
L.append("So every cell carries **both** numbers. The four throughput columns in § 1 are not duplicates — they are 2 inner protocols × 2 tunnel choices:")
L.append("")
L.append("| column | inner traffic | tunnel | answers |")
L.append("|---|---|---|---|")
L.append("| `inner-TCP TCP-tun Mbps` | TCP app | WG-over-TCP   | TCP application throughput when carrier is TCP |")
L.append("| `inner-TCP UDP-tun Mbps` | TCP app | WG-over-UDP   | TCP application throughput when carrier is UDP |")
L.append("| `inner-UDP TCP-tun Mbps` | UDP app | WG-over-TCP   | UDP application throughput when carrier is TCP |")
L.append("| `inner-UDP UDP-tun Mbps` | UDP app | WG-over-UDP   | UDP application throughput when carrier is UDP |")
L.append("")
L.append("**Why TCP and UDP probe numbers differ inside the same cell:** TCP self-throttles via congestion control and tries to saturate the link fairly (so on LAN it reaches ~2.7 Gbps). UDP is rate-capped at `-b 1G`, so it tops out at ~1 Gbps regardless of headroom. They're two different probes, not one probe reported twice.")
L.append("")
L.append("**ΔTCP%** asks: *does inner TCP traffic care which tunnel carries it?* On LAN at 0% loss, no (≤10% diff). At 10% loss, **yes, dramatically** (+9000% on x64) — TCP-meltdown on the UDP carrier vs steady on the TCP carrier.")
L.append("")
L.append("**ΔUDP%** asks: *does inner UDP traffic care which tunnel carries it?* Less so — UDP has no ACK-collapse mode, just raw packet loss. At 20% loss UDP-tunnel drops to ~780 Mbps inner-UDP while TCP-tunnel holds ~954 Mbps (carrier-level retransmits).")
L.append("")

# ============================================================
# 1. LONG-TRANSFER
# ============================================================
L.append("---")
L.append("")
L.append("## 1. long-transfer  (60 s iperf3 TCP -P 4, then 60 s iperf3 UDP -b 1G)")
L.append("")
L.append("Throughput goodput in Mbps; CPU = `100 - mpstat %idle`. **RTT not captured** for long-transfer (iperf3 runs back-to-back without ping; see ssh-interactive § 3 for RTT-vs-loss).")
L.append("")
for tier in TIERS:
    L.append(f"### 1.{TIERS.index(tier)+1} {tier}")
    L.append("")
    L.append("| arch | loss% | inner-TCP TCP-tun Mbps | inner-TCP UDP-tun Mbps | ΔTCP% | inner-UDP TCP-tun Mbps | inner-UDP UDP-tun Mbps | ΔUDP% | TCP-tun CPU% | UDP-tun CPU% | ΔCPU% |")
    L.append("|:----:|------:|-----------------------:|-----------------------:|------:|-----------------------:|-----------------------:|------:|-------------:|-------------:|------:|")
    for arch in ARCHES:
        pair = f"{tier}-{arch}"
        wl_data = data.get(pair,{}).get('long-transfer',{})
        if not wl_data: continue
        for loss in sorted(wl_data.keys(), key=loss_sort):
            t = wl_data[loss].get('wireguard-tcp-base',{})
            u = wl_data[loss].get('wireguard-udp',{})
            L.append(f"| {arch} | {loss} | "
                     f"{fmt(t.get('goodput_tcp_mbps'))} | {fmt(u.get('goodput_tcp_mbps'))} | {pct(t.get('goodput_tcp_mbps'),u.get('goodput_tcp_mbps'))} | "
                     f"{fmt(t.get('goodput_udp_mbps'))} | {fmt(u.get('goodput_udp_mbps'))} | {pct(t.get('goodput_udp_mbps'),u.get('goodput_udp_mbps'))} | "
                     f"{fmt(t.get('cpu_pct_mean'))} | {fmt(u.get('cpu_pct_mean'))} | {pct(t.get('cpu_pct_mean'),u.get('cpu_pct_mean'))} |")
    L.append("")

# ============================================================
# 2. SHORT-TRANSFER
# ============================================================
L.append("---")
L.append("")
L.append("## 2. short-transfer  (200 sequential HTTPS requests, fresh TLS each)")
L.append("")
L.append("Application latency = TTFB (time-to-first-byte). Throughput = req/s sustained.")
L.append("")
for tier in TIERS:
    L.append(f"### 2.{TIERS.index(tier)+1} {tier}")
    L.append("")
    L.append("| arch | loss% | TCP-tun TTFB ms | UDP-tun TTFB ms | ΔTTFB% | TCP-tun req/s | UDP-tun req/s | Δreq% | TCP-tun CPU% | UDP-tun CPU% | ΔCPU% |")
    L.append("|:----:|------:|----------------:|----------------:|-------:|--------------:|--------------:|------:|-------------:|-------------:|------:|")
    for arch in ARCHES:
        pair = f"{tier}-{arch}"
        wl_data = data.get(pair,{}).get('short-transfer',{})
        if not wl_data: continue
        for loss in sorted(wl_data.keys(), key=loss_sort):
            t = wl_data[loss].get('wireguard-tcp-base',{})
            u = wl_data[loss].get('wireguard-udp',{})
            L.append(f"| {arch} | {loss} | "
                     f"{fmt(t.get('ttfb_p50_ms'))} | {fmt(u.get('ttfb_p50_ms'))} | {pct(t.get('ttfb_p50_ms'),u.get('ttfb_p50_ms'))} | "
                     f"{fmt(t.get('req_per_sec'),2)} | {fmt(u.get('req_per_sec'),2)} | {pct(t.get('req_per_sec'),u.get('req_per_sec'))} | "
                     f"{fmt(t.get('cpu_pct_mean'))} | {fmt(u.get('cpu_pct_mean'))} | {pct(t.get('cpu_pct_mean'),u.get('cpu_pct_mean'))} |")
    L.append("")

# ============================================================
# 3. SSH-INTERACTIVE
# ============================================================
L.append("---")
L.append("")
L.append("## 3. ssh-interactive  (1000 × 50 ms ICMP ping; ssh keystroke-echo via ControlMaster)")
L.append("")
L.append("Latency = `rtt_mean_ms` (ICMP). Loss = `observed_loss_pct` (ping summary, post-`tc netem`).")
L.append("")
for tier in TIERS:
    L.append(f"### 3.{TIERS.index(tier)+1} {tier}")
    L.append("")
    L.append("| arch | loss% | TCP-tun rtt ms | UDP-tun rtt ms | Δrtt% | TCP-tun rtt max ms | UDP-tun rtt max ms | TCP-tun loss% | UDP-tun loss% | TCP-tun CPU% | UDP-tun CPU% | ΔCPU% |")
    L.append("|:----:|------:|---------------:|---------------:|------:|-------------------:|-------------------:|--------------:|--------------:|-------------:|-------------:|------:|")
    for arch in ARCHES:
        pair = f"{tier}-{arch}"
        wl_data = data.get(pair,{}).get('ssh-interactive',{})
        if not wl_data: continue
        for loss in sorted(wl_data.keys(), key=loss_sort):
            t = wl_data[loss].get('wireguard-tcp-base',{})
            u = wl_data[loss].get('wireguard-udp',{})
            L.append(f"| {arch} | {loss} | "
                     f"{fmt(t.get('rtt_mean_ms'),2)} | {fmt(u.get('rtt_mean_ms'),2)} | {pct(t.get('rtt_mean_ms'),u.get('rtt_mean_ms'))} | "
                     f"{fmt(t.get('rtt_max_ms'),1)} | {fmt(u.get('rtt_max_ms'),1)} | "
                     f"{fmt(t.get('observed_loss_pct'),2)} | {fmt(u.get('observed_loss_pct'),2)} | "
                     f"{fmt(t.get('cpu_pct_mean'))} | {fmt(u.get('cpu_pct_mean'))} | {pct(t.get('cpu_pct_mean'),u.get('cpu_pct_mean'))} |")
    L.append("")

# ============================================================
# 4. WEB-MIX
# ============================================================
L.append("---")
L.append("")
L.append("## 4. web-mix  (h2load: 5000 requests, 50 conn × 10 streams, HTTP/2 over TLS)")
L.append("")
L.append("Throughput = aggregate req/s. *(CPU and latency parsing for h2load not yet wired into parse-cell.py; columns omitted.)*")
L.append("")
for tier in TIERS:
    L.append(f"### 4.{TIERS.index(tier)+1} {tier}")
    L.append("")
    L.append("| arch | loss% | TCP-tun req/s | UDP-tun req/s | Δreq% |")
    L.append("|:----:|------:|--------------:|--------------:|------:|")
    for arch in ARCHES:
        pair = f"{tier}-{arch}"
        wl_data = data.get(pair,{}).get('web-mix',{})
        if not wl_data: continue
        for loss in sorted(wl_data.keys(), key=loss_sort):
            t = wl_data[loss].get('wireguard-tcp-base',{})
            u = wl_data[loss].get('wireguard-udp',{})
            L.append(f"| {arch} | {loss} | "
                     f"{fmt(t.get('req_per_sec'),2)} | {fmt(u.get('req_per_sec'),2)} | {pct(t.get('req_per_sec'),u.get('req_per_sec'))} |")
    L.append("")

# Coverage
L.append("---")
L.append("")
L.append("## Coverage")
L.append("")
totals = defaultdict(int)
for (pair, _, _, _), runs in groups.items():
    totals[pair] += len(runs)
L.append("| pair | cells / 192 |")
L.append("|------|-------:|")
for tier in TIERS:
    for arch in ARCHES:
        p = f"{tier}-{arch}"
        L.append(f"| {p} | {totals.get(p,0)} |")
L.append("")
L.append(f"Total cells: {sum(totals.values())} / 1536 ({sum(totals.values())*100//1536}%).")
L.append("")
L.append("Source: `results/baseline-1.0.0-p2p/cells/<pair>/<tunnel>_<workload>_loss<L>_run<N>/cell.json` · generator: `harness/summary-report.py`.")

OUT_MD.write_text('\n'.join(L), encoding='utf-8')
print(f"wrote {OUT_MD} ({len(L)} lines)")
