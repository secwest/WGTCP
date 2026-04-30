#!/usr/bin/env python3
"""TCP-base vs UDP-tunnel scenario summary.

Each long-transfer cell carries iperf3 TCP + UDP probes through whichever
tunnel was selected. So the proper transport comparison for the same
inner-traffic class is:

  inner-TCP traffic: tcp_tunnel.goodput_tcp_mbps  vs  udp_tunnel.goodput_tcp_mbps
  inner-UDP traffic: tcp_tunnel.goodput_udp_mbps  vs  udp_tunnel.goodput_udp_mbps

CPU and RTT are tunnel-level metrics (not iperf-protocol-specific).

Renames tunnel label wireguard-tcp-fast -> wireguard-tcp-base on output.
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

def mean(vals):
    vals = [v for v in vals if v is not None]
    return statistics.fmean(vals) if vals else None

data = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
for (pair, tun, wl, loss), runs in groups.items():
    if not runs: continue
    agg = {}
    for k in ('cpu_pct_mean', 'goodput_tcp_mbps', 'goodput_udp_mbps',
              'rtt_mean_ms', 'rtt_max_ms', 'observed_loss_pct',
              'req_per_sec', 'ttfb_p50_ms', 'ttfb_p95_ms', 'retrans_count'):
        agg[k] = mean([r.get(k) for r in runs])
    agg['n'] = len(runs)
    data[pair][wl][loss][tun] = agg

PAIR_ORDER = ['LAN-x64','LAN-arm','MED-x64','MED-arm','HIGH-x64','HIGH-arm','MAX-x64','MAX-arm']

def pct(a, b):
    if a is None or b is None or b == 0: return ''
    return f"{(a-b)/b*100:+.1f}%"

def fmt(v, nd=1):
    if v is None: return '—'
    return f"{v:.{nd}f}" if isinstance(v, float) else str(v)

L = []
L.append("# Baseline 1.0.0 — TCP-base tunnel vs UDP tunnel scenario summary")
L.append("")
L.append("- **Image**: `wireguardtcp-ubuntu24-tls/1.0.0` (x64) and `wireguardtcp-ubuntu24-arm64-tls/1.0.0` (arm64)")
L.append("- **Topology**: point-to-point, 8 isolated 2-VM pairs, one /24 each, ports 51820/UDP + 51821/TCP")
L.append("- **Tunnel labels** (in matrix.csv): `wireguard-tcp-base` = baseline-image TCP transport (`Transport=tcp`); `wireguard-udp` = stock UDP control")
L.append("- **Each long-transfer cell** runs `iperf3 -t 60 -P 4` then `iperf3 -u -b 1G -l 1200 -t 60` over the **same** selected tunnel, so both inner-TCP and inner-UDP throughput are recorded for each tunnel choice")
L.append("- **CPU**: `100 - mpstat %idle`, mean over the cell. Tunnel-level (not protocol-specific).")
L.append("- **Δ%** is `(tcp_tunnel - udp_tunnel) / udp_tunnel × 100` for the SAME inner-traffic class.")
L.append("- VM size: x64 = D2s_v5 (2 vCPU), arm = D2ps_v6 (2 vCPU)")
L.append("")
L.append("---")
L.append("")

# Headline at loss=0
L.append("## Headline — long-transfer at loss=0%")
L.append("")
L.append("Inner-TCP throughput (TCP-fairness goodput) per tunnel:")
L.append("")
L.append("| pair | TCP-tun TCP Mbps | UDP-tun TCP Mbps | Δ% | TCP-tun CPU% | UDP-tun CPU% | Δ% |")
L.append("|------|-----------------:|-----------------:|---:|-------------:|-------------:|---:|")
for pair in PAIR_ORDER:
    cell = data.get(pair,{}).get('long-transfer',{}).get(0.0,{})
    t = cell.get('wireguard-tcp-base',{}); u = cell.get('wireguard-udp',{})
    L.append(f"| {pair} | {fmt(t.get('goodput_tcp_mbps'))} | {fmt(u.get('goodput_tcp_mbps'))} | {pct(t.get('goodput_tcp_mbps'),u.get('goodput_tcp_mbps'))} | "
             f"{fmt(t.get('cpu_pct_mean'))} | {fmt(u.get('cpu_pct_mean'))} | {pct(t.get('cpu_pct_mean'),u.get('cpu_pct_mean'))} |")
L.append("")
L.append("Inner-UDP throughput (saturation goodput) per tunnel:")
L.append("")
L.append("| pair | TCP-tun UDP Mbps | UDP-tun UDP Mbps | Δ% |")
L.append("|------|-----------------:|-----------------:|---:|")
for pair in PAIR_ORDER:
    cell = data.get(pair,{}).get('long-transfer',{}).get(0.0,{})
    t = cell.get('wireguard-tcp-base',{}); u = cell.get('wireguard-udp',{})
    L.append(f"| {pair} | {fmt(t.get('goodput_udp_mbps'))} | {fmt(u.get('goodput_udp_mbps'))} | {pct(t.get('goodput_udp_mbps'),u.get('goodput_udp_mbps'))} |")
L.append("")

# Loss sweep per pair
L.append("---")
L.append("")
L.append("## Loss sweep — long-transfer (per pair)")
L.append("")
L.append("Rows = loss%. Two metrics per row: inner-TCP (top) and inner-UDP (bottom) iperf throughput. CPU is tunnel-level.")
L.append("")
for pair in PAIR_ORDER:
    if pair not in data or 'long-transfer' not in data[pair]: continue
    losses = sorted(data[pair]['long-transfer'].keys(), key=lambda x: float(x) if x != '?' else -1)
    if not losses: continue
    L.append(f"### {pair}")
    L.append("")
    L.append("| loss% | inner | TCP-tun Mbps | UDP-tun Mbps | Δ% | TCP-tun CPU% | UDP-tun CPU% | Δ% |")
    L.append("|------:|:-----:|-------------:|-------------:|---:|-------------:|-------------:|---:|")
    for loss in losses:
        cell = data[pair]['long-transfer'][loss]
        t = cell.get('wireguard-tcp-base',{}); u = cell.get('wireguard-udp',{})
        # inner-TCP row
        L.append(f"| {loss} | TCP | {fmt(t.get('goodput_tcp_mbps'))} | {fmt(u.get('goodput_tcp_mbps'))} | "
                 f"{pct(t.get('goodput_tcp_mbps'),u.get('goodput_tcp_mbps'))} | "
                 f"{fmt(t.get('cpu_pct_mean'))} | {fmt(u.get('cpu_pct_mean'))} | "
                 f"{pct(t.get('cpu_pct_mean'),u.get('cpu_pct_mean'))} |")
        # inner-UDP row
        L.append(f"|       | UDP | {fmt(t.get('goodput_udp_mbps'))} | {fmt(u.get('goodput_udp_mbps'))} | "
                 f"{pct(t.get('goodput_udp_mbps'),u.get('goodput_udp_mbps'))} | "
                 f"·          | ·          |    |")
    L.append("")

# Short-transfer (TTFB / req-rate) — these capture RTT
L.append("---")
L.append("")
L.append("## Short-transfer — TTFB p50, request rate, RTT (loss=0%)")
L.append("")
L.append("Short-transfer cells run 200 sequential HTTPS requests; ping runs in parallel for RTT.")
L.append("")
L.append("| pair | TCP-tun TTFB ms | UDP-tun TTFB ms | Δ% | TCP-tun req/s | UDP-tun req/s | Δ% | TCP-tun rtt ms | UDP-tun rtt ms | Δ% | TCP-tun CPU% | UDP-tun CPU% |")
L.append("|------|----------------:|----------------:|---:|--------------:|--------------:|---:|---------------:|---------------:|---:|-------------:|-------------:|")
for pair in PAIR_ORDER:
    cell = data.get(pair,{}).get('short-transfer',{}).get(0.0,{})
    t = cell.get('wireguard-tcp-base',{}); u = cell.get('wireguard-udp',{})
    L.append(f"| {pair} | {fmt(t.get('ttfb_p50_ms'))} | {fmt(u.get('ttfb_p50_ms'))} | {pct(t.get('ttfb_p50_ms'),u.get('ttfb_p50_ms'))} | "
             f"{fmt(t.get('req_per_sec'),2)} | {fmt(u.get('req_per_sec'),2)} | {pct(t.get('req_per_sec'),u.get('req_per_sec'))} | "
             f"{fmt(t.get('rtt_mean_ms'))} | {fmt(u.get('rtt_mean_ms'))} | {pct(t.get('rtt_mean_ms'),u.get('rtt_mean_ms'))} | "
             f"{fmt(t.get('cpu_pct_mean'))} | {fmt(u.get('cpu_pct_mean'))} |")
L.append("")

# Coverage
L.append("---")
L.append("")
L.append("## Coverage")
L.append("")
L.append("Total cells gathered per pair (full matrix per pair = 2 tunnels × 4 workloads × 8 losses × 3 runs = 192).")
L.append("")
L.append("| pair | cells captured |")
L.append("|------|---------------:|")
totals = defaultdict(int)
for (pair, tun, wl, loss), runs in groups.items():
    totals[pair] += len(runs)
for pair in PAIR_ORDER:
    L.append(f"| {pair} | {totals[pair]} / 192 |")
L.append("")
L.append("---")
L.append("")
L.append("Source data: `results/baseline-1.0.0-p2p/cells/<pair>/<tunnel>_<workload>_loss<L>_run<N>/cell.json`. Aggregated by `summary-report.py`.")

OUT_MD.write_text('\n'.join(L), encoding='utf-8')
print(f"wrote {OUT_MD} ({len(L)} lines, {sum(len(g) for g in groups.values())} cells, {sum(totals.values())} aggregated)")
