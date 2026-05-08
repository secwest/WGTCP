#!/usr/bin/env python3
"""diag-blanks.py — for each report-table blank, show the underlying cells.

Usage: diag-blanks.py <results-root> [--workload long-transfer|short-transfer|web-mix|ssh-interactive] [--key goodput_tcp_mbps|...]
"""
import json, sys, argparse
from pathlib import Path
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument('root')
ap.add_argument('--workload', default=None)
ap.add_argument('--key', default=None, help='primary metric key')
ap.add_argument('--tunnel', default=None, help='filter to wireguard-tcp-base or wireguard-udp')
ap.add_argument('--show-all', action='store_true')
args = ap.parse_args()

cells_dir = Path(args.root) / 'cells'
groups = defaultdict(list)  # (pair, tun, wl, loss) -> list of (cell_name, metrics)
for cj in cells_dir.rglob('cell.json'):
    pair = cj.relative_to(cells_dir).parts[0]
    try: doc = json.loads(cj.read_text())
    except Exception: continue
    ax = doc.get('axes', {})
    tun = ax.get('tunnel','?').replace('wireguard-tcp-base','wireguard-tcp-base')
    wl = ax.get('workload','?')
    loss = ax.get('loss_pct','?')
    if args.workload and wl != args.workload: continue
    if args.tunnel and tun != args.tunnel: continue
    groups[(pair, tun, wl, str(loss))].append((cj.parent.name, doc.get('metrics', {})))

# Default keys per workload
DEFAULT_KEYS = {
    'long-transfer': ['goodput_tcp_mbps','goodput_udp_mbps','cpu_pct_mean'],
    'short-transfer': ['req_per_sec','ttfb_p50_ms','cpu_pct_mean'],
    'web-mix': ['req_per_sec','req_mean_ms','cpu_pct_mean'],
    'ssh-interactive': ['rtt_mean_ms','rtt_max_ms','observed_loss_pct'],
}

keys = [args.key] if args.key else None

print(f"key  | pair        | tunnel              | wl              | loss | n | values")
print(f"-----+-------------+---------------------+-----------------+------+---+----------------------")
for (pair, tun, wl, loss) in sorted(groups.keys()):
    runs = groups[(pair, tun, wl, loss)]
    use_keys = keys or DEFAULT_KEYS.get(wl, ['goodput_tcp_mbps'])
    for k in use_keys:
        vals = [m.get(k) for _, m in runs]
        none_cnt = sum(1 for v in vals if v is None)
        zero_cnt = sum(1 for v in vals if v == 0)
        good = sum(1 for v in vals if v is not None and v != 0)
        if args.show_all or none_cnt + zero_cnt > 0:
            print(f"{k[:4]} | {pair:11s} | {tun:19s} | {wl:15s} | {loss:>4s} | {len(runs)} | {vals}")
