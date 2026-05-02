#!/usr/bin/env python3
"""
drop-bad-cells.py — identify and delete cell.json files that contain no
useful measurement data, so a resume run can repopulate them.

Bad-cell heuristics (any one is enough):
  * cell.json size <= 50 bytes
  * metrics dict is missing all expected workload keys
  * for iperf3 workloads: throughput_mbps absent or == 0
  * for h2load (web-mix): h2load_done == 0  (no responses received at all)
  * for ping: rtt_mean_ms absent (run failed entirely)

Usage:
    drop-bad-cells.py <cells-root> [--dry-run]
"""
import argparse, json, sys
from pathlib import Path

EXPECT = {
    'long-transfer':  ('goodput_tcp_mbps', 'goodput_udp_mbps'),  # both keys; bad if both missing
    'short-transfer': ('req_per_sec',),
    'web-mix':        None,  # special: see logic below
    'ssh-interactive': None,  # special: 100% loss is a legitimate measurement
}

def is_bad(cell_path):
    try:
        if cell_path.stat().st_size <= 50:
            return ('tiny', cell_path.stat().st_size)
        with cell_path.open() as f:
            doc = json.load(f)
    except Exception as e:
        return ('parse-error', str(e))
    metrics = doc.get('metrics') or {}
    workload = (doc.get('axes') or {}).get('workload')
    if workload == 'web-mix':
        if metrics.get('h2load_done', 0) == 0:
            return ('h2load_done=0', None)
        return None
    if workload == 'ssh-interactive':
        # observed_loss_pct = 100.0 is a legitimate measurement (TCP-WG hides
        # loss; ping never returns) so we keep those.  Only flag bad if even
        # the loss summary is missing — meaning ping never ran at all.
        if 'observed_loss_pct' not in metrics:
            return ('observed_loss_pct missing', None)
        return None
    keys = EXPECT.get(workload)
    if not keys:
        return None
    vals = [metrics.get(k) for k in keys]
    if all(v is None or v == 0 for v in vals):
        return (f'all-missing:{keys}', None)
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cells_root')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
    root = Path(args.cells_root)
    bad = []
    total = 0
    for cj in root.glob('*/*/cell.json'):
        total += 1
        why = is_bad(cj)
        if why:
            bad.append((cj, why))
    print(f'scanned {total} cells, {len(bad)} bad')
    by_pair = {}
    by_workload = {}
    for cj, (why, _extra) in bad:
        pair = cj.parent.parent.name
        by_pair[pair] = by_pair.get(pair, 0) + 1
        cell_dir = cj.parent.name
        wl = cell_dir.split('_')[1] if '_' in cell_dir else cell_dir
        by_workload[wl] = by_workload.get(wl, 0) + 1
    print('  by pair    :', dict(sorted(by_pair.items())))
    print('  by workload:', dict(sorted(by_workload.items())))
    if args.dry_run:
        print('DRY-RUN - no deletions')
        return
    for cj, _ in bad:
        cj.unlink()
    print(f'deleted {len(bad)} cell.json files (cells will be re-run on resume)')

if __name__ == '__main__':
    main()
