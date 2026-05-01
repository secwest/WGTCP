#!/usr/bin/env python3
"""aggregate.py — flatten per-cell JSONs into a single CSV matrix.

Usage:
    aggregate.py <results-dir> -o matrix.csv

Reads every cells/**/cell.json under <results-dir>, averages the 3 runs
per (axes-without-run-index) cell, and writes a CSV with one row per
unique cell."""

import argparse, csv, json, statistics, sys
from collections import defaultdict
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('results_dir')
p.add_argument('-o', '--output', default='matrix.csv')
args = p.parse_args()

cells = list(Path(args.results_dir).rglob('cell.json'))
if not cells:
    sys.exit("no cell.json found under " + args.results_dir)

cells_root = Path(args.results_dir) / 'cells'

# Group runs by (axes minus run_index)
groups = defaultdict(list)
for c in cells:
    try: doc = json.loads(c.read_text())
    except Exception as e:
        print(f"skipping {c}: {e}", file=sys.stderr); continue
    ax = doc.get('axes', {})
    # region_pair (e.g. 'LAN-x64', 'HIGH-arm') is not in axes; recover it
    # from the cells/<pair>/... path component.
    pair = ax.get('region_pair')
    if not pair:
        try: pair = c.relative_to(cells_root).parts[0]
        except Exception: pair = '?'
    key = (pair,
           ax.get('arch', '?'),
           ax.get('tunnel', '?'),
           ax.get('workload', '?'),
           ax.get('loss_pct', '?'))
    groups[key].append(doc)

# Discover all metric keys
all_metric_keys = set()
for runs in groups.values():
    for r in runs:
        all_metric_keys.update(r.get('metrics', {}).keys())

metric_keys = sorted(all_metric_keys)
header = ['region_pair','arch','tunnel','workload','loss_pct','n_runs']
for k in metric_keys:
    header += [f'{k}_mean', f'{k}_stdev']
header += ['anomaly_count']

with open(args.output, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(header)
    for key, runs in sorted(groups.items()):
        row = list(key) + [len(runs)]
        for k in metric_keys:
            vals = [r.get('metrics', {}).get(k) for r in runs]
            vals = [v for v in vals if isinstance(v, (int, float))]
            if vals:
                row += [round(statistics.mean(vals), 3),
                        round(statistics.stdev(vals), 3) if len(vals) > 1 else 0]
            else:
                row += ['', '']
        anom = sum(len(r.get('anomalies', [])) for r in runs)
        row.append(anom)
        w.writerow(row)

print(f"wrote {args.output} ({len(groups)} cells, {len(metric_keys)} metrics)")
