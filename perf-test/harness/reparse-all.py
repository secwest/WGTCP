#!/usr/bin/env python3
"""Re-parse every existing cell.json from its raw/ directory using the
current parse-cell.py logic. Used after fixing the parser to backfill
missing metrics across the whole campaign."""

import json, subprocess, sys
from pathlib import Path

if len(sys.argv) < 3:
    print("usage: reparse-all.py <cells_root> <parse-cell.py>", file=sys.stderr)
    sys.exit(2)

cells_root = Path(sys.argv[1])
parser     = Path(sys.argv[2])
n = ok = fail = 0
for cj_path in cells_root.rglob("cell.json"):
    n += 1
    raw = cj_path.parent / "raw"
    if not raw.is_dir():
        fail += 1
        continue
    try:
        old = json.loads(cj_path.read_text())
    except Exception as e:
        fail += 1
        print(f"  bad json: {cj_path}: {e}", file=sys.stderr)
        continue
    ax = old.get("axes", {})
    ctrl = old.get("controls", {})
    cmd = [
        sys.executable, str(parser),
        "--cell-id",     old.get("cell_id", cj_path.parent.name),
        "--workload",    str(ax.get("workload", "")),
        "--tunnel",      str(ax.get("tunnel", "")),
        "--loss-pct",    str(ax.get("loss_pct", 0)),
        "--run-index",   str(ax.get("run_index", 1)),
        "--arch",        str(ax.get("arch", "x86_64")),
        "--kernel",      str(ctrl.get("kernel", "unknown")),
        "--t0",          str(old.get("ran_at_start", "")),
        "--t1",          str(old.get("ran_at_end", "")),
        "--raw-dir",     str(raw),
        "--workload-rc", str(old.get("workload_rc", 0)),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        cj_path.write_text(proc.stdout)
        ok += 1
    except subprocess.CalledProcessError as e:
        fail += 1
        print(f"  parser failed for {cj_path.parent.name}: {e.stderr[:200]}", file=sys.stderr)

print(f"reparsed {ok}/{n} cells ({fail} failures)")
