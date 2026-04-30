#!/usr/bin/env python3
"""Parse all raw outputs from a single matrix cell into one JSON document
that conforms to TESTPLAN.md §11.

Invoked by run-cell.sh after the workload completes."""

import argparse, json, os, re, statistics, sys
from pathlib import Path
from datetime import datetime

p = argparse.ArgumentParser()
p.add_argument('--cell-id',     required=True)
p.add_argument('--workload',    required=True)
p.add_argument('--tunnel',      required=True)
p.add_argument('--loss-pct',    type=float, required=True)
p.add_argument('--run-index',   type=int, required=True)
p.add_argument('--arch',        required=True)
p.add_argument('--kernel',      required=True)
p.add_argument('--t0',          required=True)
p.add_argument('--t1',          required=True)
p.add_argument('--raw-dir',     required=True)
p.add_argument('--workload-rc', type=int, required=True)
args = p.parse_args()

raw = Path(args.raw_dir)

def safe_load(path):
    try: return json.loads(Path(path).read_text())
    except Exception: return None

def parse_iperf3(path):
    """Returns (goodput_mbps, retrans, mean_rtt_ms_or_None)."""
    j = safe_load(path)
    if not j: return None, None, None
    end = j.get('end', {})
    sumr = end.get('sum_received') or end.get('sum')
    if not sumr: return None, None, None
    bps = sumr.get('bits_per_second', 0)
    retrans = sumr.get('retransmits', 0)
    # mean_rtt is per-stream end stats
    rtts = []
    for s in end.get('streams', []):
        sr = s.get('sender', {})
        if 'mean_rtt' in sr:
            rtts.append(sr['mean_rtt'] / 1000.0)  # us → ms
    mean_rtt = statistics.mean(rtts) if rtts else None
    return bps / 1e6, retrans, mean_rtt

def parse_curl_tsv(path):
    """short-transfer output. Returns ttfb stats, req/s."""
    p2 = Path(path)
    if not p2.exists(): return {}
    rows = [l.strip().split('\t') for l in p2.read_text().splitlines()[1:]]
    ttfbs   = [float(r[1]) for r in rows if len(r) > 1]
    totals  = [float(r[3]) for r in rows if len(r) > 3]
    if not ttfbs: return {}
    ttfbs.sort()
    n = len(ttfbs)
    rps = n / (sum(totals) / 1000.0) if totals else None
    return {
      'ttfb_p50_ms': ttfbs[n//2],
      'ttfb_p95_ms': ttfbs[int(n*0.95)],
      'ttfb_p99_ms': ttfbs[int(n*0.99)],
      'req_per_sec': rps,
    }

def parse_h2load(path):
    p2 = Path(path)
    if not p2.exists(): return {}
    text = p2.read_text()
    out = {}
    m = re.search(r'finished in [\d.]+\w+,\s*([\d.]+)\s*req/s', text)
    if m: out['req_per_sec'] = float(m.group(1))
    m = re.search(r'time for request:.*?mean\s+([\d.]+)([um]?s)', text)
    if m:
        v = float(m.group(1))
        unit = m.group(2)
        if unit == 'us': v /= 1000
        elif unit == 'ms': pass
        else: v *= 1000  # 's'
        out['req_mean_ms'] = v
    return out

def parse_ping(path):
    p2 = Path(path)
    if not p2.exists(): return {}
    text = p2.read_text()
    out = {}
    m = re.search(r'min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', text)
    if m:
        out.update({
            'rtt_min_ms':   float(m.group(1)),
            'rtt_mean_ms':  float(m.group(2)),
            'rtt_max_ms':   float(m.group(3)),
            'rtt_mdev_ms':  float(m.group(4)),
        })
    m = re.search(r'(\d+)\s+packets transmitted,\s+(\d+)\s+received', text)
    if m:
        tx, rx = map(int, m.groups())
        out['observed_loss_pct'] = (tx - rx) / tx * 100 if tx else None
    return out

def parse_keystroke(path):
    p2 = Path(path)
    if not p2.exists(): return {}
    rows = [l.strip().split('\t') for l in p2.read_text().splitlines()[1:]]
    rtts = sorted(float(r[1]) for r in rows if len(r) > 1)
    if not rtts: return {}
    n = len(rtts)
    return {
      'keystroke_p50_ms': rtts[n//2],
      'keystroke_p95_ms': rtts[int(n*0.95)],
      'keystroke_p99_ms': rtts[int(n*0.99)],
      'keystroke_max_ms': rtts[-1],
    }

def parse_mpstat(path):
    p2 = Path(path)
    if not p2.exists(): return {}
    samples = []
    for line in p2.read_text().splitlines():
        # "Average:  all  ...  %idle"
        if 'all' in line and '%idle' not in line:
            parts = line.split()
            try:
                idle = float(parts[-1])
                samples.append(100.0 - idle)
            except (ValueError, IndexError): pass
    if not samples: return {}
    return {'cpu_pct_mean': statistics.mean(samples)}

def parse_iface_delta(pre, post):
    def rxtx(p):
        t = Path(p).read_text() if Path(p).exists() else ''
        rx = tx = None
        m = re.search(r'RX:.*?bytes\s+packets\b.*?\n\s*(\d+)', t, re.S)
        if m: rx = int(m.group(1))
        m = re.search(r'TX:.*?bytes\s+packets\b.*?\n\s*(\d+)', t, re.S)
        if m: tx = int(m.group(1))
        return rx, tx
    rx0, tx0 = rxtx(pre)
    rx1, tx1 = rxtx(post)
    if None in (rx0, tx0, rx1, tx1): return {}
    return {
        'rx_bytes_delta': rx1 - rx0,
        'tx_bytes_delta': tx1 - tx0,
    }

# ---- assemble metrics
metrics = {}
if args.workload == 'long-transfer':
    bps_t, retrans_t, _ = parse_iperf3(raw / 'iperf3-tcp.json')
    bps_u, _, _         = parse_iperf3(raw / 'iperf3-udp.json')
    if bps_t is not None: metrics['goodput_tcp_mbps'] = bps_t
    if bps_u is not None: metrics['goodput_udp_mbps'] = bps_u
    if retrans_t is not None: metrics['retrans_count'] = retrans_t
elif args.workload == 'short-transfer':
    metrics.update(parse_curl_tsv(raw / 'curl-timings.tsv'))
elif args.workload == 'web-mix':
    metrics.update(parse_h2load(raw / 'h2load.log'))
elif args.workload == 'ssh-interactive':
    metrics.update(parse_ping(raw / 'ping.log'))
    metrics.update(parse_keystroke(raw / 'ssh-keystroke-rtt.tsv'))

metrics.update(parse_mpstat(raw / 'mpstat.log'))
metrics.update(parse_iface_delta(raw / 'iface-pre.txt', raw / 'iface-post.txt'))

# ---- anomalies (only real warnings/errors; informational wireguard lines excluded)
anomalies = []
post_dmesg = Path(raw / 'dmesg-post.txt')
if post_dmesg.exists():
    for line in post_dmesg.read_text().splitlines():
        if re.search(r'\b(panic|BUG|Oops|kernel NULL pointer|stack trace)\b', line, re.I):
            anomalies.append(line.strip())
        elif re.search(r'\bwireguard\b.*\b(error|fail|drop|reject|timeout)\b', line, re.I):
            anomalies.append(line.strip())

doc = {
    'cell_id': args.cell_id,
    'ran_at_start': args.t0,
    'ran_at_end':   args.t1,
    'axes': {
        'arch':       args.arch,
        'tunnel':     args.tunnel,
        'workload':   args.workload,
        'loss_pct':   args.loss_pct,
        'run_index':  args.run_index,
    },
    'controls': {
        'kernel':     args.kernel,
    },
    'metrics':       metrics,
    'workload_rc':   args.workload_rc,
    'anomalies':     anomalies[:50],   # cap to keep JSON readable
}

print(json.dumps(doc, indent=2))
