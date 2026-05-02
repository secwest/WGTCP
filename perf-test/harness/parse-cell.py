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
    """short-transfer output. Returns ttfb stats, req/s.

    Only counts SUCCESSFUL HTTPS GETs (http_code 2xx) for TTFB stats.
    Failed curls (http_code 000 = TLS/connect failure, or anything non-2xx)
    have ttfb=0 in the raw TSV, which would corrupt the percentiles.
    Requires at least 10 successful samples before reporting stats — under
    that we treat the cell as "no useful data" rather than emit garbage.
    req_per_sec is computed from successful requests only and the wallclock
    time elapsed across ALL attempts (so heavy failure rates correctly
    reduce req/s, but TTFB reflects only what actually arrived).
    """
    p2 = Path(path)
    if not p2.exists(): return {}
    rows = [l.strip().split('\t') for l in p2.read_text().splitlines()[1:]]
    rows = [r for r in rows if len(r) >= 5]
    if not rows: return {}
    ok_rows  = [r for r in rows if r[4].startswith('2')]
    ttfbs    = sorted(float(r[1]) for r in ok_rows if r[1])
    totals_all = [float(r[3]) for r in rows if r[3]]
    n_ok = len(ttfbs)
    out = {
      'http_success_pct': 100.0 * n_ok / len(rows) if rows else None,
      'n_curl_attempts':  len(rows),
      'n_curl_ok':        n_ok,
    }
    if totals_all and n_ok >= 10:
        out['req_per_sec'] = n_ok / (sum(totals_all) / 1000.0)
    if n_ok >= 10:
        out['ttfb_p50_ms'] = ttfbs[n_ok // 2]
        out['ttfb_p95_ms'] = ttfbs[int(n_ok * 0.95)]
        out['ttfb_p99_ms'] = ttfbs[min(int(n_ok * 0.99), n_ok - 1)]
    return out

def parse_h2load(path):
    p2 = Path(path)
    if not p2.exists(): return {}
    text = p2.read_text()
    out = {}

    # If the run failed entirely (no requests succeeded) emit no latency/req
    # metrics. Otherwise h2load prints "0us 0us 0us 0us 0.00%" lines and the
    # parser would faithfully emit zero TTFB / req-rate, which downstream is
    # indistinguishable from a real measurement.  Detect by looking at the
    # 'requests:' status line.
    m_req = re.search(
        r'requests:\s*(\d+)\s*total,\s*\d+\s*started,\s*\d+\s*done,\s*'
        r'(\d+)\s*succeeded,\s*\d+\s*failed,\s*(\d+)\s*errored',
        text,
    )
    if m_req:
        total_req  = int(m_req.group(1))
        succeeded  = int(m_req.group(2))
        errored    = int(m_req.group(3))
        out['h2load_total']     = total_req
        out['h2load_succeeded'] = succeeded
        out['h2load_errored']   = errored
        if total_req == 0 or succeeded == 0:
            # No usable data; surface only the status counts so callers can
            # detect the failure and emit em-dashes.
            return out

    m = re.search(r'finished in [\d.]+\w+,\s*([\d.]+)\s*req/s', text)
    if m: out['req_per_sec'] = float(m.group(1))

    # h2load summary lines look like:
    #   time for request:      265us     30.27ms      5.56ms      5.64ms    91.40%
    #   time for connect:     6.92ms     39.38ms     21.54ms      9.97ms    56.00%
    #   time to 1st byte:    11.46ms     49.40ms     42.08ms      6.98ms    94.00%
    # columns are: min, max, mean, sd, +/- sd (sd-fraction).
    def to_ms(v, unit):
        v = float(v)
        if unit == 'us': return v / 1000.0
        if unit == 'ms': return v
        if unit == 's':  return v * 1000.0
        return v

    val = r'([\d.]+)(us|ms|s)'
    triples = [
        ('req',     r'time for request:'),
        ('connect', r'time for connect:'),
        ('ttfb',    r'time to 1st byte:'),
    ]
    for prefix, label in triples:
        pat = label + r'\s+' + val + r'\s+' + val + r'\s+' + val + r'\s+' + val
        m = re.search(pat, text)
        if not m: continue
        mn  = to_ms(m.group(1), m.group(2))
        mx  = to_ms(m.group(3), m.group(4))
        avg = to_ms(m.group(5), m.group(6))
        sd  = to_ms(m.group(7), m.group(8))
        out[f'{prefix}_min_ms']  = mn
        out[f'{prefix}_max_ms']  = mx
        out[f'{prefix}_mean_ms'] = avg
        out[f'{prefix}_sd_ms']   = sd

    # Failure / status awareness — h2load reports per-status counts.
    m = re.search(r'status codes:\s*(\d+)\s*2xx,\s*(\d+)\s*3xx,\s*(\d+)\s*4xx,\s*(\d+)\s*5xx', text)
    if m:
        s2,s3,s4,s5 = map(int, m.groups())
        total = s2+s3+s4+s5
        out['http_2xx'] = s2
        out['http_4xx'] = s4
        out['http_5xx'] = s5
        if total:
            out['http_success_pct'] = 100.0 * s2 / total
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
