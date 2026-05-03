#!/bin/bash
# Workload: web-mix
# Synthetic mixed-size HTTPS pull via h2load.
# Server: nginx on peer, port 8443, serving Zipf-distributed object catalog.

set -euo pipefail
PEER="$1"
RAW="$2"

# Warmup: a single HTTP/2 TLS handshake to the same endpoint. This
# exercises the wg-tcp peer connection / route / TLS-session paths so
# that h2load's 50-conn burst doesn't have to also pay for cold-start
# costs. On LAN-x64 TCP-WG specifically, the cold burst was observed to
# leave all 50 SYNs stuck in SYN-SENT (no SYN-ACK back), producing
# 5000/5000 errored cells. Warmup is a ~1ms no-op when tunnel is healthy.
curl -k --http2 --connect-timeout 5 --max-time 10 \
    -o /dev/null -sS \
    "https://$PEER:8443/index.html" \
    > "$RAW/warmup-curl.log" 2>&1 || true

# Run h2load with up to 3 attempts. If the result is "0 started" (TCP
# connections never established — symptomatic of a transient wg-tcp
# burst wedge that typically clears within seconds), pause 5s and retry
# with identical parameters. Canonical h2load.log = first attempt that
# starts at least one request; diagnostic logs from all attempts are
# preserved as h2load-attempt{N}.log so failures stay observable.
H2LOAD_OK=0
for ATTEMPT in 1 2 3; do
    LOG="$RAW/h2load-attempt${ATTEMPT}.log"
    h2load -n 5000 -c 50 -m 10 -t 2 \
        "https://$PEER:8443/index.html" \
        > "$LOG" 2>&1 || true
    # "requests: N total, M started" — accept when M > 0
    if grep -qE "requests: [0-9]+ total, [1-9][0-9]* started" "$LOG"; then
        cp "$LOG" "$RAW/h2load.log"
        H2LOAD_OK=1
        echo "web-mix attempt $ATTEMPT: started>0, accepting" >&2
        break
    fi
    echo "web-mix attempt $ATTEMPT: 0 started, retrying after 5s pause" >&2
    sleep 5
done

if [ "$H2LOAD_OK" = "0" ]; then
    cp "$RAW/h2load-attempt3.log" "$RAW/h2load.log"
    echo "web-mix: all 3 attempts had 0 started — recording failed cell" >&2
fi

# h2load on LAN cells finishes in <1s — short enough that mpstat's first
# sample interval may be cut off. Idle wait gives mpstat at least one
# extra steady-state sample so cpu_pct_mean has data to average.
sleep 2

echo "web-mix OK"
