#!/bin/bash
# Workload: short-transfer
# Sequential HTTPS GETs of 1KB, 64KB, 1MB objects (200 each, interleaved).
# Server: nginx on peer, port 443, serving /var/www/perf/{1k,64k,1m}.bin.

set -euo pipefail
PEER="$1"
RAW="$2"

OUT="$RAW/curl-timings.tsv"
echo -e "size\tttfb_ms\tconnect_ms\ttotal_ms\thttp_code" > "$OUT"

for i in $(seq 1 200); do
  for sz in 1k 64k 1m; do
    curl -k -s -o /dev/null \
        -w "${sz}\t%{time_starttransfer}\t%{time_connect}\t%{time_total}\t%{http_code}\n" \
        --resolve "perf:443:$PEER" \
        "https://perf/static/${sz}.bin" >> "$OUT"
  done
done

# Convert seconds to ms in-place
awk -F'\t' 'NR==1{print; next}
            {printf "%s\t%.3f\t%.3f\t%.3f\t%s\n",$1,$2*1000,$3*1000,$4*1000,$5}' \
    "$OUT" > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"

echo "short-transfer OK"
