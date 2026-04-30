#!/bin/bash
# Workload: web-mix
# Synthetic mixed-size HTTPS pull via h2load.
# Server: nginx on peer, port 8443, serving Zipf-distributed object catalog.

set -euo pipefail
PEER="$1"
RAW="$2"

h2load -n 5000 -c 50 -m 10 -t 2 \
    --header "Host: perf" \
    "https://$PEER:8443/index.html" \
    > "$RAW/h2load.log" 2>&1

# h2load writes summary to stdout; copy to a structured file for parser
echo "web-mix OK"
