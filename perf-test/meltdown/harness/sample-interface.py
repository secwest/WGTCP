#!/usr/bin/env python3
"""Sample tunnel interface counters at stable 100 ms intervals."""

from __future__ import annotations

import argparse
import time
from pathlib import Path


def read_counter(path: Path) -> int:
    return int(path.read_text(encoding="ascii").strip())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--duration", required=True, type=float)
    args = parser.parse_args()

    stats = Path("/sys/class/net") / args.iface / "statistics"
    rx_path = stats / "rx_bytes"
    tx_path = stats / "tx_bytes"
    if not rx_path.is_file() or not tx_path.is_file():
        parser.error(f"interface counters unavailable: {args.iface}")

    interval = 0.1
    started = time.monotonic()
    deadline = started
    print("timestamp_ns,rx_bytes,tx_bytes", flush=True)
    while True:
        now = time.monotonic()
        if now - started > args.duration:
            break
        print(
            f"{time.time_ns()},{read_counter(rx_path)},{read_counter(tx_path)}",
            flush=True,
        )
        deadline += interval
        time.sleep(max(0.0, deadline - time.monotonic()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
