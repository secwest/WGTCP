#!/usr/bin/env python3
import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

TRANSITION_ERRORS = (
    subprocess.CalledProcessError,
    json.JSONDecodeError,
    OSError,
    ValueError,
)


def wait_until(timestamp_ns: int) -> None:
    while True:
        remaining_ns = timestamp_ns - time.time_ns()
        if remaining_ns <= 0:
            return
        time.sleep(min(remaining_ns / 1_000_000_000, 0.25))


def append_event(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def clock_quality() -> tuple[int, int]:
    result = subprocess.run(
        ["chronyc", "tracking"],
        check=True,
        capture_output=True,
        text=True,
    )
    system_time = re.search(
        r"^System time\s*:\s*([0-9.]+) seconds",
        result.stdout,
        re.MULTILINE,
    )
    root_dispersion = re.search(
        r"^Root dispersion\s*:\s*([0-9.]+) seconds",
        result.stdout,
        re.MULTILINE,
    )
    root_delay = re.search(
        r"^Root delay\s*:\s*([0-9.]+) seconds",
        result.stdout,
        re.MULTILINE,
    )
    leap_status = re.search(
        r"^Leap status\s*:\s*(\S+)",
        result.stdout,
        re.MULTILINE,
    )
    if (
        system_time is None
        or root_dispersion is None
        or root_delay is None
        or leap_status is None
        or leap_status.group(1) != "Normal"
    ):
        raise ValueError("chrony is not synchronized")
    offset_ns = math.ceil(float(system_time.group(1)) * 1_000_000_000)
    error_bound_ns = offset_ns + math.ceil(
        (
            float(root_dispersion.group(1))
            + float(root_delay.group(1)) / 2.0
        )
        * 1_000_000_000
    )
    return offset_ns, error_bound_ns


def change_loss(
    shape_link: Path,
    iface: str,
    ifb: str,
    rtt_ms: float,
    model: str,
    loss_pct: float,
    burst_p: float,
    burst_r: float,
    burst_h: float,
    burst_k: float,
) -> tuple[list[dict[str, Any]], int, int, int, int]:
    command = [
        str(shape_link),
        "change-loss",
        "--iface",
        iface,
        "--ifb",
        ifb,
        "--rtt-ms",
        str(rtt_ms),
        "--loss-model",
        model,
        "--loss-pct",
        str(loss_pct),
        "--burst-p",
        str(burst_p),
        "--burst-r",
        str(burst_r),
        "--burst-h",
        str(burst_h),
        "--burst-k",
        str(burst_k),
    ]
    command_start_ns = time.time_ns()
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    command_end_ns = time.time_ns()
    document = json.loads(result.stdout)
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("qdisc"), list)
        or not isinstance(document.get("change_start_ns"), int)
        or not isinstance(document.get("change_end_ns"), int)
        or document["change_end_ns"] < document["change_start_ns"]
    ):
        raise ValueError("shape-link output is not a timed qdisc transition")
    return (
        document["qdisc"],
        command_start_ns,
        command_end_ns,
        document["change_start_ns"],
        document["change_end_ns"],
    )


def touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    os.chmod(path, 0o644)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shape-link", required=True, type=Path)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--ifb", default="ifb-wgmt")
    parser.add_argument("--rtt-ms", required=True, type=float)
    parser.add_argument("--loss-model", required=True, choices=("random", "gemodel"))
    parser.add_argument("--loss-pct", default=0.0, type=float)
    parser.add_argument("--burst-p", default=0.0, type=float)
    parser.add_argument("--burst-r", default=0.0, type=float)
    parser.add_argument("--burst-h", default=0.0, type=float)
    parser.add_argument("--burst-k", default=0.0, type=float)
    parser.add_argument("--start-ns", required=True, type=int)
    parser.add_argument("--duration-ms", required=True, type=int)
    parser.add_argument("--event-log", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    parser.add_argument("--done-file", required=True, type=Path)
    parser.add_argument("--state-marker", required=True, type=Path)
    args = parser.parse_args()

    if args.start_ns <= time.time_ns():
        parser.error("--start-ns must be in the future")
    if args.duration_ms <= 0:
        parser.error("--duration-ms must be positive")
    if not args.shape_link.is_file():
        parser.error("--shape-link is unavailable")
    if not args.state_marker.is_file():
        parser.error("active shaping marker is unavailable")
    try:
        _, initial_clock_error_bound_ns = clock_quality()
    except (subprocess.CalledProcessError, ValueError) as error:
        parser.error(f"clock quality is unavailable: {error}")
    if initial_clock_error_bound_ns > 5_000_000:
        parser.error("clock error bound exceeds 5 ms")

    args.event_log.parent.mkdir(parents=True, exist_ok=True)
    if args.event_log.exists() or args.done_file.exists():
        parser.error("timed impairment evidence already exists")
    touch(args.ready_file)

    transitions = (
        (
            "loss_start",
            args.start_ns,
            args.loss_model,
            args.loss_pct,
            args.burst_p,
            args.burst_r,
            args.burst_h,
            args.burst_k,
        ),
        (
            "loss_stop",
            args.start_ns + args.duration_ms * 1_000_000,
            "none",
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        ),
    )
    loss_may_be_active = False
    try:
        for event_name, requested_ns, model, loss, p, r, h, k in transitions:
            wait_until(max(time.time_ns(), requested_ns - 1_000_000_000))
            clock_offset_ns, clock_error_bound_ns = clock_quality()
            if clock_error_bound_ns > 5_000_000:
                raise ValueError("clock error bound exceeds 5 ms")
            wait_until(requested_ns)
            if event_name == "loss_start":
                loss_may_be_active = True
            try:
                (
                    qdisc,
                    command_start_ns,
                    command_end_ns,
                    change_start_ns,
                    change_end_ns,
                ) = change_loss(
                    args.shape_link,
                    args.iface,
                    args.ifb,
                    args.rtt_ms,
                    model,
                    loss,
                    p,
                    r,
                    h,
                    k,
                )
            except TRANSITION_ERRORS as error:
                append_event(
                    args.event_log,
                    {
                        "event": event_name,
                        "requested_ns": requested_ns,
                        "success": False,
                        "error": str(error),
                    },
                )
                raise
            if event_name == "loss_stop":
                loss_may_be_active = False
            append_event(
                args.event_log,
                {
                    "event": event_name,
                    "requested_ns": requested_ns,
                    "command_start_ns": command_start_ns,
                    "command_end_ns": command_end_ns,
                    "change_start_ns": change_start_ns,
                    "change_end_ns": change_end_ns,
                    "applied_ns": change_end_ns,
                    "clock_offset_ns": clock_offset_ns,
                    "clock_error_bound_ns": clock_error_bound_ns,
                    "success": True,
                    "loss_model": model,
                    "qdisc": qdisc,
                },
            )
    except TRANSITION_ERRORS:
        if loss_may_be_active:
            try:
                (
                    qdisc,
                    command_start_ns,
                    command_end_ns,
                    change_start_ns,
                    change_end_ns,
                ) = change_loss(
                    args.shape_link,
                    args.iface,
                    args.ifb,
                    args.rtt_ms,
                    "none",
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                )
                append_event(
                    args.event_log,
                    {
                        "event": "failsafe_clear",
                        "command_start_ns": command_start_ns,
                        "command_end_ns": command_end_ns,
                        "change_start_ns": change_start_ns,
                        "change_end_ns": change_end_ns,
                        "applied_ns": change_end_ns,
                        "success": True,
                        "loss_model": "none",
                        "qdisc": qdisc,
                    },
                )
            except TRANSITION_ERRORS as clear_error:
                append_event(
                    args.event_log,
                    {
                        "event": "failsafe_clear",
                        "success": False,
                        "error": str(clear_error),
                    },
                )
        raise

    touch(args.done_file)
    os.chmod(args.event_log, 0o644)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr, file=sys.stderr, end="")
        raise
