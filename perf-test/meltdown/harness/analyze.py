#!/usr/bin/env python3
"""Analyze TCP-over-TCP meltdown cells without third-party dependencies."""

from __future__ import annotations

import argparse
import bisect
import csv
import json
import math
import re
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STALL_THRESHOLD = 0.20
TREND_THRESHOLD = -0.20
TREND_T_THRESHOLD = -2.0
RTO_THRESHOLD = 1.0
DELIVERY_BIN_NS = 100_000_000
MAX_COUNTER_ALIGNMENT_NS = 75_000_000
TCP_EVENTS_HEADER = "timestamp_ns,event,layer,sport,dport,value1,value2,value3"
MAX_TRACE_SUMMARY_LAG = 1
WORKLOAD_MIN_INTERVAL_FRACTION = 0.995
WORKLOAD_MAX_INTERVAL_FRACTION = 1.005
WORKLOAD_MAX_INTERVAL_GAP_S = 0.02
WORKLOAD_MAX_INTERVAL_BOUNDARY_ERROR_S = 0.001
BASELINE_PREFLIGHT_MAX_RTT_MS = 20.0
IMPAIRMENT_VALIDATION_POLICIES = {"strict", "transport_aware"}
PUBLISHED_AXIS_FIELDS = (
    "tunnel",
    "rate_mbps",
    "rtt_ms",
    "queue_bdp",
    "queue_kind",
    "loss_model",
    "loss_pct",
    "burst_p",
    "burst_r",
    "burst_h",
    "burst_k",
    "flows",
    "duration_s",
    "warmup_s",
    "workload_completion",
    "impairment_validation",
    "inner_cc",
    "direction",
    "competitor",
    "campaign_fingerprint",
    "cell_fingerprint",
)
FINAL_CONTROL_ERRORS = (
    re.compile(
        r"unable to receive results:\s*(?:Connection reset by peer|Broken pipe)?"
    ),
    re.compile(
        r"unable to send control message - port may not be available, "
        r"the other side may have stopped running, etc\.: Broken pipe"
    ),
    re.compile(r"control socket has closed unexpectedly"),
)
TCP_EVENT_SUMMARIES = {
    (event, layer)
    for event in ("rto", "retrans")
    for layer in ("inner", "outer", "competitor")
}
PER_CPU_SUMMARY_KEYS = {
    (event_id, layer_id): (event, layer)
    for event_id, event in ((1, "rto"), (2, "retrans"))
    for layer_id, layer in ((1, "inner"), (2, "outer"), (3, "competitor"))
}
PER_CPU_SUMMARY_LINE = re.compile(
    r"^@event_counts\[(\d+),\s*(\d+)\]:\s*(\d+)$"
)
CPU_SEQUENCE_SUMMARY_LINE = re.compile(
    r"^@event_sequences\[(\d+),\s*(\d+),\s*(\d+)\]:\s*(\d+)$"
)


def load_json(path: Path, default: Any = None) -> Any:
    try:
        text = path.read_text(encoding="utf-8-sig").lstrip()
        starts = [index for token in ("{", "[") if (index := text.find(token)) >= 0]
        if not starts:
            return default
        value, _ = json.JSONDecoder().raw_decode(text[min(starts) :])
        return value
    except (OSError, json.JSONDecodeError):
        return default


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return values
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def iperf_intervals(
    doc: dict[str, Any],
    summary_keys: tuple[str, ...] = ("sum_received", "sum"),
    *,
    allow_stream_fallback: bool = True,
) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    for interval in doc.get("intervals", []):
        if not isinstance(interval, dict):
            continue
        summary = next(
            (
                candidate
                for key in summary_keys
                if isinstance((candidate := interval.get(key)), dict) and candidate
            ),
            None,
        )
        if not summary and allow_stream_fallback:
            streams = interval.get("streams", [])
            if isinstance(streams, list) and streams:
                summary = {
                    "start": min(as_float(s.get("start")) for s in streams),
                    "end": max(as_float(s.get("end")) for s in streams),
                    "seconds": max(as_float(s.get("end")) for s in streams)
                    - min(as_float(s.get("start")) for s in streams),
                    "bytes": sum(as_int(s.get("bytes")) for s in streams),
                    "bits_per_second": sum(as_float(s.get("bits_per_second")) for s in streams),
                    "omitted": any(bool(s.get("omitted")) for s in streams),
                }
        if not summary or summary.get("omitted"):
            continue
        rows.append(
            {
                "start": as_float(summary.get("start")),
                "end": as_float(summary.get("end")),
                "seconds": as_float(summary.get("seconds")),
                "bytes": float(as_int(summary.get("bytes"))),
                "bits_per_second": as_float(summary.get("bits_per_second")),
            }
        )
    return rows


def interval_completion_stats(
    intervals: list[dict[str, float]], duration: float
) -> dict[str, Any]:
    span = (
        max(row["end"] for row in intervals)
        - min(row["start"] for row in intervals)
        if intervals
        else None
    )
    total = sum(row["seconds"] for row in intervals) if intervals else None
    max_gap = (
        max(
            (
                max(0.0, current["start"] - previous["end"])
                for previous, current in zip(intervals, intervals[1:])
            ),
            default=0.0,
        )
        if intervals
        else None
    )
    max_overlap = (
        max(
            (
                max(0.0, previous["end"] - current["start"])
                for previous, current in zip(intervals, intervals[1:])
            ),
            default=0.0,
        )
        if intervals
        else None
    )
    max_duration_error = (
        max(
            abs(row["seconds"] - (row["end"] - row["start"]))
            for row in intervals
        )
        if intervals
        else None
    )
    ordered = bool(intervals) and all(
        current["start"] > previous["start"]
        and current["end"] > previous["end"]
        for previous, current in zip(intervals, intervals[1:])
    )
    shape_valid = bool(intervals) and all(
        math.isfinite(row[key])
        for row in intervals
        for key in ("start", "end", "seconds")
    ) and all(
        row["start"] >= 0
        and row["end"] > row["start"]
        and row["seconds"] > 0
        for row in intervals
    )
    return {
        "count": len(intervals),
        "span_s": span,
        "sum_s": total,
        "span_fraction": span / duration if span is not None and duration > 0 else None,
        "sum_fraction": total / duration if total is not None and duration > 0 else None,
        "max_gap_s": max_gap,
        "max_overlap_s": max_overlap,
        "max_duration_error_s": max_duration_error,
        "ordered": ordered,
        "shape_valid": shape_valid,
    }


def interval_completion_issues(
    stats: dict[str, Any], prefix: str = "interval"
) -> list[str]:
    issues: list[str] = []
    if not stats["shape_valid"]:
        issues.append(f"{prefix}_shape")
    if not stats["ordered"]:
        issues.append(f"{prefix}_order")
    if (
        stats["max_overlap_s"] is None
        or stats["max_overlap_s"] > WORKLOAD_MAX_INTERVAL_BOUNDARY_ERROR_S
    ):
        issues.append(f"{prefix}_overlap")
    if (
        stats["max_duration_error_s"] is None
        or stats["max_duration_error_s"] > WORKLOAD_MAX_INTERVAL_BOUNDARY_ERROR_S
    ):
        issues.append(f"{prefix}_duration")
    if not (
        stats["span_fraction"] is not None
        and WORKLOAD_MIN_INTERVAL_FRACTION
        <= stats["span_fraction"]
        <= WORKLOAD_MAX_INTERVAL_FRACTION
    ):
        issues.append(f"{prefix}_span")
    if not (
        stats["sum_fraction"] is not None
        and WORKLOAD_MIN_INTERVAL_FRACTION
        <= stats["sum_fraction"]
        <= WORKLOAD_MAX_INTERVAL_FRACTION
    ):
        issues.append(f"{prefix}_sum")
    if (
        stats["max_gap_s"] is None
        or stats["max_gap_s"] > WORKLOAD_MAX_INTERVAL_GAP_S
    ):
        issues.append(f"{prefix}_gap")
    return issues


def final_control_error_allowed(error: str) -> bool:
    normalized = error.strip()
    return any(pattern.fullmatch(normalized) for pattern in FINAL_CONTROL_ERRORS)


def workload_completion(
    axes: dict[str, str],
    document: dict[str, Any],
    intervals: list[dict[str, float]],
    delivery: dict[str, Any],
    stderr: str | None = "",
) -> tuple[dict[str, Any], list[str]]:
    policy = (axes.get("workload_completion") or "strict").strip()
    try:
        workload_rc: int | None = int(axes["workload_rc"])
    except (KeyError, TypeError, ValueError):
        workload_rc = None
    duration = as_float(axes.get("duration_s"))
    expected_flows = max(1, as_int(axes.get("flows"), 1))
    if axes.get("direction") == "bidir":
        expected_flows *= 2
    connected = document.get("start", {}).get("connected", [])
    connected_flows = len(connected) if isinstance(connected, list) else 0
    error = str(document.get("error") or "")
    reported_iperf_version = str(document.get("start", {}).get("version") or "")
    completion_intervals = (
        iperf_intervals(
            document,
            ("sum",),
            allow_stream_fallback=False,
        )
        if axes.get("direction") == "bidir"
        else intervals
    )
    interval_stats = interval_completion_stats(completion_intervals, duration)
    bidir_reverse_stats = (
        interval_completion_stats(
            iperf_intervals(
                document,
                ("sum_bidir_reverse",),
                allow_stream_fallback=False,
            ),
            duration,
        )
        if axes.get("direction") == "bidir"
        else None
    )
    delivery_complete = (
        delivery.get("expected_bins", 0) > 0
        and delivery.get("covered_bins") == delivery.get("expected_bins")
    )
    error_allowed = final_control_error_allowed(error)
    metrics: dict[str, Any] = {
        "workload_completion_policy": policy,
        "workload_exit_code": workload_rc,
        "workload_completion_fallback_used": False,
        "workload_completion_valid": False,
        "workload_error": error,
        "workload_stderr_empty": stderr is not None and not stderr.strip(),
        "workload_final_control_error_allowed": error_allowed,
        "workload_reported_iperf_version": reported_iperf_version,
        "workload_iperf_version_matches": (
            bool(axes.get("iperf_version"))
            and reported_iperf_version == axes.get("iperf_version")
        ),
        "workload_connected_flows": connected_flows,
        "workload_expected_flows": expected_flows,
        "workload_interval_count": interval_stats["count"],
        "workload_interval_span_s": interval_stats["span_s"],
        "workload_interval_sum_s": interval_stats["sum_s"],
        "workload_interval_span_fraction": interval_stats["span_fraction"],
        "workload_interval_sum_fraction": interval_stats["sum_fraction"],
        "workload_interval_max_gap_s": interval_stats["max_gap_s"],
        "workload_interval_max_overlap_s": interval_stats["max_overlap_s"],
        "workload_interval_max_duration_error_s": interval_stats[
            "max_duration_error_s"
        ],
        "workload_interval_ordered": interval_stats["ordered"],
        "workload_interval_shape_valid": interval_stats["shape_valid"],
        "workload_interface_delivery_complete": delivery_complete,
    }
    if bidir_reverse_stats is not None:
        metrics.update(
            {
                f"workload_bidir_reverse_interval_{key}": value
                for key, value in bidir_reverse_stats.items()
            }
        )

    issues: list[str] = []
    if policy == "strict":
        if workload_rc != 0:
            issues.append("exit_status")
    elif policy == "interval_complete":
        if (
            not axes.get("iperf_version")
            or reported_iperf_version != axes.get("iperf_version")
        ):
            issues.append("iperf_version")
        if not re.fullmatch(r"[a-f0-9]{64}", axes.get("iperf_sha256", "")):
            issues.append("iperf_sha256")
        if connected_flows != expected_flows:
            issues.append("connected_flows")
        issues.extend(interval_completion_issues(interval_stats))
        if bidir_reverse_stats is not None:
            issues.extend(
                interval_completion_issues(
                    bidir_reverse_stats,
                    "bidir_reverse_interval",
                )
            )
        if not delivery_complete:
            issues.append("interface_delivery")
        if workload_rc not in (0, 1):
            issues.append("exit_status")
        elif workload_rc == 1 and not error_allowed:
            issues.append("final_control_error")
        if workload_rc == 0 and error.strip():
            issues.append("unexpected_error")
        if stderr is None or stderr.strip():
            issues.append("stderr")
    else:
        issues.append("policy")

    metrics["workload_completion_fallback_used"] = (
        policy == "interval_complete" and workload_rc == 1 and not issues
    )
    metrics["workload_completion_valid"] = not issues
    return metrics, issues


def competitor_workload(
    cell_dir: Path, axes: dict[str, str]
) -> tuple[dict[str, float | int | None], list[str]]:
    if as_int(axes.get("competitor")) != 1:
        return {
            "competitor_bytes": None,
            "competitor_seconds": None,
            "competitor_goodput_mbps": None,
        }, []

    issues: list[str] = []
    if as_int(axes.get("competitor_rc"), 1) != 0:
        issues.append("exit_status")
    document = load_json(cell_dir / "competitor-iperf3.json")
    if not isinstance(document, dict) or document.get("error"):
        issues.append("output")
        return {
            "competitor_bytes": None,
            "competitor_seconds": None,
            "competitor_goodput_mbps": None,
        }, issues

    end = document.get("end") or {}
    summary = end.get("sum_received") or end.get("sum_sent") or end.get("sum") or {}
    transferred = as_int(summary.get("bytes"))
    seconds = as_float(summary.get("seconds"))
    expected_seconds = as_float(axes.get("duration_s")) + as_float(
        axes.get("warmup_s")
    )
    if transferred <= 0:
        issues.append("no_traffic")
    if seconds < expected_seconds * 0.80:
        issues.append("short_duration")
    return {
        "competitor_bytes": transferred,
        "competitor_seconds": seconds,
        "competitor_goodput_mbps": (
            transferred * 8.0 / seconds / 1_000_000.0 if seconds > 0 else None
        ),
    }, issues


def interface_samples(path: Path) -> list[tuple[int, int, int]]:
    rows: list[tuple[int, int, int]] = []
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                rows.append(
                    (
                        int(row["timestamp_ns"]),
                        int(row["rx_bytes"]),
                        int(row["tx_bytes"]),
                    )
                )
    except (KeyError, OSError, TypeError, ValueError):
        return []
    return sorted(rows)


def first_inner_data_ns(path: Path) -> int | None:
    try:
        first_line = path.read_text(encoding="utf-8-sig").splitlines()[0]
        return round(float(first_line.split()[0]) * 1_000_000_000)
    except (IndexError, OSError, ValueError):
        return None


def receiver_data_start_ns(cell_dir: Path, direction: str) -> int | None:
    receivers = {
        "forward": ("server",),
        "reverse": ("client",),
        "bidir": ("client", "server"),
    }.get(direction, ())
    starts: list[int] = []
    for endpoint in receivers:
        value = first_inner_data_ns(cell_dir / endpoint / "first-inner-data.txt")
        if value is not None:
            starts.append(value)
    return min(starts) if len(starts) == len(receivers) and starts else None


def sampled_rx_at(
    rows: list[tuple[int, int, int]], timestamps: list[int], timestamp_ns: int
) -> tuple[int, int] | None:
    index = bisect.bisect_left(timestamps, timestamp_ns)
    candidates = [
        rows[candidate]
        for candidate in (index - 1, index)
        if 0 <= candidate < len(rows)
    ]
    if not candidates:
        return None
    sample = min(
        candidates,
        key=lambda row: (abs(row[0] - timestamp_ns), row[0] > timestamp_ns),
    )
    if abs(sample[0] - timestamp_ns) > MAX_COUNTER_ALIGNMENT_NS:
        return None
    return sample[0], sample[1]


def interface_delivery_bins(
    cell_dir: Path, direction: str, warmup_s: float, duration_s: float
) -> dict[str, Any]:
    data_start_ns = receiver_data_start_ns(cell_dir, direction)
    expected_bins = max(0, round(duration_s * 10))
    if data_start_ns is None or expected_bins == 0:
        return {
            "bps": [],
            "covered_bins": 0,
            "expected_bins": expected_bins,
            "source_endpoints": [],
            "measurement_start_ns": None,
            "measurement_end_ns": None,
        }

    source_endpoints = {
        "forward": ("server",),
        "reverse": ("client",),
        "bidir": ("client", "server"),
    }.get(direction, ())
    measurement_start = data_start_ns + round(warmup_s * 1_000_000_000)
    measurement_end = measurement_start + round(duration_s * 1_000_000_000)
    delivered = [0] * expected_bins
    valid = [True] * expected_bins

    for endpoint_name in source_endpoints:
        rows = interface_samples(cell_dir / endpoint_name / "interface-series.csv")
        timestamps = [row[0] for row in rows]
        boundaries = [
            sampled_rx_at(rows, timestamps, measurement_start + index * DELIVERY_BIN_NS)
            for index in range(expected_bins + 1)
        ]
        for index, (before, after) in enumerate(zip(boundaries, boundaries[1:])):
            if before is None or after is None:
                valid[index] = False
                continue
            before_timestamp, before_rx = before
            after_timestamp, after_rx = after
            if after_timestamp <= before_timestamp or after_rx < before_rx:
                valid[index] = False
                continue
            delivered[index] += after_rx - before_rx

    covered = [index for index, is_valid in enumerate(valid) if is_valid]
    return {
        "bps": [delivered[index] * 80.0 for index in covered],
        "covered_bins": len(covered),
        "expected_bins": expected_bins,
        "source_endpoints": list(source_endpoints),
        "measurement_start_ns": measurement_start,
        "measurement_end_ns": measurement_end,
    }


def ols_trend(values: list[float]) -> dict[str, float | None]:
    n = len(values)
    if n < 3:
        return {"slope_bps_per_bin": None, "slope_t": None, "trend_drop_fraction": None}
    mean_y = statistics.fmean(values)
    x_mean = (n - 1) / 2.0
    sxx = sum((x - x_mean) ** 2 for x in range(n))
    slope = sum((x - x_mean) * (y - mean_y) for x, y in enumerate(values)) / sxx
    intercept = mean_y - slope * x_mean
    residual = sum((y - (intercept + slope * x)) ** 2 for x, y in enumerate(values))
    if n > 2 and residual > 0:
        slope_se = math.sqrt((residual / (n - 2)) / sxx)
        slope_t = slope / slope_se if slope_se else 0.0
    else:
        slope_t = 0.0
    trend_fraction = slope * (n - 1) / mean_y if mean_y > 0 else None
    return {
        "slope_bps_per_bin": slope,
        "slope_t": slope_t,
        "trend_drop_fraction": trend_fraction,
    }


def longest_zero_run(values: list[float]) -> int:
    longest = current = 0
    for value in values:
        if value <= 0:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def zero_delivery_runs(
    values: list[float], measurement_start_ns: int | None = None
) -> list[dict[str, int | float | bool]]:
    runs: list[dict[str, int | float | bool]] = []
    start: int | None = None
    for index, value in enumerate([*values, 1.0]):
        if value <= 0 and start is None:
            start = index
        elif value > 0 and start is not None:
            run = {
                "start_bin": start,
                "end_bin_exclusive": index,
                "start_s": start * DELIVERY_BIN_NS / 1_000_000_000,
                "end_s": index * DELIVERY_BIN_NS / 1_000_000_000,
                "duration_ms": (index - start) * DELIVERY_BIN_NS // 1_000_000,
                "left_censored": start == 0,
                "right_censored": index == len(values),
            }
            if measurement_start_ns is not None:
                run["start_ns"] = measurement_start_ns + start * DELIVERY_BIN_NS
                run["end_ns"] = measurement_start_ns + index * DELIVERY_BIN_NS
            runs.append(run)
            start = None
    return runs


def rolling_minimum_mbps(values: list[float], window_bins: int) -> float | None:
    if window_bins <= 0 or len(values) < window_bins:
        return None
    return (
        min(
            statistics.fmean(values[index : index + window_bins])
            for index in range(len(values) - window_bins + 1)
        )
        / 1_000_000
    )


def dynamic_episode_metrics(
    values: list[float],
    measurement_start_ns: int | None,
    measurement_end_ns: int | None,
    impairment_start_ns: int | None,
    impairment_stop_ns: int | None,
    recovery_start_ns: int | None,
    timed_events: list[dict[str, Any]],
    tunnel: str,
) -> tuple[dict[str, int | float | bool | None], list[str]]:
    defaults: dict[str, int | float | bool | None] = {
        "pre_median_mbps": None,
        "pre_mean_mbps": None,
        "impairment_mean_mbps": None,
        "post_0_1s_mbps": None,
        "post_1_5s_mbps": None,
        "post_5_10s_mbps": None,
        "post_10_30s_mbps": None,
        "post_30_60s_mbps": None,
        "episode_min_1s_mbps": None,
        "episode_min_5s_mbps": None,
        "episode_longest_stall_ms": None,
        "episode_stall_fraction_100ms": None,
        "bandwidth_deficit_mbit": None,
        "first_delivery_after_recovery_ms": None,
        "recovery_90_ms": None,
        "recovery_90_right_censored": None,
        "episode_outer_recovery_events": None,
        "mechanism_observed": False,
        "user_visible_disruption": False,
        "episode_below_half_pre": False,
        "quasi_meltdown_episode": False,
    }
    if (
        not values
        or measurement_start_ns is None
        or measurement_end_ns is None
        or impairment_start_ns is None
        or impairment_stop_ns is None
        or recovery_start_ns is None
        or not (
            measurement_start_ns
            < impairment_start_ns
            < impairment_stop_ns
            <= recovery_start_ns
            < measurement_end_ns
        )
    ):
        return defaults, ["dynamic_phase_window"]

    episode_end_ns = min(
        measurement_end_ns,
        recovery_start_ns + 60_000_000_000,
    )
    indexed = [
        (
            measurement_start_ns + index * DELIVERY_BIN_NS,
            measurement_start_ns + (index + 0.5) * DELIVERY_BIN_NS,
            value,
        )
        for index, value in enumerate(values)
    ]

    def phase(start_ns: int, end_ns: int) -> list[float]:
        return [
            value
            for _, center_ns, value in indexed
            if start_ns <= center_ns < end_ns
        ]

    pre_values = phase(measurement_start_ns, impairment_start_ns)
    impairment_values = phase(impairment_start_ns, impairment_stop_ns)
    episode_values = phase(impairment_start_ns, episode_end_ns)
    if len(pre_values) < 100 or not impairment_values:
        return defaults, ["dynamic_phase_coverage"]
    pre_median = statistics.median(pre_values)
    if pre_median <= 0:
        return defaults, ["dynamic_baseline"]

    recovery_values = [
        (start_ns, value)
        for start_ns, center_ns, value in indexed
        if recovery_start_ns <= center_ns < episode_end_ns
    ]
    first_delivery_ms = next(
        (
            max(0.0, (start_ns - recovery_start_ns) / 1_000_000)
            for start_ns, value in recovery_values
            if value > 0
        ),
        None,
    )
    recovery_90_ms: float | None = None
    for index in range(max(0, len(recovery_values) - 99)):
        first = [value for _, value in recovery_values[index : index + 50]]
        second = [value for _, value in recovery_values[index + 50 : index + 100]]
        if (
            statistics.fmean(first) >= pre_median * 0.90
            and statistics.fmean(second) >= pre_median * 0.90
            and sum(value <= 0 for value in first) / len(first) <= 0.05
            and sum(value <= 0 for value in second) / len(second) <= 0.05
        ):
            recovery_90_ms = max(
                0.0,
                (recovery_values[index][0] - recovery_start_ns) / 1_000_000,
            )
            break
    recovery_censored = recovery_90_ms is None
    episode_longest_stall_ms = longest_zero_run(episode_values) * 100
    episode_min_5s = rolling_minimum_mbps(episode_values, 50)
    below_half_pre = bool(
        episode_min_5s is not None
        and episode_min_5s <= pre_median / 1_000_000 * 0.50
    )
    outer_events = sum(
        event.get("layer") == "outer"
        and event.get("event") in {"retrans", "rto"}
        and impairment_start_ns <= as_int(event.get("timestamp_ns")) <= episode_end_ns
        for event in timed_events
    )
    mechanism_observed = tunnel == "tcp" and outer_events > 0
    user_visible = bool(
        episode_longest_stall_ms >= 1000
        or recovery_censored
        or (recovery_90_ms is not None and recovery_90_ms >= 5000)
    )

    def phase_mean_mbps(start_offset_s: float, end_offset_s: float) -> float | None:
        phase_values = phase(
            recovery_start_ns + round(start_offset_s * 1_000_000_000),
            min(
                episode_end_ns,
                recovery_start_ns + round(end_offset_s * 1_000_000_000),
            ),
        )
        return statistics.fmean(phase_values) / 1_000_000 if phase_values else None

    return {
        **defaults,
        "pre_median_mbps": pre_median / 1_000_000,
        "pre_mean_mbps": statistics.fmean(pre_values) / 1_000_000,
        "impairment_mean_mbps": statistics.fmean(impairment_values) / 1_000_000,
        "post_0_1s_mbps": phase_mean_mbps(0, 1),
        "post_1_5s_mbps": phase_mean_mbps(1, 5),
        "post_5_10s_mbps": phase_mean_mbps(5, 10),
        "post_10_30s_mbps": phase_mean_mbps(10, 30),
        "post_30_60s_mbps": phase_mean_mbps(30, 60),
        "episode_min_1s_mbps": rolling_minimum_mbps(episode_values, 10),
        "episode_min_5s_mbps": episode_min_5s,
        "episode_longest_stall_ms": episode_longest_stall_ms,
        "episode_stall_fraction_100ms": (
            sum(value <= 0 for value in episode_values) / len(episode_values)
        ),
        "bandwidth_deficit_mbit": sum(
            max(0.0, pre_median - value) * DELIVERY_BIN_NS / 1_000_000_000
            for value in episode_values
        )
        / 1_000_000,
        "first_delivery_after_recovery_ms": first_delivery_ms,
        "recovery_90_ms": recovery_90_ms,
        "recovery_90_right_censored": recovery_censored,
        "episode_outer_recovery_events": outer_events,
        "mechanism_observed": mechanism_observed,
        "user_visible_disruption": user_visible,
        "episode_below_half_pre": below_half_pre,
        "quasi_meltdown_episode": False,
    }, []


def stall_timeline(cell_dir: Path) -> dict[str, Any]:
    document = analyze_cell(cell_dir)
    axes = document.get("axes", {})
    delivery = interface_delivery_bins(
        cell_dir,
        str(axes.get("direction", "")),
        as_float(axes.get("warmup_s")),
        as_float(axes.get("duration_s")),
    )
    covered = as_int(delivery.get("covered_bins"))
    expected = as_int(delivery.get("expected_bins"))
    if expected <= 0 or covered != expected:
        raise ValueError(
            f"complete delivery coverage required: covered {covered} of {expected} bins"
        )

    values = delivery["bps"]
    measurement_start_ns = as_int(delivery.get("measurement_start_ns"))
    runs = zero_delivery_runs(values, measurement_start_ns)
    stall_bins = sum(value <= 0 for value in values)
    return {
        "cell_id": document.get("cell_id", cell_dir.name),
        "valid": document.get("valid"),
        "classification": document.get("classification"),
        "bin_ms": DELIVERY_BIN_NS // 1_000_000,
        "measurement_start_ns": measurement_start_ns,
        "measurement_end_ns": delivery.get("measurement_end_ns"),
        "covered_bins": covered,
        "expected_bins": expected,
        "stall_bins": stall_bins,
        "stall_fraction_100ms": stall_bins / len(values) if values else None,
        "longest_stall_ms": max(
            (as_int(run["duration_ms"]) for run in runs), default=0
        ),
        "stall_count": len(runs),
        "left_censored_stall_count": sum(
            bool(run["left_censored"]) for run in runs
        ),
        "right_censored_stall_count": sum(
            bool(run["right_censored"]) for run in runs
        ),
        "stalls": runs,
    }


def write_stall_csv(path: Path, report: dict[str, Any]) -> None:
    fieldnames = [
        "start_ns",
        "end_ns",
        "start_bin",
        "end_bin_exclusive",
        "start_s",
        "end_s",
        "duration_ms",
        "left_censored",
        "right_censored",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report["stalls"])


def parse_ping(path: Path) -> dict[str, int | float | None]:
    try:
        text = path.read_text()
    except OSError:
        return {
            "ping_transmitted": None,
            "ping_received": None,
            "ping_loss_pct": None,
            "ping_rtt_mean_ms": None,
        }
    packets = re.search(
        r"(\d+) packets transmitted,\s*(\d+) received",
        text,
    )
    loss = re.search(r"([\d.]+)% packet loss", text)
    rtt = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", text)
    return {
        "ping_transmitted": int(packets.group(1)) if packets else None,
        "ping_received": int(packets.group(2)) if packets else None,
        "ping_loss_pct": float(loss.group(1)) if loss else None,
        "ping_rtt_mean_ms": float(rtt.group(2)) if rtt else None,
    }


def baseline_preflight(
    path: Path,
) -> tuple[dict[str, int | float | bool | None], bool]:
    baseline = parse_ping(path)
    valid = (
        baseline["ping_transmitted"] == 10
        and baseline["ping_received"] == 10
        and baseline["ping_loss_pct"] == 0.0
        and baseline["ping_rtt_mean_ms"] is not None
        and baseline["ping_rtt_mean_ms"] <= BASELINE_PREFLIGHT_MAX_RTT_MS
    )
    return {
        **baseline,
        "baseline_preflight_valid": valid,
    }, valid


def impairment_ping_validation(
    cell_dir: Path, axes: dict[str, str]
) -> tuple[dict[str, int | float | bool | None], list[str]]:
    policy = axes.get("impairment_validation") or "strict"
    policy_valid = policy in IMPAIRMENT_VALIDATION_POLICIES
    tunnel = axes.get("tunnel")
    target_rtt = as_float(axes.get("rtt_ms"))
    ping = parse_ping(cell_dir / "preflight-ping.txt")
    measured_rtt = ping["ping_rtt_mean_ms"]
    transport_aware_tcp = (
        policy_valid and policy == "transport_aware" and tunnel == "tcp"
    )
    timed_impairment = axes.get("impairment_schedule") == "timed"
    rtt_valid = (
        measured_rtt is not None
        and measured_rtt >= max(0.0, target_rtt * 0.70)
        and (
            transport_aware_tcp and not timed_impairment
            or measured_rtt <= target_rtt * 1.35 + 5.0
        )
    )

    baseline, baseline_valid = (
        baseline_preflight(cell_dir / "preimpairment-ping.txt")
        if policy_valid and policy == "transport_aware"
        else (
            {
                "ping_transmitted": None,
                "ping_received": None,
                "ping_loss_pct": None,
                "ping_rtt_mean_ms": None,
                "baseline_preflight_valid": None,
            },
            None,
        )
    )

    issues: list[str] = []
    if not policy_valid:
        issues.append("impairment_validation_policy")
    if (
        ping["ping_loss_pct"] is None
        or ping["ping_loss_pct"] >= 100
        or (
            timed_impairment
            and (
                ping["ping_transmitted"] != 10
                or ping["ping_received"] != 10
                or ping["ping_loss_pct"] != 0.0
            )
        )
    ):
        issues.append("tunnel_preflight")
    if baseline_valid is False:
        issues.append("baseline_preflight")
    if not rtt_valid:
        issues.append("rtt_not_achieved")
    return {
        **ping,
        "impaired_ping_rtt_valid": rtt_valid,
        "baseline_ping_transmitted": baseline["ping_transmitted"],
        "baseline_ping_received": baseline["ping_received"],
        "baseline_ping_loss_pct": baseline["ping_loss_pct"],
        "baseline_ping_rtt_mean_ms": baseline["ping_rtt_mean_ms"],
        "baseline_preflight_valid": baseline_valid,
    }, issues


def tcp_carrier_stability(
    path: Path, start_ns: int | None = None, end_ns: int | None = None
) -> dict[str, Any]:
    samples: list[tuple[int, frozenset[str]]] = []
    current: set[str] | None = None
    current_timestamp: int | None = None
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        lines = []

    for line in lines:
        if line.startswith("--- "):
            if current is not None and current_timestamp is not None:
                samples.append((current_timestamp, frozenset(current)))
            try:
                current_timestamp = round(float(line.split()[1]) * 1_000_000_000)
            except (IndexError, ValueError):
                current_timestamp = None
            current = set()
            continue
        if current is None or line[:1].isspace():
            continue
        fields = line.split()
        if len(fields) < 5 or fields[0] != "ESTAB":
            continue
        local, remote = fields[3], fields[4]
        if local.rsplit(":", 1)[-1] == "51821" or remote.rsplit(":", 1)[-1] == "51821":
            current.add(f"{local}>{remote}")
    if current is not None and current_timestamp is not None:
        samples.append((current_timestamp, frozenset(current)))

    timestamps = [sample[0] for sample in samples]
    carriers = [sample[1] for sample in samples]
    counts = [len(sample) for sample in carriers]
    changes = sum(left != right for left, right in zip(carriers, carriers[1:]))
    sampler_complete = load_env(path.with_name("ss-series.status")).get(
        "complete"
    ) == "yes"
    if start_ns is not None and end_ns is not None and end_ns > start_ns:
        expected_samples = max(
            2, math.floor((end_ns - start_ns) / 200_000_000 * 0.80)
        )
        coverage_complete = (
            sampler_complete
            and len(samples) >= expected_samples
            and timestamps[0] <= start_ns + 500_000_000
            and timestamps[-1] >= end_ns - 500_000_000
        )
    else:
        expected_samples = 2
        coverage_complete = sampler_complete and len(samples) >= expected_samples
    return {
        "samples": len(samples),
        "expected_samples": expected_samples,
        "coverage_complete": coverage_complete,
        "min_count": min(counts) if counts else None,
        "max_count": max(counts) if counts else None,
        "tuple_changes": changes,
        "stable_dual_carrier": coverage_complete
        and all(count == 2 for count in counts)
        and changes == 0,
    }


def clock_boot_epoch_ns(endpoint: Path) -> int | None:
    try:
        values = load_env(endpoint / "clock.txt")
        epoch_ns = int(values["EpochNs"])
        uptime_ns = round(float(values["UptimeSeconds"]) * 1_000_000_000)
    except (KeyError, OSError, TypeError, ValueError):
        return None
    return epoch_ns - uptime_ns


def timed_tcp_events(endpoint: Path) -> list[dict[str, Any]]:
    boot_epoch_ns = clock_boot_epoch_ns(endpoint)
    if boot_epoch_ns is None:
        return []
    events: list[dict[str, Any]] = []
    try:
        lines = (endpoint / "tcp-events.csv").read_text(
            encoding="utf-8-sig"
        ).splitlines()
    except OSError:
        return []
    for line in lines:
        parts = line.split(",")
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        if len(parts) > 2 and parts[1:3] == ["capture", "meta"]:
            continue
        try:
            event = {
                "timestamp_ns": boot_epoch_ns + int(parts[0]),
                "event": parts[1],
                "layer": parts[2],
                "sport": int(parts[3]),
                "dport": int(parts[4]),
                "endpoint": endpoint.name,
                "value1": int(parts[5]) if len(parts) > 5 else 0,
                "value2": int(parts[6]) if len(parts) > 6 else 0,
                "value3": int(parts[7]) if len(parts) > 7 else 0,
            }
        except ValueError:
            continue
        events.append(event)
    return events


def tcp_event_telemetry_issues(
    endpoint: Path,
    require_capture_anchor: bool = False,
) -> list[str]:
    issues: list[str] = []
    if not (endpoint / "done").is_file():
        issues.append("sampler_not_done")

    status = load_env(endpoint / "tcp-events.status")
    if status.get("complete") != "yes":
        issues.append("trace_incomplete")

    try:
        lines = (endpoint / "tcp-events.csv").read_text(
            encoding="utf-8-sig"
        ).splitlines()
    except OSError:
        return issues + ["events_missing"]
    if not lines or lines[0] != TCP_EVENTS_HEADER:
        return issues + ["events_header"]

    summaries: dict[tuple[str, str], int] = {}
    per_cpu_summaries: dict[tuple[str, str], int] = {}
    per_cpu_marker_count = 0
    cpu_sequence_summaries: dict[tuple[str, str, int], int] = {}
    cpu_sequence_rows: dict[tuple[str, str, int], list[tuple[int, int]]] = {}
    cpu_sequence_marker_count = 0
    event_counts: Counter[tuple[str, str]] = Counter()
    nonzero_event_values = False
    capture_markers: list[tuple[int, int, int]] = []
    event_timestamps: list[int] = []
    for line_number, line in enumerate(lines[1:], start=2):
        if not line:
            continue
        per_cpu_match = PER_CPU_SUMMARY_LINE.fullmatch(line)
        if per_cpu_match:
            numeric_key = (int(per_cpu_match[1]), int(per_cpu_match[2]))
            key = PER_CPU_SUMMARY_KEYS.get(numeric_key)
            if key is None or key in per_cpu_summaries:
                issues.append(f"events_malformed_line_{line_number}")
            else:
                per_cpu_summaries[key] = int(per_cpu_match[3])
            continue
        if line.startswith("@event_counts["):
            issues.append(f"events_malformed_line_{line_number}")
            continue
        cpu_sequence_match = CPU_SEQUENCE_SUMMARY_LINE.fullmatch(line)
        if cpu_sequence_match:
            numeric_key = (
                int(cpu_sequence_match[1]),
                int(cpu_sequence_match[2]),
            )
            event_key = PER_CPU_SUMMARY_KEYS.get(numeric_key)
            key = (
                event_key[0],
                event_key[1],
                int(cpu_sequence_match[3]),
            ) if event_key is not None else None
            sequence = int(cpu_sequence_match[4])
            if (
                key is None
                or key in cpu_sequence_summaries
                or sequence <= 0
            ):
                issues.append(f"events_malformed_line_{line_number}")
            else:
                cpu_sequence_summaries[key] = sequence
            continue
        if line.startswith("@event_sequences["):
            issues.append(f"events_malformed_line_{line_number}")
            continue
        parts = line.split(",")
        if len(parts) != 8:
            issues.append(f"events_malformed_line_{line_number}")
            continue
        if parts[0] == "summary":
            if parts[1:] == [
                "format",
                "per_cpu_count",
                "1",
                "0",
                "0",
                "0",
                "0",
            ]:
                per_cpu_marker_count += 1
            elif parts[1:] == [
                "format",
                "cpu_sequence",
                "1",
                "0",
                "0",
                "0",
                "0",
            ]:
                cpu_sequence_marker_count += 1
            elif (
                parts[1] not in {"rto", "retrans"}
                or parts[2] not in {"inner", "outer", "competitor"}
                or not all(value.isdigit() for value in parts[3:])
            ):
                issues.append(f"events_malformed_line_{line_number}")
            elif (parts[1], parts[2]) in summaries:
                issues.append(f"events_duplicate_summary_{line_number}")
            else:
                summaries[(parts[1], parts[2])] = int(parts[3])
            continue
        if parts[1:3] == ["capture", "meta"]:
            if (
                not parts[0].isdigit()
                or not all(value.isdigit() for value in parts[3:])
                or parts[4] != "0"
                or parts[6:] != ["0", "0"]
            ):
                issues.append(f"events_malformed_line_{line_number}")
            else:
                capture_markers.append(
                    (int(parts[0]), int(parts[3]), int(parts[5]))
                )
            continue
        if (
            not parts[0].isdigit()
            or parts[1] not in {"rto", "retrans", "cwnd"}
            or parts[2] not in {"inner", "outer", "competitor"}
            or not all(value.isdigit() for value in parts[3:])
        ):
            issues.append(f"events_malformed_line_{line_number}")
        elif parts[1] in {"rto", "retrans"}:
            event_key = (parts[1], parts[2])
            event_counts[event_key] += 1
            nonzero_event_values = (
                nonzero_event_values or parts[5:] != ["0", "0", "0"]
            )
            cpu_sequence_rows.setdefault(
                (event_key[0], event_key[1], int(parts[5])),
                [],
            ).append((int(parts[6]), int(parts[7])))
            event_timestamps.append(int(parts[0]))
        else:
            event_timestamps.append(int(parts[0]))

    if cpu_sequence_marker_count or cpu_sequence_summaries:
        if (
            cpu_sequence_marker_count != 1
            or per_cpu_marker_count
            or per_cpu_summaries
            or summaries
        ):
            issues.append("events_summary_format")
        elif set(cpu_sequence_rows) != set(cpu_sequence_summaries):
            issues.append("events_sequence_mismatch")
        elif any(
            len(rows) != cpu_sequence_summaries[key]
            or any(
                sequence != expected or reserved != 0
                for expected, (sequence, reserved) in enumerate(rows, start=1)
            )
            for key, rows in cpu_sequence_rows.items()
        ):
            issues.append("events_sequence_mismatch")
    elif per_cpu_marker_count or per_cpu_summaries:
        if per_cpu_marker_count != 1 or summaries or nonzero_event_values:
            issues.append("events_summary_format")
        elif any(
            per_cpu_summaries.get(key, 0) != event_counts[key]
            for key in TCP_EVENT_SUMMARIES
        ):
            issues.append("events_summary_mismatch")
    else:
        if nonzero_event_values:
            issues.append("events_summary_format")
        elif set(summaries) != TCP_EVENT_SUMMARIES:
            issues.append("events_summary")
        elif any(
            summaries[key] > event_counts[key]
            or event_counts[key] - summaries[key] > MAX_TRACE_SUMMARY_LAG
            for key in TCP_EVENT_SUMMARIES
        ):
            issues.append("events_summary_mismatch")
    anchor_mode = status.get("cutoff_anchor")
    if anchor_mode == "attached_command":
        if len(capture_markers) != 1:
            issues.append("events_capture_anchor")
        else:
            capture_start_ns, capture_duration_s, capture_until_ns = capture_markers[0]
            if (
                status.get("capture_duration_s") != str(capture_duration_s)
                or status.get("capture_marker_count") != "1"
                or status.get("quiescence_s") != "1"
                or capture_duration_s <= 0
                or capture_until_ns - capture_start_ns
                != capture_duration_s * 1_000_000_000
            ):
                issues.append("events_capture_anchor")
            if any(
                timestamp < capture_start_ns or timestamp > capture_until_ns
                for timestamp in event_timestamps
            ):
                issues.append("events_capture_window")
    elif require_capture_anchor or anchor_mode is not None or capture_markers:
        issues.append("events_capture_anchor")
    if clock_boot_epoch_ns(endpoint) is None:
        issues.append("clock_anchor")
    return issues


def iperf_data_flow_ports(doc: dict[str, Any]) -> set[tuple[int, int]]:
    ports: set[tuple[int, int]] = set()
    for connection in doc.get("start", {}).get("connected", []):
        local_port = as_int(connection.get("local_port"))
        remote_port = as_int(connection.get("remote_port"))
        if local_port and remote_port:
            ports.add(tuple(sorted((local_port, remote_port))))
    return ports


def scored_tcp_events(
    cell_dir: Path,
    start_ns: int | None,
    end_ns: int | None,
    data_flow_ports: set[tuple[int, int]],
) -> list[dict[str, Any]]:
    if start_ns is None or end_ns is None:
        return []
    events: list[dict[str, Any]] = []
    for endpoint_name in ("client", "server"):
        for event in timed_tcp_events(cell_dir / endpoint_name):
            if not start_ns <= event["timestamp_ns"] <= end_ns:
                continue
            if (
                event["layer"] == "inner"
                and data_flow_ports
                and tuple(sorted((event["sport"], event["dport"])))
                not in data_flow_ports
            ):
                continue
            events.append(event)
    return sorted(events, key=lambda item: item["timestamp_ns"])


def coupled_responses(
    trigger_times: list[int], response_times: list[int], window_ns: int = 1_000_000_000
) -> dict[str, float | int | None]:
    if not response_times:
        return {"responses": 0, "coupled": 0, "fraction": None, "median_lag_ms": None}
    lags: list[int] = []
    for response in response_times:
        index = bisect.bisect_right(trigger_times, response) - 1
        if index >= 0:
            lag = response - trigger_times[index]
            if lag <= window_ns:
                lags.append(lag)
    return {
        "responses": len(response_times),
        "coupled": len(lags),
        "fraction": len(lags) / len(response_times),
        "median_lag_ms": statistics.median(lags) / 1_000_000 if lags else None,
    }


def correlate_tcp_layers(events: list[dict[str, Any]]) -> dict[str, Any]:
    outer_times = sorted(
        event["timestamp_ns"]
        for event in events
        if event["layer"] == "outer" and event["event"] in {"retrans", "rto"}
    )
    inner_rto_times = sorted(
        event["timestamp_ns"]
        for event in events
        if event["layer"] == "inner" and event["event"] == "rto"
    )

    previous: dict[tuple[str, int, int], dict[str, Any]] = {}
    cwnd_drop_times: list[int] = []
    for event in events:
        if event["layer"] != "inner" or event["event"] != "cwnd":
            continue
        key = (event["endpoint"], event["sport"], event["dport"])
        prior = previous.get(key)
        if (
            prior
            and prior["value1"] >= 4
            and event["value1"] <= prior["value1"] * 0.70
        ):
            cwnd_drop_times.append(event["timestamp_ns"])
        previous[key] = event

    return {
        "outer_recovery_events": len(outer_times),
        "inner_rto_coupling": coupled_responses(outer_times, inner_rto_times),
        "inner_cwnd_coupling": coupled_responses(outer_times, cwnd_drop_times),
    }


def find_qdisc_in(
    qdiscs: Any, kind: str, handle_prefix: str = "20:"
) -> dict[str, Any] | None:
    if not isinstance(qdiscs, list):
        return None
    for qdisc in qdiscs:
        if qdisc.get("kind") == kind and str(qdisc.get("handle", "")).startswith(
            handle_prefix
        ):
            return qdisc
    return None


def find_qdisc(
    path: Path, kind: str, handle_prefix: str = "20:"
) -> dict[str, Any] | None:
    return find_qdisc_in(load_json(path, []), kind, handle_prefix)


def qdisc_metric(qdisc: dict[str, Any] | None, key: str) -> int | None:
    if not qdisc:
        return None
    value: Any = None
    if key in qdisc:
        value = qdisc.get(key)
    else:
        stats = qdisc.get("stats") or qdisc.get("stats2") or {}
        if isinstance(stats, dict):
            if key in stats:
                value = stats.get(key)
            else:
                basic = stats.get("basic") or {}
                queue = stats.get("queue") or {}
                if key in basic:
                    value = basic.get(key)
                elif key in queue:
                    value = queue.get(key)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def qdisc_snapshot_delta(
    endpoint: Path,
    stem: str,
    kind: str,
    key: str,
    handle_prefix: str,
) -> int | None:
    before = find_qdisc(
        endpoint / f"{stem}-pre.json",
        kind,
        handle_prefix=handle_prefix,
    )
    after = find_qdisc(
        endpoint / f"{stem}-post.json",
        kind,
        handle_prefix=handle_prefix,
    )
    if before is None or after is None:
        return None
    before_value = qdisc_metric(before, key)
    after_value = qdisc_metric(after, key)
    if before_value is None or after_value is None or after_value < before_value:
        return None
    return after_value - before_value


def expected_netem_loss_fraction(axes: dict[str, str]) -> float | None:
    model = axes.get("loss_model", "none")
    if model == "none":
        return 0.0
    if model == "random":
        expected = as_float(axes.get("loss_pct")) / 100.0
        return expected if expected > 0 else None
    if model != "gemodel":
        return None

    p = as_float(axes.get("burst_p")) / 100.0
    r = as_float(axes.get("burst_r")) / 100.0
    bad_loss = as_float(axes.get("burst_h")) / 100.0
    good_loss = as_float(axes.get("burst_k")) / 100.0
    if p + r <= 0:
        return None
    bad_state_fraction = p / (p + r)
    return bad_state_fraction * bad_loss + (1.0 - bad_state_fraction) * good_loss


def netem_counter_metrics(endpoint: Path) -> dict[str, int | float | None]:
    packets = qdisc_snapshot_delta(
        endpoint, "ifb-qdisc", "netem", "packets", "40:"
    )
    drops = qdisc_snapshot_delta(
        endpoint, "ifb-qdisc", "netem", "drops", "40:"
    )
    total = (
        packets + drops
        if packets is not None and drops is not None
        else None
    )
    return {
        "packets": packets,
        "drops": drops,
        "loss_fraction": (
            drops / total
            if drops is not None and total is not None and total > 0
            else None
        ),
    }


def netem_loss_band_required(axes: dict[str, str]) -> bool:
    return (
        axes.get("loss_model", "none") != "none"
        and not (
            axes.get("impairment_validation") == "transport_aware"
            and axes.get("tunnel") == "tcp"
        )
    )


def netem_counter_issues(endpoint: Path, axes: dict[str, str]) -> list[str]:
    if axes.get("loss_model", "none") == "none":
        return []
    metrics = netem_counter_metrics(endpoint)
    packets = metrics["packets"]
    drops = metrics["drops"]
    loss_fraction = metrics["loss_fraction"]
    if packets is None or drops is None:
        return ["netem_counter_window"]
    if packets + drops <= 0:
        return ["netem_path_unused"]
    if drops <= 0 or loss_fraction is None:
        return ["netem_loss_not_realized"]
    if not netem_loss_band_required(axes):
        return []

    expected = expected_netem_loss_fraction(axes)
    if (
        expected is None
        or loss_fraction < expected * 0.5
        or loss_fraction > min(1.0, expected * 2.0)
    ):
        return ["netem_loss_rate"]
    return []


def parse_timestamp_ns(value: str) -> int | None:
    try:
        return round(
            datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            * 1_000_000_000
        )
    except ValueError:
        return None


def qdisc_window_values(
    endpoint: Path,
    kind: str,
    key: str,
    start_ns: int | None,
    end_ns: int | None,
    handle_prefix: str = "20:",
    series_name: str = "qdisc-series.jsonl",
) -> list[int] | None:
    if start_ns is None or end_ns is None:
        return None
    samples: list[tuple[int, int]] = []
    try:
        lines = (endpoint / series_name).read_text(
            encoding="utf-8-sig"
        ).splitlines()
    except OSError:
        return None
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        timestamp_ns = parse_timestamp_ns(str(row.get("timestamp", "")))
        qdisc = find_qdisc_in(row.get("qdisc"), kind, handle_prefix=handle_prefix)
        metric = qdisc_metric(qdisc, key)
        if timestamp_ns is not None and metric is not None:
            samples.append((timestamp_ns, metric))
    if not samples:
        return None
    timestamps = [sample[0] for sample in samples]
    start_index = bisect.bisect_right(timestamps, start_ns) - 1
    end_index = bisect.bisect_right(timestamps, end_ns) - 1
    if start_index < 0 or end_index < start_index:
        return None
    if (
        start_ns - timestamps[start_index] > 500_000_000
        or end_ns - timestamps[end_index] > 500_000_000
    ):
        return None
    return [value for _, value in samples[start_index : end_index + 1]]


def qdisc_window_delta(
    endpoint: Path,
    kind: str,
    key: str,
    start_ns: int | None,
    end_ns: int | None,
    handle_prefix: str = "20:",
    series_name: str = "qdisc-series.jsonl",
) -> int | None:
    values = qdisc_window_values(
        endpoint,
        kind,
        key,
        start_ns,
        end_ns,
        handle_prefix,
        series_name,
    )
    if values is None:
        return None
    return max(0, values[-1] - values[0])


def qdisc_window_peak(
    endpoint: Path,
    kind: str,
    key: str,
    start_ns: int | None,
    end_ns: int | None,
    handle_prefix: str = "20:",
    series_name: str = "qdisc-series.jsonl",
) -> int | None:
    values = qdisc_window_values(
        endpoint,
        kind,
        key,
        start_ns,
        end_ns,
        handle_prefix,
        series_name,
    )
    return max(values) if values else None


def load_jsonl_objects(path: Path) -> tuple[list[dict[str, Any]], bool]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return [], False
    rows: list[dict[str, Any]] = []
    valid = True
    for line in lines:
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            valid = False
            continue
        if not isinstance(row, dict):
            valid = False
            continue
        rows.append(row)
    return rows, valid


def qdisc_series_rows(
    endpoint: Path,
    series_name: str,
    kind: str,
    handle_prefix: str,
) -> tuple[list[tuple[int, int, dict[str, Any]]], bool]:
    rows, valid = load_jsonl_objects(endpoint / series_name)
    samples: list[tuple[int, int, dict[str, Any]]] = []
    for row in rows:
        timestamp_ns = parse_timestamp_ns(str(row.get("timestamp", "")))
        query_start_ns = as_int(row.get("query_start_ns"))
        query_end_ns = as_int(row.get("query_end_ns"))
        qdiscs = row.get("qdisc")
        qdisc = find_qdisc_in(qdiscs, kind, handle_prefix)
        if (
            timestamp_ns is None
            or query_start_ns <= 0
            or query_end_ns < query_start_ns
            or not isinstance(qdiscs, list)
            or len(qdiscs) != 1
            or qdisc is None
        ):
            valid = False
            continue
        samples.append((query_start_ns, query_end_ns, qdisc))
    samples.sort(key=lambda item: item[0])
    return samples, valid


def qdisc_phase_coverage_valid(
    samples: list[tuple[int, int, dict[str, Any]]],
    start_ns: int,
    end_ns: int,
) -> bool:
    return bool(
        samples
        and samples[0][0] - start_ns <= 100_000_000
        and end_ns - samples[-1][1] <= 100_000_000
        and all(
            right[0] - left[1] <= 250_000_000
            for left, right in zip(samples, samples[1:])
        )
    )


def counter_metrics_from_values(
    packet_values: list[int | None] | None,
    drop_values: list[int | None] | None,
) -> dict[str, int | float | None]:
    packets = (
        packet_values[-1] - packet_values[0]
        if packet_values
        and len(packet_values) >= 2
        and all(isinstance(value, int) for value in packet_values)
        and all(left <= right for left, right in zip(packet_values, packet_values[1:]))
        else None
    )
    drops = (
        drop_values[-1] - drop_values[0]
        if drop_values
        and len(drop_values) >= 2
        and all(isinstance(value, int) for value in drop_values)
        and all(left <= right for left, right in zip(drop_values, drop_values[1:]))
        else None
    )
    total = (
        packets + drops
        if packets is not None and drops is not None
        else None
    )
    return {
        "packets": packets,
        "drops": drops,
        "loss_fraction": (
            drops / total
            if drops is not None and total is not None and total > 0
            else None
        ),
    }


def timed_counter_issues(
    metrics: dict[str, int | float | None],
    axes: dict[str, str],
) -> list[str]:
    packets = metrics["packets"]
    drops = metrics["drops"]
    loss_fraction = metrics["loss_fraction"]
    if not isinstance(packets, int) or not isinstance(drops, int):
        return ["impairment_counter_window"]
    if packets + drops <= 0:
        return ["netem_path_unused"]
    if drops <= 0 or not isinstance(loss_fraction, float):
        return ["netem_loss_not_realized"]
    if not netem_loss_band_required(axes):
        return []
    expected = expected_netem_loss_fraction(axes)
    if (
        expected is None
        or loss_fraction < expected * 0.5
        or loss_fraction > min(1.0, expected * 2.0)
    ):
        return ["netem_loss_rate"]
    return []


def timed_impairment_evidence(
    cell_dir: Path,
    axes: dict[str, str],
    measurement_start_ns: int | None,
    measurement_end_ns: int | None,
) -> tuple[
    dict[str, int | float | bool | None],
    dict[str, dict[str, int | float | None]],
    list[str],
]:
    metrics: dict[str, int | float | bool | None] = {
        "timed_impairment_valid": False,
        "impairment_start_ns": None,
        "impairment_stop_ns": None,
        "recovery_start_ns": None,
        "impairment_start_skew_ms": None,
        "impairment_stop_skew_ms": None,
        "transition_clock_error_bound_ms": None,
        "actual_loss_epoch_ms": None,
        "actual_loss_epoch_offset_s": None,
        "recovery_observation_s": None,
    }
    endpoint_metrics: dict[str, dict[str, int | float | None]] = {}
    issues: list[str] = []
    scheduled_start_ns = as_int(axes.get("scheduled_loss_start_ns"))
    scheduled_stop_ns = as_int(axes.get("scheduled_loss_stop_ns"))
    expected_duration_ns = as_int(axes.get("loss_epoch_ms")) * 1_000_000
    if (
        scheduled_start_ns <= 0
        or scheduled_stop_ns - scheduled_start_ns != expected_duration_ns
    ):
        return metrics, endpoint_metrics, ["impairment_transition_schedule"]

    endpoint_events: dict[str, dict[str, dict[str, Any]]] = {}
    for endpoint_name in ("client", "server"):
        endpoint = cell_dir / endpoint_name
        rows, rows_valid = load_jsonl_objects(endpoint / "impairment-events.jsonl")
        if (
            not rows_valid
            or not (endpoint / "impairment-ready").is_file()
            or not (endpoint / "impairment-done").is_file()
            or [row.get("event") for row in rows] != ["loss_start", "loss_stop"]
        ):
            issues.append("impairment_transition_evidence")
            continue
        events = {str(row["event"]): row for row in rows}
        endpoint_events[endpoint_name] = events
        for event_name, expected_requested_ns, expected_model in (
            ("loss_start", scheduled_start_ns, axes.get("loss_model")),
            ("loss_stop", scheduled_stop_ns, "none"),
        ):
            event = events[event_name]
            requested_ns = as_int(event.get("requested_ns"))
            command_start_ns = as_int(event.get("command_start_ns"))
            command_end_ns = as_int(event.get("command_end_ns"))
            change_start_ns = as_int(event.get("change_start_ns"))
            change_end_ns = as_int(event.get("change_end_ns"))
            clock_error_bound_ns = as_int(event.get("clock_error_bound_ns"))
            if (
                event.get("success") is not True
                or event.get("loss_model") != expected_model
                or requested_ns != expected_requested_ns
                or not (
                    requested_ns
                    <= command_start_ns
                    <= change_start_ns
                    <= change_end_ns
                    <= command_end_ns
                )
                or as_int(event.get("applied_ns")) != change_end_ns
                or change_end_ns - requested_ns > 100_000_000
                or not 0 <= clock_error_bound_ns <= 5_000_000
            ):
                issues.append("impairment_transition_schedule")
            event_qdiscs = event.get("qdisc")
            netem = find_qdisc_in(event_qdiscs, "netem", "40:")
            expected_axes = (
                axes if event_name == "loss_start" else {**axes, "loss_model": "none"}
            )
            if (
                not isinstance(event_qdiscs, list)
                or len(event_qdiscs) != 1
                or netem_base_configuration_issues(netem, expected_axes)
                or netem_loss_configuration_issues(netem, expected_axes)
            ):
                issues.append("impairment_transition_configuration")

    if len(endpoint_events) != 2:
        return metrics, endpoint_metrics, issues

    start_intervals = [
        (
            as_int(endpoint_events[name]["loss_start"].get("change_start_ns")),
            as_int(endpoint_events[name]["loss_start"].get("change_end_ns")),
        )
        for name in ("client", "server")
    ]
    stop_intervals = [
        (
            as_int(endpoint_events[name]["loss_stop"].get("change_start_ns")),
            as_int(endpoint_events[name]["loss_stop"].get("change_end_ns")),
        )
        for name in ("client", "server")
    ]
    start_clock_error_bound_ns = sum(
        as_int(
            endpoint_events[name]["loss_start"].get("clock_error_bound_ns")
        )
        for name in ("client", "server")
    )
    stop_clock_error_bound_ns = sum(
        as_int(
            endpoint_events[name]["loss_stop"].get("clock_error_bound_ns")
        )
        for name in ("client", "server")
    )
    start_skew_bound_ns = (
        max(interval[1] for interval in start_intervals)
        - min(interval[0] for interval in start_intervals)
        + start_clock_error_bound_ns
    )
    stop_skew_bound_ns = (
        max(interval[1] for interval in stop_intervals)
        - min(interval[0] for interval in stop_intervals)
        + stop_clock_error_bound_ns
    )
    impairment_start_ns = max(interval[1] for interval in start_intervals)
    impairment_stop_ns = min(interval[0] for interval in stop_intervals)
    recovery_start_ns = max(interval[1] for interval in stop_intervals)
    actual_duration_ns = impairment_stop_ns - impairment_start_ns
    metrics.update(
        {
            "impairment_start_ns": impairment_start_ns,
            "impairment_stop_ns": impairment_stop_ns,
            "recovery_start_ns": recovery_start_ns,
            "impairment_start_skew_ms": start_skew_bound_ns / 1_000_000,
            "impairment_stop_skew_ms": stop_skew_bound_ns / 1_000_000,
            "transition_clock_error_bound_ms": (
                max(
                    start_clock_error_bound_ns,
                    stop_clock_error_bound_ns,
                )
                / 1_000_000
            ),
            "actual_loss_epoch_ms": actual_duration_ns / 1_000_000,
            "actual_loss_epoch_offset_s": (
                (impairment_start_ns - measurement_start_ns) / 1_000_000_000
                if measurement_start_ns is not None
                else None
            ),
            "recovery_observation_s": (
                (measurement_end_ns - recovery_start_ns) / 1_000_000_000
                if measurement_end_ns is not None
                else None
            ),
        }
    )
    if (
        start_skew_bound_ns > 20_000_000
        or stop_skew_bound_ns > 20_000_000
    ):
        issues.append("impairment_transition_skew")
    if abs(actual_duration_ns - expected_duration_ns) > 50_000_000:
        issues.append("impairment_transition_window")
    expected_offset_ns = round(as_float(axes.get("loss_epoch_start_s")) * 1_000_000_000)
    if (
        measurement_start_ns is None
        or measurement_end_ns is None
        or abs(
            impairment_start_ns - measurement_start_ns - expected_offset_ns
        )
        > 100_000_000
        or measurement_end_ns - recovery_start_ns < 60_000_000_000
    ):
        issues.append("impairment_transition_window")

    for endpoint_name in ("client", "server"):
        endpoint = cell_dir / endpoint_name
        events = endpoint_events[endpoint_name]
        endpoint_start_ns = as_int(events["loss_start"].get("change_start_ns"))
        endpoint_active_ns = as_int(events["loss_start"].get("change_end_ns"))
        endpoint_stop_ns = as_int(events["loss_stop"].get("change_start_ns"))
        endpoint_clear_ns = as_int(events["loss_stop"].get("change_end_ns"))
        samples, samples_valid = qdisc_series_rows(
            endpoint,
            "ifb-qdisc-series.jsonl",
            "netem",
            "40:",
        )
        baseline_samples = [
            (query_start_ns, query_end_ns, qdisc)
            for query_start_ns, query_end_ns, qdisc in samples
            if measurement_start_ns is not None
            and measurement_start_ns <= query_start_ns
            and query_end_ns <= endpoint_start_ns
        ]
        active_samples = [
            (query_start_ns, query_end_ns, qdisc)
            for query_start_ns, query_end_ns, qdisc in samples
            if endpoint_active_ns <= query_start_ns
            and query_end_ns <= endpoint_stop_ns
        ]
        recovery_samples = [
            (query_start_ns, query_end_ns, qdisc)
            for query_start_ns, query_end_ns, qdisc in samples
            if measurement_end_ns is not None
            and endpoint_clear_ns <= query_start_ns
            and query_end_ns <= measurement_end_ns
        ]
        clean_axes = {**axes, "loss_model": "none"}
        if (
            not samples_valid
            or not qdisc_phase_coverage_valid(
                baseline_samples,
                as_int(measurement_start_ns),
                endpoint_start_ns,
            )
            or not qdisc_phase_coverage_valid(
                active_samples,
                endpoint_active_ns,
                endpoint_stop_ns,
            )
            or not qdisc_phase_coverage_valid(
                recovery_samples,
                endpoint_clear_ns,
                as_int(measurement_end_ns),
            )
            or any(
                netem_base_configuration_issues(qdisc, clean_axes)
                or netem_loss_configuration_issues(qdisc, clean_axes)
                for _, _, qdisc in baseline_samples
            )
            or any(
                netem_base_configuration_issues(qdisc, axes)
                or netem_loss_configuration_issues(qdisc, axes)
                for _, _, qdisc in active_samples
            )
            or any(
                netem_base_configuration_issues(qdisc, clean_axes)
                or netem_loss_configuration_issues(qdisc, clean_axes)
                for _, _, qdisc in recovery_samples
            )
        ):
            issues.append("impairment_transition_configuration")
        start_event_netem = find_qdisc_in(
            events["loss_start"].get("qdisc"),
            "netem",
            "40:",
        )
        stop_event_netem = find_qdisc_in(
            events["loss_stop"].get("qdisc"),
            "netem",
            "40:",
        )
        packet_values = [
            qdisc_metric(start_event_netem, "packets"),
            qdisc_metric(stop_event_netem, "packets"),
        ]
        drop_values = [
            qdisc_metric(start_event_netem, "drops"),
            qdisc_metric(stop_event_netem, "drops"),
        ]
        counters = counter_metrics_from_values(packet_values, drop_values)
        endpoint_metrics[endpoint_name] = counters
        issues.extend(timed_counter_issues(counters, axes))
        clear_event_netem = find_qdisc_in(
            events["loss_stop"].get("qdisc"),
            "netem",
            "40:",
        )
        clean_drop_phases = (
            [
                qdisc_metric(qdisc, "drops")
                for _, _, qdisc in baseline_samples
            ],
            [
                qdisc_metric(clear_event_netem, "drops"),
                *[
                    qdisc_metric(qdisc, "drops")
                    for _, _, qdisc in recovery_samples
                ],
            ],
        )
        for clean_drop_values in clean_drop_phases:
            if (
                len(clean_drop_values) < 2
                or any(value is None for value in clean_drop_values)
                or any(
                    left > right
                    for left, right in zip(
                        clean_drop_values,
                        clean_drop_values[1:],
                    )
                    if left is not None and right is not None
                )
                or clean_drop_values[-1] != clean_drop_values[0]
            ):
                issues.append("impairment_clean_window")

    metrics["timed_impairment_valid"] = not issues
    return metrics, endpoint_metrics, issues


def htb_rate_mbps(path: Path) -> float | None:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return None

    classes = load_json(path, [])
    if isinstance(classes, list):
        for item in classes:
            if item.get("kind") != "htb" or item.get("handle") != "1:10":
                continue
            rate = (item.get("options") or {}).get("rate")
            if isinstance(rate, (int, float)) and not isinstance(rate, bool):
                return float(rate) * 8.0 / 1_000_000.0
            if isinstance(rate, str):
                match = re.fullmatch(
                    r"\s*([\d.]+)\s*([KMGT]?)bit\s*", rate, re.IGNORECASE
                )
                if match:
                    scale = {
                        "": 0.000001,
                        "K": 0.001,
                        "M": 1.0,
                        "G": 1000.0,
                        "T": 1_000_000.0,
                    }[match.group(2).upper()]
                    return float(match.group(1)) * scale

    match = re.search(
        r"class htb 1:10\b[^\n]*\brate ([\d.]+)([KMGT]?)bit\b",
        text,
        re.IGNORECASE,
    )
    if not match:
        return None
    scale = {
        "": 0.000001,
        "K": 0.001,
        "M": 1.0,
        "G": 1000.0,
        "T": 1_000_000.0,
    }[match.group(2).upper()]
    return float(match.group(1)) * scale


def matching_filter_count(path: Path, port: int, ingress: bool) -> int:
    filters = load_json(path, [])
    if not isinstance(filters, list):
        return 0
    count = 0
    for item in filters:
        options = item.get("options") or {}
        keys = options.get("keys") or {}
        if keys.get("ip_proto") not in {"tcp", "udp"}:
            continue
        if port not in {as_int(keys.get("src_port")), as_int(keys.get("dst_port"))}:
            continue
        if not ingress and options.get("classid") != "1:10":
            continue
        if ingress and not any(
            action.get("kind") == "mirred"
            and action.get("mirred_action") == "redirect"
            and action.get("to_dev") == "ifb-wgmt"
            for action in options.get("actions", [])
        ):
            continue
        count += 1
    return count


def netem_loss_configuration_issues(
    netem: dict[str, Any] | None, axes: dict[str, str]
) -> list[str]:
    options = ((netem or {}).get("options") or {})
    configured_models = {
        key
        for key in ("loss-random", "loss-state", "loss-gemodel")
        if key in options
    }
    expected_model = axes.get("loss_model", "none")
    expected_key = {
        "random": "loss-random",
        "gemodel": "loss-gemodel",
    }.get(expected_model)

    if expected_model == "none":
        return ["netem_loss_model"] if configured_models else []
    if expected_key is None or configured_models != {expected_key}:
        return ["netem_loss_model"]

    parameters = options.get(expected_key)
    if not isinstance(parameters, dict):
        return ["netem_loss_parameters"]
    expected_parameters = (
        {"loss": "loss_pct"}
        if expected_model == "random"
        else {
            "p": "burst_p",
            "r": "burst_r",
            "1-h": "burst_h",
            "1-k": "burst_k",
        }
    )
    for option, axis in expected_parameters.items():
        configured = parameters.get(option)
        expected = as_float(axes.get(axis)) / 100.0
        if not isinstance(configured, (int, float)) or not math.isclose(
            float(configured), expected, rel_tol=0.0, abs_tol=1e-6
        ):
            return ["netem_loss_parameters"]
    return []


def netem_base_configuration_issues(
    netem: dict[str, Any] | None,
    axes: dict[str, str],
) -> list[str]:
    options = ((netem or {}).get("options") or {})
    delay = options.get("delay") or {}
    configured_delay_ms = as_float(delay.get("delay")) * 1000.0
    expected_delay_ms = as_float(axes.get("rtt_ms")) / 2.0
    model = axes.get("loss_model", "none")
    loss_key = {
        "random": "loss-random",
        "gemodel": "loss-gemodel",
    }.get(model)
    expected_option_keys = {"limit", "delay", "ecn", "gap"}
    if loss_key is not None:
        expected_option_keys.add(loss_key)
    if (
        set(options) != expected_option_keys
        or as_int(options.get("limit")) != 100000
        or set(delay) != {"delay", "jitter", "correlation"}
        or abs(configured_delay_ms - expected_delay_ms) > 1.0
        or as_float(delay.get("jitter")) != 0.0
        or as_float(delay.get("correlation")) != 0.0
        or options.get("ecn") is not False
        or as_int(options.get("gap"), -1) != 0
        or (
            model == "random"
            and (
                not isinstance(options.get("loss-random"), dict)
                or set(options["loss-random"]) != {"loss", "correlation"}
                or as_float(options["loss-random"].get("correlation")) != 0.0
            )
        )
        or (
            model == "gemodel"
            and (
                not isinstance(options.get("loss-gemodel"), dict)
                or set(options["loss-gemodel"]) != {"p", "r", "1-h", "1-k"}
            )
        )
    ):
        return ["netem_base_parameters"]
    return []


def impairment_configuration_issues(
    endpoint: Path, axes: dict[str, str], queue_bytes: int
) -> list[str]:
    issues: list[str] = []
    qdiscs = load_json(endpoint / "qdisc-pre.json", [])
    root = find_qdisc_in(qdiscs, "htb", "1:")
    queue_kind = axes.get("queue_kind", "bfifo")
    queue = find_qdisc_in(qdiscs, queue_kind, handle_prefix="20:")
    if not root or not root.get("root"):
        issues.append("htb_root")
    if not queue or queue.get("parent") != "1:10":
        issues.append("queue_kind")
    else:
        options = queue.get("options") or {}
        configured_limit = (
            as_int(options.get("limit"))
            if queue_kind == "bfifo"
            else as_int(options.get("memory_limit"))
        )
        if configured_limit != queue_bytes:
            issues.append("queue_limit")

    expected_rate = as_float(axes.get("rate_mbps"))
    configured_rate = htb_rate_mbps(endpoint / "class-pre.json")
    if (
        configured_rate is None
        or expected_rate <= 0
        or abs(configured_rate - expected_rate) / expected_rate > 0.01
    ):
        issues.append("class_rate")

    netem = find_qdisc(
        endpoint / "ifb-qdisc-pre.json", "netem", handle_prefix="40:"
    )
    delay = ((netem or {}).get("options") or {}).get("delay") or {}
    configured_delay_ms = as_float(delay.get("delay")) * 1000.0
    expected_delay_ms = as_float(axes.get("rtt_ms")) / 2.0
    if abs(configured_delay_ms - expected_delay_ms) > 1.0:
        issues.append("netem_delay")
    configuration_axes = axes
    if axes.get("impairment_schedule") == "timed":
        configuration_axes = {**axes, "loss_model": "none"}
    issues.extend(netem_loss_configuration_issues(netem, configuration_axes))

    port = 51821 if axes.get("tunnel") == "tcp" else 51820
    if matching_filter_count(endpoint / "filter-pre.json", port, False) < 2:
        issues.append("egress_filters")
    if matching_filter_count(endpoint / "ingress-pre.json", port, True) < 2:
        issues.append("ingress_filters")
    if axes.get("impairment_schedule") != "timed":
        issues.extend(netem_counter_issues(endpoint, axes))
    return issues


def parse_nstat(path: Path) -> dict[str, int]:
    counters: dict[str, int] = {}
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return counters
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1].lstrip("-").isdigit():
            counters[parts[0]] = int(parts[1])
    return counters


def nstat_delta(endpoint: Path, names: tuple[str, ...]) -> int:
    before = parse_nstat(endpoint / "nstat-pre.txt")
    after = parse_nstat(endpoint / "nstat-post.txt")
    return sum(max(0, after.get(name, 0) - before.get(name, 0)) for name in names)


def clock_synchronized(endpoint: Path) -> bool:
    try:
        return "NTPSynchronized=yes" in (endpoint / "clock.txt").read_text()
    except OSError:
        return False


def kernel_anomalies(endpoint: Path) -> list[str]:
    pattern = re.compile(
        r"(?:\bBUG:|\bOops:|\bkernel panic\b|\bKASAN:|\bUBSAN:|"
        r"\bWARNING: CPU:|\bsoft lockup\b|\bhard LOCKUP\b)",
        re.IGNORECASE,
    )
    try:
        lines = (endpoint / "kernel.log").read_text(errors="replace").splitlines()
    except OSError:
        return []
    return [line.strip() for line in lines if pattern.search(line)][:20]


def analyze_cell(cell_dir: Path) -> dict[str, Any]:
    axes = load_env(cell_dir / "cell.env")
    iperf = load_json(cell_dir / "iperf3.json", {})
    intervals = iperf_intervals(iperf if isinstance(iperf, dict) else {})
    duration = as_float(axes.get("duration_s"))
    workload_duration = as_float(axes.get("workload_duration_s"), duration)
    warmup = as_float(axes.get("warmup_s"))
    direction = axes.get("direction", "reverse")
    delivery = interface_delivery_bins(cell_dir, direction, warmup, duration)
    runtime_delivery = (
        delivery
        if math.isclose(workload_duration, duration)
        else interface_delivery_bins(
            cell_dir,
            direction,
            warmup,
            workload_duration,
        )
    )
    bps = delivery["bps"]
    runtime_bps = runtime_delivery["bps"]
    scored_intervals = (
        intervals
        if math.isclose(workload_duration, duration)
        else [
            row
            for row in intervals
            if row["start"] < duration
            and row["end"] <= duration + WORKLOAD_MAX_INTERVAL_BOUNDARY_ERROR_S
        ]
    )
    iperf_bps = [row["bits_per_second"] for row in scored_intervals]
    completion_axes = (
        axes
        if math.isclose(workload_duration, duration)
        else {**axes, "duration_s": str(workload_duration)}
    )
    completion_metrics, completion_issues = workload_completion(
        completion_axes,
        iperf if isinstance(iperf, dict) else {},
        intervals,
        runtime_delivery,
        (
            (cell_dir / "iperf3.stderr").read_text(errors="replace")
            if (cell_dir / "iperf3.stderr").is_file()
            else None
        ),
    )
    flows = max(1, as_int(axes.get("flows"), 1))
    expected_bins = delivery["expected_bins"]
    stall_fraction = sum(value <= 0 for value in bps) / len(bps) if bps else None
    trend = ols_trend(bps)
    quarter = max(1, len(bps) // 4)
    first_q = statistics.fmean(bps[:quarter]) if bps else None
    last_q = statistics.fmean(bps[-quarter:]) if bps else None
    mean_bps = statistics.fmean(bps) if bps else None
    quarter_change = (
        (last_q - first_q) / mean_bps
        if mean_bps and first_q is not None and last_q is not None
        else None
    )

    data_flow_ports = iperf_data_flow_ports(iperf if isinstance(iperf, dict) else {})
    timed_events = scored_tcp_events(
        cell_dir,
        delivery["measurement_start_ns"],
        delivery["measurement_end_ns"],
        data_flow_ports,
    )
    runtime_timed_events = (
        timed_events
        if runtime_delivery is delivery
        else scored_tcp_events(
            cell_dir,
            runtime_delivery["measurement_start_ns"],
            runtime_delivery["measurement_end_ns"],
            data_flow_ports,
        )
    )
    events = Counter((event["event"], event["layer"]) for event in timed_events)
    inner_rto = events[("rto", "inner")]
    outer_rto = events[("rto", "outer")]
    minutes = duration / 60.0 if duration else 0
    logical_flows = flows * (2 if direction == "bidir" else 1)
    inner_rto_rate = inner_rto / (logical_flows * minutes) if minutes else None
    outer_rto_rate = outer_rto / minutes if minutes else None
    correlation = correlate_tcp_layers(timed_events)
    competitor_metrics, competitor_issues = competitor_workload(cell_dir, axes)
    telemetry_issues = [
        f"{endpoint}:{issue}"
        for endpoint in ("client", "server")
        for issue in tcp_event_telemetry_issues(
            cell_dir / endpoint,
            require_capture_anchor=(
                axes.get("workload_completion") == "interval_complete"
            ),
        )
    ]
    carrier_endpoints = {
        endpoint: tcp_carrier_stability(
            cell_dir / endpoint / "ss-series.txt",
            runtime_delivery["measurement_start_ns"],
            runtime_delivery["measurement_end_ns"],
        )
        for endpoint in ("client", "server")
    }
    carrier_stable = all(
        status["stable_dual_carrier"] for status in carrier_endpoints.values()
    )

    target_rtt = as_float(axes.get("rtt_ms"))
    queue_bytes = max(
        16384,
        round(
            as_float(axes.get("rate_mbps"))
            * target_rtt
            * 125
            * as_float(axes.get("queue_bdp"), 1)
        ),
    )
    queue_kind = axes.get("queue_kind", "bfifo")
    queue_window: dict[str, list[int | None]] = {
        key: [
            qdisc_window_delta(
                cell_dir / endpoint,
                queue_kind,
                key,
                delivery["measurement_start_ns"],
                delivery["measurement_end_ns"],
            )
            for endpoint in ("client", "server")
        ]
        for key in ("packets", "drops", "overlimits")
    }
    queue_window_complete = all(
        value is not None for values in queue_window.values() for value in values
    )
    queue_packets = sum(value or 0 for value in queue_window["packets"])
    queue_drops = sum(value or 0 for value in queue_window["drops"])
    queue_overlimits = sum(value or 0 for value in queue_window["overlimits"])
    queue_peak_backlogs = [
        qdisc_window_peak(
            cell_dir / endpoint,
            queue_kind,
            "backlog",
            delivery["measurement_start_ns"],
            delivery["measurement_end_ns"],
        )
        for endpoint in ("client", "server")
    ]
    queue_peak_backlog = (
        max(value for value in queue_peak_backlogs if value is not None)
        if all(value is not None for value in queue_peak_backlogs)
        else None
    )
    timed_schedule = axes.get("impairment_schedule") == "timed"
    timed_metrics: dict[str, int | float | bool | None] = {}
    episode_metrics: dict[str, int | float | bool | None] = {}
    timed_issues: list[str] = []
    episode_issues: list[str] = []
    if timed_schedule:
        timed_metrics, timed_endpoint_metrics, timed_issues = timed_impairment_evidence(
            cell_dir,
            axes,
            runtime_delivery["measurement_start_ns"],
            runtime_delivery["measurement_end_ns"],
        )
        netem_endpoints = [
            timed_endpoint_metrics.get(endpoint, {
                "packets": None,
                "drops": None,
                "loss_fraction": None,
            })
            for endpoint in ("client", "server")
        ]
        episode_metrics, episode_issues = dynamic_episode_metrics(
            runtime_bps,
            runtime_delivery["measurement_start_ns"],
            runtime_delivery["measurement_end_ns"],
            as_int(timed_metrics.get("impairment_start_ns")) or None,
            as_int(timed_metrics.get("impairment_stop_ns")) or None,
            as_int(timed_metrics.get("recovery_start_ns")) or None,
            runtime_timed_events,
            axes.get("tunnel", ""),
        )
    else:
        netem_endpoints = [
            netem_counter_metrics(cell_dir / endpoint)
            for endpoint in ("client", "server")
        ]
    netem_counter_complete = all(
        metric[key] is not None
        for metric in netem_endpoints
        for key in ("packets", "drops")
    )
    netem_packets = (
        sum(as_int(metric["packets"]) for metric in netem_endpoints)
        if netem_counter_complete
        else None
    )
    netem_drops = (
        sum(as_int(metric["drops"]) for metric in netem_endpoints)
        if netem_counter_complete
        else None
    )
    netem_total = (
        netem_packets + netem_drops
        if netem_packets is not None and netem_drops is not None
        else None
    )
    netem_loss_fraction = (
        netem_drops / netem_total
        if netem_drops is not None and netem_total is not None and netem_total > 0
        else None
    )
    netem_loss_fractions = [
        as_float(metric["loss_fraction"])
        for metric in netem_endpoints
        if metric["loss_fraction"] is not None
    ]
    impairment_issues = [
        f"{endpoint}:{issue}"
        for endpoint in ("client", "server")
        for issue in impairment_configuration_issues(
            cell_dir / endpoint, axes, queue_bytes
        )
    ]

    ping_metrics, ping_issues = impairment_ping_validation(cell_dir, axes)
    expected_loss = expected_netem_loss_fraction(axes)
    loss_band_required = netem_loss_band_required(axes)
    loss_band_valid = (
        all(
            metric["loss_fraction"] is not None
            and expected_loss is not None
            and as_float(metric["loss_fraction"]) >= expected_loss * 0.5
            and as_float(metric["loss_fraction"])
            <= min(1.0, expected_loss * 2.0)
            for metric in netem_endpoints
        )
        if loss_band_required
        else None
    )
    loss_realized = all(
        metric["packets"] is not None
        and metric["drops"] is not None
        and as_int(metric["packets"]) + as_int(metric["drops"]) > 0
        and as_int(metric["drops"]) > 0
        for metric in netem_endpoints
    )

    anomalies = kernel_anomalies(cell_dir / "client") + kernel_anomalies(cell_dir / "server")
    invalid_reasons: list[str] = []
    if completion_issues:
        invalid_reasons.append(
            "workload_rc"
            if completion_metrics["workload_completion_policy"] == "strict"
            else "workload_completion"
        )
    if delivery["covered_bins"] < expected_bins * 0.80:
        invalid_reasons.append("missing_delivery_bins")
    if timed_schedule and (
        workload_duration < duration
        or delivery["covered_bins"] != expected_bins
        or runtime_delivery["covered_bins"] != runtime_delivery["expected_bins"]
    ):
        invalid_reasons.append("dynamic_delivery_bins")
    invalid_reasons.extend(ping_issues)
    if impairment_issues:
        invalid_reasons.append("impairment_configuration")
    if not queue_window_complete:
        invalid_reasons.append("queue_counter_window")
    if queue_packets <= 0:
        invalid_reasons.append("shaped_class_unused")
    if not clock_synchronized(cell_dir / "client") or not clock_synchronized(cell_dir / "server"):
        invalid_reasons.append("clock_unsynchronized")
    if telemetry_issues:
        invalid_reasons.append("tcp_event_telemetry")
    if timed_issues:
        invalid_reasons.append("timed_impairment")
    if episode_issues:
        invalid_reasons.append("dynamic_episode")
    if competitor_issues:
        invalid_reasons.append("competitor_workload")
    if anomalies:
        invalid_reasons.append("kernel_anomaly")
    if axes.get("tunnel") == "tcp" and not carrier_stable:
        invalid_reasons.append("unstable_tcp_carriers")

    stall_condition = stall_fraction is not None and stall_fraction >= STALL_THRESHOLD
    trend_condition = (
        trend["trend_drop_fraction"] is not None
        and trend["trend_drop_fraction"] <= TREND_THRESHOLD
        and trend["slope_t"] is not None
        and trend["slope_t"] <= TREND_T_THRESHOLD
    )
    rto_condition = inner_rto_rate is not None and inner_rto_rate >= RTO_THRESHOLD
    condition_count = sum((stall_condition, trend_condition, rto_condition))
    if invalid_reasons:
        classification = "invalid"
    elif condition_count == 3:
        classification = "meltdown"
    elif condition_count == 2:
        classification = "near-meltdown"
    elif condition_count == 1:
        classification = "degraded"
    else:
        classification = "stable"

    timeout_names = ("TcpTimeouts", "TcpExtTCPTimeouts")
    retrans_names = ("TcpRetransSegs",)
    nstat_timeouts = sum(
        nstat_delta(cell_dir / endpoint, timeout_names) for endpoint in ("client", "server")
    )
    nstat_retrans = sum(
        nstat_delta(cell_dir / endpoint, retrans_names) for endpoint in ("client", "server")
    )

    return {
        "cell_id": axes.get("cell_id", cell_dir.name),
        "axes": {
            **{
                key: axes.get(key)
                for key in PUBLISHED_AXIS_FIELDS
            },
            **(
                {
                    key: axes.get(key)
                    for key in (
                        "impairment_schedule",
                        "loss_epoch_start_s",
                        "loss_epoch_ms",
                        "workload_duration_s",
                    )
                }
                if timed_schedule
                else {}
            ),
        },
        "runtime": {
            key: axes.get(key)
            for key in (
                "module_srcversion",
                "module_sha256",
                "tool_sha256",
                "iperf_version",
                "iperf_sha256",
            )
        },
        "derived_controls": {
            "queue_bytes": queue_bytes,
            "expected_delivery_bins": expected_bins,
            "delivery_source_endpoints": delivery["source_endpoints"],
            **(
                {
                    "runtime_expected_delivery_bins": runtime_delivery[
                        "expected_bins"
                    ],
                }
                if timed_schedule
                else {}
            ),
        },
        "metrics": {
            "delivery_bins": delivery["covered_bins"],
            "delivery_bin_coverage": (
                delivery["covered_bins"] / expected_bins if expected_bins else None
            ),
            **(
                {
                    "runtime_delivery_bin_coverage": (
                        runtime_delivery["covered_bins"]
                        / runtime_delivery["expected_bins"]
                        if runtime_delivery["expected_bins"]
                        else None
                    ),
                }
                if timed_schedule
                else {}
            ),
            "goodput_mbps": mean_bps / 1e6 if mean_bps is not None else None,
            "iperf_goodput_mbps": (
                statistics.fmean(iperf_bps) / 1e6 if iperf_bps else None
            ),
            **completion_metrics,
            "stall_fraction_100ms": stall_fraction,
            "longest_stall_ms": longest_zero_run(bps) * 100,
            "first_quartile_mbps": first_q / 1e6 if first_q is not None else None,
            "last_quartile_mbps": last_q / 1e6 if last_q is not None else None,
            "quarter_change_fraction": quarter_change,
            **trend,
            "inner_rto": inner_rto,
            "outer_rto": outer_rto,
            "inner_retrans": events[("retrans", "inner")],
            "outer_retrans": events[("retrans", "outer")],
            "outer_recovery_events": correlation["outer_recovery_events"],
            "inner_rto_coupling_fraction": correlation["inner_rto_coupling"]["fraction"],
            "inner_rto_coupling_lag_ms": correlation["inner_rto_coupling"]["median_lag_ms"],
            "inner_cwnd_collapses": correlation["inner_cwnd_coupling"]["responses"],
            "inner_cwnd_coupling_fraction": correlation["inner_cwnd_coupling"]["fraction"],
            "inner_cwnd_coupling_lag_ms": correlation["inner_cwnd_coupling"]["median_lag_ms"],
            "inner_rto_per_flow_min": inner_rto_rate,
            "outer_rto_per_min": outer_rto_rate,
            "nstat_timeouts": nstat_timeouts,
            "nstat_retrans": nstat_retrans,
            "queue_packets": queue_packets,
            "queue_drops": queue_drops,
            "queue_overlimits": queue_overlimits,
            "queue_peak_backlog_bytes": queue_peak_backlog,
            "queue_peak_backlog_fraction": (
                queue_peak_backlog / queue_bytes
                if queue_peak_backlog is not None and queue_bytes
                else None
            ),
            "netem_packets": netem_packets,
            "netem_drops": netem_drops,
            "netem_expected_loss_fraction": expected_loss,
            "netem_loss_fraction": netem_loss_fraction,
            "netem_loss_realized_both_endpoints": loss_realized,
            "netem_loss_band_required": loss_band_required,
            "netem_loss_band_valid": loss_band_valid,
            "netem_loss_fraction_min": (
                min(netem_loss_fractions)
                if len(netem_loss_fractions) == len(netem_endpoints)
                else None
            ),
            "netem_loss_fraction_max": (
                max(netem_loss_fractions)
                if len(netem_loss_fractions) == len(netem_endpoints)
                else None
            ),
            **timed_metrics,
            **episode_metrics,
            **competitor_metrics,
            "tcp_carrier_samples": sum(
                status["samples"] for status in carrier_endpoints.values()
            ),
            "tcp_carrier_coverage_complete": all(
                status["coverage_complete"] for status in carrier_endpoints.values()
            ),
            "tcp_carrier_min_count": min(
                (
                    status["min_count"]
                    for status in carrier_endpoints.values()
                    if status["min_count"] is not None
                ),
                default=None,
            ),
            "tcp_carrier_max_count": max(
                (
                    status["max_count"]
                    for status in carrier_endpoints.values()
                    if status["max_count"] is not None
                ),
                default=None,
            ),
            "tcp_carrier_tuple_changes": sum(
                status["tuple_changes"] for status in carrier_endpoints.values()
            ),
            **ping_metrics,
        },
        "conditions": {
            "stall": stall_condition,
            "negative_trend": trend_condition,
            "inner_rto": rto_condition,
            **(
                {
                    "formal_meltdown": condition_count == 3,
                    "mechanism_observed": bool(
                        episode_metrics.get("mechanism_observed")
                    ),
                    "user_visible_disruption": bool(
                        episode_metrics.get("user_visible_disruption")
                    ),
                    "quasi_meltdown_episode": False,
                }
                if timed_schedule
                else {}
            ),
        },
        "thresholds": {
            "stall_fraction_100ms": STALL_THRESHOLD,
            "trend_drop_fraction": TREND_THRESHOLD,
            "trend_slope_t": TREND_T_THRESHOLD,
            "inner_rto_per_flow_min": RTO_THRESHOLD,
            "workload_interval_min_fraction": WORKLOAD_MIN_INTERVAL_FRACTION,
            "workload_interval_max_fraction": WORKLOAD_MAX_INTERVAL_FRACTION,
            "workload_interval_max_gap_s": WORKLOAD_MAX_INTERVAL_GAP_S,
            "workload_interval_max_boundary_error_s": (
                WORKLOAD_MAX_INTERVAL_BOUNDARY_ERROR_S
            ),
            "baseline_preflight_max_rtt_ms": BASELINE_PREFLIGHT_MAX_RTT_MS,
        },
        "valid": not invalid_reasons,
        "invalid_reasons": invalid_reasons,
        "impairment_configuration_issues": impairment_issues,
        **(
            {
                "timed_impairment_issues": sorted(set(timed_issues)),
                "dynamic_episode_issues": sorted(set(episode_issues)),
            }
            if timed_schedule
            else {}
        ),
        "tcp_event_telemetry_issues": telemetry_issues,
        "workload_completion_issues": completion_issues,
        "competitor_workload_issues": competitor_issues,
        "kernel_anomalies": anomalies,
        "classification": classification,
    }


CSV_FIELDS = [
    "cell_id",
    "tunnel",
    "rate_mbps",
    "rtt_ms",
    "queue_bdp",
    "queue_kind",
    "loss_model",
    "loss_pct",
    "burst_p",
    "burst_r",
    "burst_h",
    "burst_k",
    "flows",
    "duration_s",
    "workload_completion",
    "impairment_validation",
    "impairment_schedule",
    "loss_epoch_start_s",
    "loss_epoch_ms",
    "workload_duration_s",
    "inner_cc",
    "direction",
    "competitor",
    "valid",
    "classification",
    "goodput_mbps",
    "iperf_goodput_mbps",
    "iperf_version",
    "iperf_sha256",
    "workload_exit_code",
    "workload_completion_fallback_used",
    "workload_completion_valid",
    "workload_error",
    "workload_stderr_empty",
    "workload_final_control_error_allowed",
    "workload_reported_iperf_version",
    "workload_iperf_version_matches",
    "workload_connected_flows",
    "workload_expected_flows",
    "workload_interval_count",
    "workload_interval_span_s",
    "workload_interval_sum_s",
    "workload_interval_span_fraction",
    "workload_interval_sum_fraction",
    "workload_interval_max_gap_s",
    "workload_interval_max_overlap_s",
    "workload_interval_max_duration_error_s",
    "workload_interval_ordered",
    "workload_interval_shape_valid",
    "workload_bidir_reverse_interval_count",
    "workload_bidir_reverse_interval_span_s",
    "workload_bidir_reverse_interval_sum_s",
    "workload_bidir_reverse_interval_span_fraction",
    "workload_bidir_reverse_interval_sum_fraction",
    "workload_bidir_reverse_interval_max_gap_s",
    "workload_bidir_reverse_interval_max_overlap_s",
    "workload_bidir_reverse_interval_max_duration_error_s",
    "workload_bidir_reverse_interval_ordered",
    "workload_bidir_reverse_interval_shape_valid",
    "workload_interface_delivery_complete",
    "udp_control_goodput_ratio",
    "delivery_bin_coverage",
    "runtime_delivery_bin_coverage",
    "stall_fraction_100ms",
    "longest_stall_ms",
    "trend_drop_fraction",
    "slope_t",
    "inner_rto",
    "outer_rto",
    "inner_rto_per_flow_min",
    "outer_rto_per_min",
    "inner_retrans",
    "outer_retrans",
    "outer_recovery_events",
    "inner_rto_coupling_fraction",
    "inner_rto_coupling_lag_ms",
    "inner_cwnd_collapses",
    "inner_cwnd_coupling_fraction",
    "inner_cwnd_coupling_lag_ms",
    "queue_packets",
    "queue_drops",
    "queue_overlimits",
    "queue_peak_backlog_bytes",
    "queue_peak_backlog_fraction",
    "netem_packets",
    "netem_drops",
    "netem_expected_loss_fraction",
    "netem_loss_fraction",
    "netem_loss_realized_both_endpoints",
    "netem_loss_band_required",
    "netem_loss_band_valid",
    "netem_loss_fraction_min",
    "netem_loss_fraction_max",
    "timed_impairment_valid",
    "impairment_start_skew_ms",
    "impairment_stop_skew_ms",
    "transition_clock_error_bound_ms",
    "actual_loss_epoch_ms",
    "actual_loss_epoch_offset_s",
    "recovery_observation_s",
    "pre_median_mbps",
    "pre_mean_mbps",
    "impairment_mean_mbps",
    "post_0_1s_mbps",
    "post_1_5s_mbps",
    "post_5_10s_mbps",
    "post_10_30s_mbps",
    "post_30_60s_mbps",
    "episode_min_1s_mbps",
    "episode_min_5s_mbps",
    "episode_longest_stall_ms",
    "episode_stall_fraction_100ms",
    "bandwidth_deficit_mbit",
    "first_delivery_after_recovery_ms",
    "recovery_90_ms",
    "recovery_90_right_censored",
    "episode_outer_recovery_events",
    "mechanism_observed",
    "user_visible_disruption",
    "episode_below_half_pre",
    "udp_control_episode_min_5s_ratio",
    "episode_below_half_udp_control",
    "quasi_meltdown_episode",
    "competitor_goodput_mbps",
    "competitor_seconds",
    "tcp_carrier_min_count",
    "tcp_carrier_max_count",
    "tcp_carrier_tuple_changes",
    "baseline_ping_transmitted",
    "baseline_ping_received",
    "baseline_ping_loss_pct",
    "baseline_ping_rtt_mean_ms",
    "baseline_preflight_valid",
    "ping_transmitted",
    "ping_received",
    "ping_rtt_mean_ms",
    "impaired_ping_rtt_valid",
    "invalid_reasons",
]


def flatten(doc: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {"cell_id": doc.get("cell_id")}
    row.update(doc.get("axes", {}))
    row.update(doc.get("runtime", {}))
    row.update(doc.get("metrics", {}))
    row["valid"] = doc.get("valid")
    row["classification"] = doc.get("classification")
    row["invalid_reasons"] = ";".join(doc.get("invalid_reasons", []))
    return row


def apply_udp_control_comparison(docs: list[dict[str, Any]]) -> None:
    controls: dict[tuple[str, str, str], dict[str, Any]] = {}
    pattern = re.compile(r"^(.*)-(tcp|udp)-r(\d+)$")
    for doc in docs:
        match = pattern.match(str(doc.get("cell_id", "")))
        if match:
            controls[(match.group(1), match.group(3), match.group(2))] = doc

    for doc in docs:
        match = pattern.match(str(doc.get("cell_id", "")))
        if not match or match.group(2) != "tcp":
            continue
        udp = controls.get((match.group(1), match.group(3), "udp"))
        tcp_goodput = doc.get("metrics", {}).get("goodput_mbps")
        udp_goodput = (udp or {}).get("metrics", {}).get("goodput_mbps")
        ratio = (
            as_float(tcp_goodput) / as_float(udp_goodput)
            if tcp_goodput is not None
            and udp_goodput is not None
            and as_float(udp_goodput) > 0
            else None
        )
        doc.setdefault("metrics", {})["udp_control_goodput_ratio"] = ratio
        below_half = bool(
            doc.get("valid")
            and udp
            and udp.get("valid")
            and ratio is not None
            and ratio < 0.50
        )
        doc.setdefault("conditions", {})["below_half_udp_control"] = below_half
        if below_half and doc.get("classification") == "stable":
            doc["classification"] = "degraded"
        if doc.get("axes", {}).get("impairment_schedule") == "timed":
            metrics = doc.setdefault("metrics", {})
            udp_metrics = (udp or {}).get("metrics", {})
            tcp_episode_min = metrics.get("episode_min_5s_mbps")
            udp_episode_min = udp_metrics.get("episode_min_5s_mbps")
            episode_ratio = (
                as_float(tcp_episode_min) / as_float(udp_episode_min)
                if tcp_episode_min is not None
                and udp_episode_min is not None
                and as_float(udp_episode_min) > 0
                else None
            )
            below_half_episode_control = bool(
                doc.get("valid")
                and udp
                and udp.get("valid")
                and episode_ratio is not None
                and episode_ratio <= 0.50
            )
            quasi_meltdown = bool(
                below_half_episode_control
                and metrics.get("episode_below_half_pre")
                and metrics.get("mechanism_observed")
                and metrics.get("user_visible_disruption")
                and as_int(metrics.get("episode_longest_stall_ms")) >= 1000
            )
            metrics["udp_control_episode_min_5s_ratio"] = episode_ratio
            metrics["episode_below_half_udp_control"] = (
                below_half_episode_control
            )
            metrics["quasi_meltdown_episode"] = quasi_meltdown
            doc.setdefault("conditions", {})[
                "below_half_udp_episode_control"
            ] = below_half_episode_control
            doc["conditions"]["quasi_meltdown_episode"] = quasi_meltdown


def write_report(path: Path, docs: list[dict[str, Any]]) -> None:
    counts = Counter(doc.get("classification", "unknown") for doc in docs)
    valid = [doc for doc in docs if doc.get("valid")]
    meltdown = [doc for doc in valid if doc.get("classification") == "meltdown"]
    near = [doc for doc in valid if doc.get("classification") == "near-meltdown"]
    lines = [
        "# Generated TCP Meltdown Results",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"Full meltdown observed under the predeclared definition: **{'YES' if meltdown else 'NO'}**.",
        "",
        "| classification | cells |",
        "|---|---:|",
    ]
    for name in ("stable", "degraded", "near-meltdown", "meltdown", "invalid"):
        lines.append(f"| {name} | {counts.get(name, 0)} |")
    lines.extend(
        [
            "",
            f"Near-meltdown cells: {len(near)}. Valid cells: {len(valid)} / {len(docs)}.",
            "",
            "| cell | tunnel | RTT ms | queue BDP | flows | Mbps | stalls | trend | inner RTO/flow-min | qdrops | result |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for doc in sorted(docs, key=lambda item: str(item.get("cell_id"))):
        axes = doc.get("axes", {})
        metrics = doc.get("metrics", {})
        lines.append(
            "| {cell} | {tunnel} | {rtt} | {queue} | {flows} | {mbps} | {stalls} | "
            "{trend} | {rto} | {drops} | {result} |".format(
                cell=doc.get("cell_id"),
                tunnel=axes.get("tunnel"),
                rtt=axes.get("rtt_ms"),
                queue=axes.get("queue_bdp"),
                flows=axes.get("flows"),
                mbps=format_number(metrics.get("goodput_mbps"), 2),
                stalls=format_number(metrics.get("stall_fraction_100ms"), 3),
                trend=format_number(metrics.get("trend_drop_fraction"), 3),
                rto=format_number(metrics.get("inner_rto_per_flow_min"), 2),
                drops=metrics.get("queue_drops", 0),
                result=doc.get("classification"),
            )
        )
    path.write_text("\n".join(lines) + "\n")


def format_number(value: Any, digits: int) -> str:
    if value is None:
        return "-"
    return f"{as_float(value):.{digits}f}"


def campaign_manifest_issues(root: Path, discovered: set[str]) -> list[str]:
    manifest_path = root / "campaign-status.json"
    if not manifest_path.exists():
        return ["campaign_status_missing"]
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        return ["campaign_status_unreadable"]
    issues: list[str] = []
    if manifest.get("status") not in {"ready", "complete"}:
        issues.append("campaign_not_complete")
    expected_value = manifest.get("expected_cells")
    if not isinstance(expected_value, list) or not all(
        isinstance(value, str) for value in expected_value
    ):
        issues.append("campaign_expected_cells")
    elif set(expected_value) != discovered:
        issues.append("campaign_cell_mismatch")
    failed_value = manifest.get("failed_cells", [])
    if not isinstance(failed_value, list) or failed_value:
        issues.append("campaign_failed_cells")
    matrix_value = manifest.get("matrix_expected_cells")
    targeted_value = manifest.get("targeted_selection")
    qualifying_value = manifest.get("qualifying_complete")
    if matrix_value is not None:
        if not isinstance(matrix_value, list) or not all(
            isinstance(value, str) for value in matrix_value
        ):
            issues.append("campaign_matrix_cells")
        elif (
            isinstance(expected_value, list)
            and not set(expected_value).issubset(set(matrix_value))
        ):
            issues.append("campaign_matrix_selection")
        elif targeted_value != (
            isinstance(expected_value, list)
            and set(expected_value) != set(matrix_value)
        ):
            issues.append("campaign_targeted_selection")
        if qualifying_value is not (
            manifest.get("status") == "complete" and targeted_value is False
        ):
            issues.append("campaign_qualifying_complete")
    campaign_fingerprint = manifest.get("campaign_fingerprint")
    fingerprints = manifest.get("cell_fingerprints")
    if (
        not isinstance(campaign_fingerprint, str)
        or not re.fullmatch(r"[a-f0-9]{64}", campaign_fingerprint)
    ):
        issues.append("campaign_fingerprint")
    if not isinstance(fingerprints, dict) or set(fingerprints) != discovered:
        issues.append("campaign_cell_fingerprints")
    else:
        for cell_id in discovered:
            expected_fingerprint = fingerprints.get(cell_id)
            try:
                actual_fingerprint = (
                    root / "cells" / cell_id / "cell.fingerprint"
                ).read_text(encoding="ascii").strip()
            except OSError:
                actual_fingerprint = None
            axes = load_env(root / "cells" / cell_id / "cell.env")
            if (
                not isinstance(expected_fingerprint, str)
                or not re.fullmatch(r"[a-f0-9]{64}", expected_fingerprint)
                or actual_fingerprint != expected_fingerprint
                or axes.get("cell_fingerprint") != expected_fingerprint
                or axes.get("campaign_fingerprint") != campaign_fingerprint
            ):
                issues.append(f"campaign_fingerprint_mismatch:{cell_id}")
    return issues


def campaign(root: Path, csv_path: Path, report_path: Path | None) -> int:
    docs: list[dict[str, Any]] = []
    issues: list[str] = []
    cell_paths = sorted((root / "cells").glob("*/cell.json"))
    if not cell_paths:
        issues.append("no_cells")
    discovered = {path.parent.name for path in cell_paths}
    for path in cell_paths:
        if not (path.parent / "cell.complete").is_file():
            issues.append(f"incomplete_cell:{path.parent.name}")
            continue
        doc = load_json(path)
        if not isinstance(doc, dict):
            issues.append(f"unreadable_cell:{path.parent.name}")
            continue
        if doc.get("cell_id") != path.parent.name:
            issues.append(f"cell_id_mismatch:{path.parent.name}")
            continue
        docs.append(doc)
    issues.extend(campaign_manifest_issues(root, discovered))
    if issues:
        print("campaign is incomplete: " + ", ".join(issues), file=sys.stderr)
        return 1

    apply_udp_control_comparison(docs)
    for doc in docs:
        cell_id = doc.get("cell_id")
        if cell_id:
            (root / "cells" / str(cell_id) / "cell.json").write_text(
                json.dumps(doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for doc in docs:
            writer.writerow(flatten(doc))
    if report_path:
        write_report(report_path, docs)
    print(
        json.dumps(
            {
                "cells": len(docs),
                "classifications": Counter(doc.get("classification") for doc in docs),
                "csv": str(csv_path),
                "report": str(report_path) if report_path else None,
            },
            default=dict,
            indent=2,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    cell_parser = sub.add_parser("cell")
    cell_parser.add_argument("cell_dir", type=Path)
    baseline_parser = sub.add_parser("baseline")
    baseline_parser.add_argument("ping_path", type=Path)
    campaign_parser = sub.add_parser("campaign")
    campaign_parser.add_argument("root", type=Path)
    campaign_parser.add_argument("--csv", type=Path, required=True)
    campaign_parser.add_argument("--report", type=Path)
    stalls_parser = sub.add_parser("stalls")
    stalls_parser.add_argument("cell_dir", type=Path)
    stalls_parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    if args.command == "cell":
        print(json.dumps(analyze_cell(args.cell_dir), indent=2, sort_keys=True))
        return 0
    if args.command == "baseline":
        metrics, valid = baseline_preflight(args.ping_path)
        print(json.dumps(metrics, indent=2, sort_keys=True))
        return 0 if valid else 1
    if args.command == "stalls":
        try:
            report = stall_timeline(args.cell_dir)
        except ValueError as error:
            parser.error(str(error))
        if args.csv:
            write_stall_csv(args.csv, report)
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    return campaign(args.root, args.csv, args.report)


if __name__ == "__main__":
    raise SystemExit(main())
