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
TCP_EVENT_SUMMARIES = {
    (event, layer)
    for event in ("rto", "retrans")
    for layer in ("inner", "outer", "competitor")
}


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


def iperf_intervals(doc: dict[str, Any]) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    for interval in doc.get("intervals", []):
        summary = interval.get("sum_received") or interval.get("sum")
        if not summary:
            streams = interval.get("streams", [])
            if streams:
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


def parse_ping(path: Path) -> dict[str, float | None]:
    try:
        text = path.read_text()
    except OSError:
        return {"ping_loss_pct": None, "ping_rtt_mean_ms": None}
    loss = re.search(r"([\d.]+)% packet loss", text)
    rtt = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", text)
    return {
        "ping_loss_pct": float(loss.group(1)) if loss else None,
        "ping_rtt_mean_ms": float(rtt.group(2)) if rtt else None,
    }


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


def tcp_event_telemetry_issues(endpoint: Path) -> list[str]:
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
    event_counts: Counter[tuple[str, str]] = Counter()
    for line_number, line in enumerate(lines[1:], start=2):
        if not line:
            continue
        parts = line.split(",")
        if len(parts) != 8:
            issues.append(f"events_malformed_line_{line_number}")
            continue
        if parts[0] == "summary":
            if (
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
        if (
            not parts[0].isdigit()
            or parts[1] not in {"rto", "retrans", "cwnd"}
            or parts[2] not in {"inner", "outer", "competitor"}
            or not all(value.isdigit() for value in parts[3:])
        ):
            issues.append(f"events_malformed_line_{line_number}")
        elif parts[1] in {"rto", "retrans"}:
            event_counts[(parts[1], parts[2])] += 1

    if set(summaries) != TCP_EVENT_SUMMARIES:
        issues.append("events_summary")
    elif any(
        summaries[key] > event_counts[key]
        or event_counts[key] - summaries[key] > MAX_TRACE_SUMMARY_LAG
        for key in TCP_EVENT_SUMMARIES
    ):
        issues.append("events_summary_mismatch")
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


def qdisc_metric(qdisc: dict[str, Any] | None, key: str) -> int:
    if not qdisc:
        return 0
    if key in qdisc:
        return as_int(qdisc.get(key))
    stats = qdisc.get("stats") or qdisc.get("stats2") or {}
    if isinstance(stats, dict):
        if key in stats:
            return as_int(stats.get(key))
        basic = stats.get("basic") or {}
        queue = stats.get("queue") or {}
        if key in basic:
            return as_int(basic.get(key))
        if key in queue:
            return as_int(queue.get(key))
    return 0


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
) -> list[int] | None:
    if start_ns is None or end_ns is None:
        return None
    samples: list[tuple[int, int]] = []
    try:
        lines = (endpoint / "qdisc-series.jsonl").read_text(
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
        qdisc = find_qdisc_in(row.get("qdisc"), kind, handle_prefix="20:")
        if timestamp_ns is not None and qdisc is not None:
            samples.append((timestamp_ns, qdisc_metric(qdisc, key)))
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
) -> int | None:
    values = qdisc_window_values(endpoint, kind, key, start_ns, end_ns)
    if values is None:
        return None
    return max(0, values[-1] - values[0])


def qdisc_window_peak(
    endpoint: Path,
    kind: str,
    key: str,
    start_ns: int | None,
    end_ns: int | None,
) -> int | None:
    values = qdisc_window_values(endpoint, kind, key, start_ns, end_ns)
    return max(values) if values else None


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
    issues.extend(netem_loss_configuration_issues(netem, axes))

    port = 51821 if axes.get("tunnel") == "tcp" else 51820
    if matching_filter_count(endpoint / "filter-pre.json", port, False) < 2:
        issues.append("egress_filters")
    if matching_filter_count(endpoint / "ingress-pre.json", port, True) < 2:
        issues.append("ingress_filters")
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
    warmup = as_float(axes.get("warmup_s"))
    direction = axes.get("direction", "reverse")
    delivery = interface_delivery_bins(cell_dir, direction, warmup, duration)
    bps = delivery["bps"]
    iperf_bps = [row["bits_per_second"] for row in intervals]
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
        for issue in tcp_event_telemetry_issues(cell_dir / endpoint)
    ]
    carrier_endpoints = {
        endpoint: tcp_carrier_stability(
            cell_dir / endpoint / "ss-series.txt",
            delivery["measurement_start_ns"],
            delivery["measurement_end_ns"],
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
    impairment_issues = [
        f"{endpoint}:{issue}"
        for endpoint in ("client", "server")
        for issue in impairment_configuration_issues(
            cell_dir / endpoint, axes, queue_bytes
        )
    ]

    ping = parse_ping(cell_dir / "preflight-ping.txt")
    measured_rtt = ping["ping_rtt_mean_ms"]
    rtt_valid = (
        measured_rtt is not None
        and measured_rtt >= max(0.0, target_rtt * 0.70)
        and measured_rtt <= target_rtt * 1.35 + 5.0
    )

    anomalies = kernel_anomalies(cell_dir / "client") + kernel_anomalies(cell_dir / "server")
    invalid_reasons: list[str] = []
    if as_int(axes.get("workload_rc"), 1) != 0:
        invalid_reasons.append("workload_rc")
    if delivery["covered_bins"] < expected_bins * 0.80:
        invalid_reasons.append("missing_delivery_bins")
    if ping["ping_loss_pct"] is None or ping["ping_loss_pct"] >= 100:
        invalid_reasons.append("tunnel_preflight")
    if not rtt_valid:
        invalid_reasons.append("rtt_not_achieved")
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
            key: axes.get(key)
            for key in (
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
                "inner_cc",
                "direction",
                "competitor",
            )
        },
        "derived_controls": {
            "queue_bytes": queue_bytes,
            "expected_delivery_bins": expected_bins,
            "delivery_source_endpoints": delivery["source_endpoints"],
        },
        "metrics": {
            "delivery_bins": delivery["covered_bins"],
            "delivery_bin_coverage": (
                delivery["covered_bins"] / expected_bins if expected_bins else None
            ),
            "goodput_mbps": mean_bps / 1e6 if mean_bps is not None else None,
            "iperf_goodput_mbps": (
                statistics.fmean(iperf_bps) / 1e6 if iperf_bps else None
            ),
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
            **ping,
        },
        "conditions": {
            "stall": stall_condition,
            "negative_trend": trend_condition,
            "inner_rto": rto_condition,
        },
        "thresholds": {
            "stall_fraction_100ms": STALL_THRESHOLD,
            "trend_drop_fraction": TREND_THRESHOLD,
            "trend_slope_t": TREND_T_THRESHOLD,
            "inner_rto_per_flow_min": RTO_THRESHOLD,
        },
        "valid": not invalid_reasons,
        "invalid_reasons": invalid_reasons,
        "impairment_configuration_issues": impairment_issues,
        "tcp_event_telemetry_issues": telemetry_issues,
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
    "inner_cc",
    "direction",
    "competitor",
    "valid",
    "classification",
    "goodput_mbps",
    "iperf_goodput_mbps",
    "udp_control_goodput_ratio",
    "delivery_bin_coverage",
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
    "competitor_goodput_mbps",
    "competitor_seconds",
    "tcp_carrier_min_count",
    "tcp_carrier_max_count",
    "tcp_carrier_tuple_changes",
    "ping_rtt_mean_ms",
    "invalid_reasons",
]


def flatten(doc: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {"cell_id": doc.get("cell_id")}
    row.update(doc.get("axes", {}))
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
    campaign_parser = sub.add_parser("campaign")
    campaign_parser.add_argument("root", type=Path)
    campaign_parser.add_argument("--csv", type=Path, required=True)
    campaign_parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.command == "cell":
        print(json.dumps(analyze_cell(args.cell_dir), indent=2, sort_keys=True))
        return 0
    return campaign(args.root, args.csv, args.report)


if __name__ == "__main__":
    raise SystemExit(main())
