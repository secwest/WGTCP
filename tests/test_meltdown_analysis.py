#!/usr/bin/env python3
"""Behavioral tests for the TCP meltdown result analyzer."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYZER_PATH = ROOT / "perf-test" / "meltdown" / "harness" / "analyze.py"
SPEC = importlib.util.spec_from_file_location("meltdown_analyze", ANALYZER_PATH)
assert SPEC and SPEC.loader
ANALYZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZE)
ORCHESTRATOR = (
    ROOT / "perf-test" / "meltdown" / "orchestrator" / "run-campaign.ps1"
).read_text(encoding="utf-8")
SHAPER = (
    ROOT / "perf-test" / "meltdown" / "harness" / "shape-link.sh"
).read_text(encoding="utf-8")
SAMPLER = (
    ROOT / "perf-test" / "meltdown" / "harness" / "sample-endpoint.sh"
).read_text(encoding="utf-8")
TCP_EVENTS = (
    ROOT / "perf-test" / "meltdown" / "harness" / "tcp-events.bt"
).read_text(encoding="utf-8")
MECHANISM_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-mechanism.csv"
)
ADAPTIVE_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-mechanism-adaptive.csv"
)
RECOVERY_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-mechanism-recovery.csv"
)
BURST_MATRIX = ROOT / "perf-test" / "meltdown" / "matrix-mechanism-burst.csv"
BURST_RECOVERY_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-mechanism-burst-recovery.csv"
)
BURST_QUALIFIED_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-mechanism-burst-qualified.csv"
)


def workload_document(
    interval_count: int = 599,
    connected_flows: int = 16,
    error: str | None = "unable to receive results: ",
    bidirectional: bool = False,
) -> dict[str, object]:
    intervals = []
    for index in range(interval_count):
        summary = {
            "start": index / 10,
            "end": (index + 1) / 10,
            "seconds": 0.1,
            "bytes": 1_000,
            "bits_per_second": 80_000,
            "omitted": False,
        }
        if bidirectional:
            intervals.append(
                {
                    "sum": summary,
                    "sum_bidir_reverse": dict(summary),
                }
            )
        else:
            intervals.append({"sum_received": summary})
    document: dict[str, object] = {
        "start": {
            "version": "iperf 3.16",
            "connected": [
                {"local_port": 40_000 + index, "remote_port": 5201}
                for index in range(connected_flows)
            ]
        },
        "intervals": intervals,
    }
    if error is not None:
        document["error"] = error
    return document


class MeltdownAnalysisTest(unittest.TestCase):
    def test_mechanism_matrix_is_paired_and_predeclared(self) -> None:
        with MECHANISM_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 8)
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual({row["flows"] for row in rows}, {"16"})
        self.assertEqual({row["duration_s"] for row in rows}, {"60"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"5"})
        self.assertEqual({row["repetitions"] for row in rows}, {"2"})
        self.assertEqual({row["queue_kind"] for row in rows}, {"bfifo"})
        self.assertEqual({row["loss_model"] for row in rows}, {"none"})

        pairs: dict[tuple[str, str, str, str], set[str]] = {}
        for row in rows:
            key = (
                row["rate_mbps"],
                row["rtt_ms"],
                row["queue_bdp"],
                row["name"],
            )
            pairs.setdefault(key, set()).add(row["tunnel"])
        self.assertEqual(
            set(pairs),
            {
                ("35", "200", "0.25", "r35-q025-r200-16f"),
                ("35", "200", "0.5", "r35-q05-r200-16f"),
                ("25", "200", "0.25", "r25-q025-r200-16f"),
                ("35", "400", "0.25", "r35-q025-r400-16f"),
            },
        )
        self.assertTrue(all(tunnels == {"tcp", "udp"} for tunnels in pairs.values()))
        self.assertEqual(
            {row["stage"] for row in rows[:2]},
            {"mechanism-smoke"},
        )
        self.assertEqual({row["stage"] for row in rows[2:]}, {"mechanism"})

    def test_adaptive_matrix_is_paired_and_predeclared(self) -> None:
        with ADAPTIVE_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 4)
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual({row["rate_mbps"] for row in rows}, {"35"})
        self.assertEqual({row["rtt_ms"] for row in rows}, {"200"})
        self.assertEqual({row["flows"] for row in rows}, {"16"})
        self.assertEqual({row["duration_s"] for row in rows}, {"60"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"5"})
        self.assertEqual({row["repetitions"] for row in rows}, {"2"})
        self.assertEqual({row["queue_kind"] for row in rows}, {"bfifo"})
        self.assertEqual({row["loss_model"] for row in rows}, {"none"})

        pairs: dict[tuple[str, str], set[str]] = {}
        for row in rows:
            pairs.setdefault((row["queue_bdp"], row["name"]), set()).add(
                row["tunnel"]
            )
        self.assertEqual(
            set(pairs),
            {
                ("0.1", "r35-q010-r200-16f"),
                ("0.05", "r35-q005-r200-16f"),
            },
        )
        self.assertTrue(all(tunnels == {"tcp", "udp"} for tunnels in pairs.values()))
        self.assertEqual(
            {row["stage"] for row in rows[:2]},
            {"adaptive-smoke"},
        )
        self.assertEqual(
            {row["stage"] for row in rows[2:]},
            {"adaptive-fallback"},
        )

    def test_recovery_matrix_is_paired_and_predeclared(self) -> None:
        with RECOVERY_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 8)
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual({row["flows"] for row in rows}, {"16"})
        self.assertEqual({row["duration_s"] for row in rows}, {"60"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"5"})
        self.assertEqual({row["repetitions"] for row in rows}, {"2"})
        self.assertEqual({row["queue_kind"] for row in rows}, {"bfifo"})
        self.assertEqual({row["loss_model"] for row in rows}, {"none"})

        pairs: dict[tuple[str, str, str, str, str], set[str]] = {}
        for row in rows:
            key = (
                row["rate_mbps"],
                row["rtt_ms"],
                row["queue_bdp"],
                row["competitor"],
                row["name"],
            )
            pairs.setdefault(key, set()).add(row["tunnel"])
        self.assertEqual(
            set(pairs),
            {
                ("35", "200", "0.05", "0", "r35-q005-r200-16f"),
                ("25", "200", "0.05", "0", "r25-q005-r200-16f"),
                ("35", "400", "0.05", "0", "r35-q005-r400-16f"),
                ("35", "200", "0.1", "1", "r35-q010-r200-16f-comp"),
            },
        )
        self.assertTrue(all(tunnels == {"tcp", "udp"} for tunnels in pairs.values()))
        self.assertEqual(
            {row["stage"] for row in rows[:2]},
            {"recovery-smoke"},
        )
        self.assertEqual({row["stage"] for row in rows[2:]}, {"recovery"})

    def test_burst_matrix_is_paired_and_predeclared(self) -> None:
        with BURST_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual({row["stage"] for row in rows}, {"burst-smoke"})
        self.assertEqual({row["name"] for row in rows}, {"ge-r200-q1-16f"})
        self.assertEqual({row["tunnel"] for row in rows}, {"tcp", "udp"})
        self.assertEqual({row["rate_mbps"] for row in rows}, {"50"})
        self.assertEqual({row["rtt_ms"] for row in rows}, {"200"})
        self.assertEqual({row["queue_bdp"] for row in rows}, {"1"})
        self.assertEqual({row["queue_kind"] for row in rows}, {"bfifo"})
        self.assertEqual({row["loss_model"] for row in rows}, {"gemodel"})
        self.assertEqual({row["loss_pct"] for row in rows}, {"0"})
        self.assertEqual({row["burst_p"] for row in rows}, {"2"})
        self.assertEqual({row["burst_r"] for row in rows}, {"25"})
        self.assertEqual({row["burst_h"] for row in rows}, {"90"})
        self.assertEqual({row["burst_k"] for row in rows}, {"99"})
        self.assertEqual({row["flows"] for row in rows}, {"16"})
        self.assertEqual({row["duration_s"] for row in rows}, {"60"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"5"})
        self.assertEqual({row["inner_cc"] for row in rows}, {"cubic"})
        self.assertEqual({row["direction"] for row in rows}, {"reverse"})
        self.assertEqual({row["competitor"] for row in rows}, {"0"})
        self.assertEqual({row["repetitions"] for row in rows}, {"2"})

    def test_burst_recovery_matrix_is_paired_and_predeclared(self) -> None:
        with BURST_RECOVERY_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual({row["stage"] for row in rows}, {"burst-recovery-smoke"})
        self.assertEqual(
            {row["name"] for row in rows},
            {"ge2-25-90-1-r200-q1-16f"},
        )
        self.assertEqual({row["tunnel"] for row in rows}, {"tcp", "udp"})
        self.assertEqual({row["rate_mbps"] for row in rows}, {"50"})
        self.assertEqual({row["rtt_ms"] for row in rows}, {"200"})
        self.assertEqual({row["queue_bdp"] for row in rows}, {"1"})
        self.assertEqual({row["queue_kind"] for row in rows}, {"bfifo"})
        self.assertEqual({row["loss_model"] for row in rows}, {"gemodel"})
        self.assertEqual({row["loss_pct"] for row in rows}, {"0"})
        self.assertEqual({row["burst_p"] for row in rows}, {"2"})
        self.assertEqual({row["burst_r"] for row in rows}, {"25"})
        self.assertEqual({row["burst_h"] for row in rows}, {"90"})
        self.assertEqual({row["burst_k"] for row in rows}, {"1"})
        self.assertEqual({row["flows"] for row in rows}, {"16"})
        self.assertEqual({row["duration_s"] for row in rows}, {"60"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"5"})
        self.assertEqual({row["inner_cc"] for row in rows}, {"cubic"})
        self.assertEqual({row["direction"] for row in rows}, {"reverse"})
        self.assertEqual({row["competitor"] for row in rows}, {"0"})
        self.assertEqual({row["repetitions"] for row in rows}, {"2"})

    def test_burst_qualified_matrix_is_paired_and_predeclared(self) -> None:
        with BURST_QUALIFIED_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        self.assertEqual(
            sum(int(row["repetitions"]) for row in rows),
            4,
        )
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual({row["stage"] for row in rows}, {"burst-qualified-smoke"})
        self.assertEqual(
            {row["name"] for row in rows},
            {"ge2-25-90-1-r200-q1-16f"},
        )
        self.assertEqual({row["tunnel"] for row in rows}, {"tcp", "udp"})
        self.assertEqual({row["rate_mbps"] for row in rows}, {"50"})
        self.assertEqual({row["rtt_ms"] for row in rows}, {"200"})
        self.assertEqual({row["queue_bdp"] for row in rows}, {"1"})
        self.assertEqual({row["queue_kind"] for row in rows}, {"bfifo"})
        self.assertEqual({row["loss_model"] for row in rows}, {"gemodel"})
        self.assertEqual({row["burst_p"] for row in rows}, {"2"})
        self.assertEqual({row["burst_r"] for row in rows}, {"25"})
        self.assertEqual({row["burst_h"] for row in rows}, {"90"})
        self.assertEqual({row["burst_k"] for row in rows}, {"1"})
        self.assertEqual({row["flows"] for row in rows}, {"16"})
        self.assertEqual({row["duration_s"] for row in rows}, {"60"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"5"})
        self.assertEqual(
            {row["workload_completion"] for row in rows},
            {"interval_complete"},
        )
        self.assertEqual({row["inner_cc"] for row in rows}, {"cubic"})
        self.assertEqual({row["direction"] for row in rows}, {"reverse"})
        self.assertEqual({row["competitor"] for row in rows}, {"0"})

    def test_netem_loss_configuration_is_fail_closed(self) -> None:
        axes = {
            "loss_model": "gemodel",
            "loss_pct": "0",
            "burst_p": "2",
            "burst_r": "25",
            "burst_h": "90",
            "burst_k": "99",
        }
        netem = {
            "options": {
                "loss-gemodel": {
                    "p": 0.02,
                    "r": 0.25,
                    "1-h": 0.90,
                    "1-k": 0.99,
                }
            }
        }
        self.assertEqual(
            ANALYZE.netem_loss_configuration_issues(netem, axes),
            [],
        )

        wrong_parameters = {
            "options": {
                "loss-gemodel": {
                    "p": 0.03,
                    "r": 0.25,
                    "1-h": 0.90,
                    "1-k": 0.99,
                }
            }
        }
        self.assertEqual(
            ANALYZE.netem_loss_configuration_issues(wrong_parameters, axes),
            ["netem_loss_parameters"],
        )
        self.assertEqual(
            ANALYZE.netem_loss_configuration_issues(
                {"options": {"loss-random": {"loss": 0.02}}},
                axes,
            ),
            ["netem_loss_model"],
        )
        self.assertEqual(
            ANALYZE.netem_loss_configuration_issues(
                netem,
                {"loss_model": "none"},
            ),
            ["netem_loss_model"],
        )
        self.assertEqual(
            ANALYZE.netem_loss_configuration_issues(
                {"options": {"loss-random": {"loss": 0.003}}},
                {"loss_model": "random", "loss_pct": "0.3"},
            ),
            [],
        )

    def test_netem_loss_counters_are_fail_closed(self) -> None:
        axes = {
            "loss_model": "gemodel",
            "burst_p": "2",
            "burst_r": "25",
            "burst_h": "90",
            "burst_k": "1",
        }
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)

            def write_counters(name: str, packets: int, drops: int) -> None:
                (endpoint / name).write_text(
                    json.dumps(
                        [
                            {
                                "kind": "netem",
                                "handle": "40:",
                                "packets": packets,
                                "drops": drops,
                            }
                        ]
                    ),
                    encoding="utf-8",
                )

            write_counters("ifb-qdisc-pre.json", 100, 10)
            write_counters("ifb-qdisc-post.json", 1024, 86)
            metrics = ANALYZE.netem_counter_metrics(endpoint)
            self.assertEqual(metrics["packets"], 924)
            self.assertEqual(metrics["drops"], 76)
            self.assertAlmostEqual(metrics["loss_fraction"], 0.076)
            self.assertAlmostEqual(
                ANALYZE.expected_netem_loss_fraction(axes),
                0.07592592592592592,
            )
            self.assertEqual(ANALYZE.netem_counter_issues(endpoint, axes), [])

            (endpoint / "ifb-qdisc-pre.json").write_text(
                json.dumps(
                    [
                        {
                            "kind": "netem",
                            "handle": "40:",
                            "drops": 10,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                ANALYZE.netem_counter_issues(endpoint, axes),
                ["netem_counter_window"],
            )
            write_counters("ifb-qdisc-pre.json", 100, 10)

            write_counters("ifb-qdisc-post.json", 120, 990)
            self.assertEqual(
                ANALYZE.netem_counter_issues(endpoint, axes),
                ["netem_loss_rate"],
            )
            write_counters("ifb-qdisc-post.json", 1100, 10)
            self.assertEqual(
                ANALYZE.netem_counter_issues(endpoint, axes),
                ["netem_loss_not_realized"],
            )
            (endpoint / "ifb-qdisc-post.json").unlink()
            self.assertEqual(
                ANALYZE.netem_counter_issues(endpoint, axes),
                ["netem_counter_window"],
            )

    def test_json_loader_accepts_utf8_bom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cell.json"
            path.write_text(
                "\ufeffWARNING: prefixed diagnostic\n" + json.dumps({"valid": True}),
                encoding="utf-8",
            )
            self.assertEqual(ANALYZE.load_json(path), {"valid": True})

    def test_interface_delivery_uses_receiver_counter_and_preserves_stalls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            client = cell / "client"
            client.mkdir()
            start = 1_700_000_000_000_000_000
            (client / "first-inner-data.txt").write_text(
                "1700000000.000000 IP test\n", encoding="ascii"
            )
            (client / "interface-series.csv").write_text(
                "timestamp_ns,rx_bytes,tx_bytes\n"
                f"{start},0,0\n"
                f"{start + 100_000_000},100,0\n"
                f"{start + 200_000_000},100,0\n"
                f"{start + 300_000_000},300,0\n",
                encoding="ascii",
            )

            result = ANALYZE.interface_delivery_bins(cell, "reverse", 0, 0.3)

            self.assertEqual(result["covered_bins"], 3)
            self.assertEqual(result["source_endpoints"], ["client"])
            self.assertEqual(result["bps"], [8000.0, 0.0, 16000.0])

    def test_interface_delivery_marks_sampling_gaps_uncovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            client = cell / "client"
            client.mkdir()
            start = 1_700_000_000_000_000_000
            (client / "first-inner-data.txt").write_text(
                "1700000000.000000 IP test\n", encoding="ascii"
            )
            (client / "interface-series.csv").write_text(
                "timestamp_ns,rx_bytes,tx_bytes\n"
                f"{start},0,0\n"
                f"{start + 100_000_000},100,0\n"
                f"{start + 300_000_000},300,0\n",
                encoding="ascii",
            )

            result = ANALYZE.interface_delivery_bins(cell, "reverse", 0, 0.3)

            self.assertEqual(result["covered_bins"], 1)
            self.assertEqual(result["bps"], [8000.0])

    def test_missing_completion_policy_preserves_strict_exit_rule(self) -> None:
        axes = {
            "workload_rc": "1",
            "duration_s": "60",
            "flows": "16",
            "direction": "reverse",
        }
        document = workload_document()
        intervals = ANALYZE.iperf_intervals(document)
        delivery = {"covered_bins": 600, "expected_bins": 600}

        metrics, issues = ANALYZE.workload_completion(
            axes, document, intervals, delivery
        )

        self.assertEqual(metrics["workload_completion_policy"], "strict")
        self.assertEqual(issues, ["exit_status"])
        self.assertFalse(metrics["workload_completion_fallback_used"])

        axes["workload_rc"] = "0"
        metrics, issues = ANALYZE.workload_completion(axes, {}, [], {})
        self.assertEqual(issues, [])
        self.assertTrue(metrics["workload_completion_valid"])

    def test_interval_completion_accepts_only_qualified_final_control_failure(
        self,
    ) -> None:
        axes = {
            "workload_completion": "interval_complete",
            "workload_rc": "1",
            "duration_s": "60",
            "flows": "16",
            "direction": "reverse",
            "iperf_version": "iperf 3.16",
            "iperf_sha256": "a" * 64,
        }
        delivery = {"covered_bins": 600, "expected_bins": 600}
        errors = (
            "unable to receive results: ",
            "unable to receive results: Connection reset by peer",
            "unable to send control message - port may not be available, "
            "the other side may have stopped running, etc.: Broken pipe",
            "control socket has closed unexpectedly",
        )
        for error in errors:
            with self.subTest(error=error):
                document = workload_document(error=error)
                metrics, issues = ANALYZE.workload_completion(
                    axes,
                    document,
                    ANALYZE.iperf_intervals(document),
                    delivery,
                )
                self.assertEqual(issues, [])
                self.assertTrue(metrics["workload_completion_fallback_used"])
                self.assertTrue(metrics["workload_completion_valid"])
                self.assertEqual(metrics["workload_connected_flows"], 16)
                self.assertEqual(metrics["workload_interval_count"], 599)
                self.assertAlmostEqual(
                    metrics["workload_interval_span_fraction"],
                    59.9 / 60,
                )
                self.assertAlmostEqual(
                    metrics["workload_interval_sum_fraction"],
                    59.9 / 60,
                )
                self.assertEqual(metrics["workload_interval_max_gap_s"], 0.0)
                self.assertTrue(
                    metrics["workload_interface_delivery_complete"]
                )
                self.assertTrue(metrics["workload_iperf_version_matches"])
                self.assertTrue(metrics["workload_stderr_empty"])

    def test_interval_completion_fails_closed_on_incomplete_evidence(self) -> None:
        base_axes = {
            "workload_completion": "interval_complete",
            "workload_rc": "1",
            "duration_s": "60",
            "flows": "16",
            "direction": "reverse",
            "iperf_version": "iperf 3.16",
            "iperf_sha256": "a" * 64,
        }
        complete_delivery = {"covered_bins": 600, "expected_bins": 600}

        cases: list[tuple[str, dict[str, str], dict[str, object], dict[str, int], str]] = [
            (
                "wrong error",
                base_axes,
                workload_document(error="unable to connect to server"),
                complete_delivery,
                "final_control_error",
            ),
            (
                "wrong flow count",
                base_axes,
                workload_document(connected_flows=15),
                complete_delivery,
                "connected_flows",
            ),
            (
                "truncated intervals",
                base_axes,
                workload_document(interval_count=590),
                complete_delivery,
                "interval_span",
            ),
            (
                "incomplete interface delivery",
                base_axes,
                workload_document(),
                {"covered_bins": 599, "expected_bins": 600},
                "interface_delivery",
            ),
            (
                "missing iperf identity",
                {key: value for key, value in base_axes.items() if key != "iperf_version"},
                workload_document(),
                complete_delivery,
                "iperf_version",
            ),
            (
                "missing iperf hash",
                {
                    key: value
                    for key, value in base_axes.items()
                    if key != "iperf_sha256"
                },
                workload_document(),
                complete_delivery,
                "iperf_sha256",
            ),
        ]
        gap_document = workload_document()
        gap_interval = gap_document["intervals"][300]["sum_received"]
        gap_interval["start"] += 0.05
        gap_interval["end"] += 0.05
        cases.append(
            (
                "material interval gap",
                base_axes,
                gap_document,
                complete_delivery,
                "interval_gap",
            )
        )
        reordered_document = workload_document()
        reordered_intervals = reordered_document["intervals"]
        reordered_intervals[100], reordered_intervals[200] = (
            reordered_intervals[200],
            reordered_intervals[100],
        )
        cases.append(
            (
                "reordered intervals",
                base_axes,
                reordered_document,
                complete_delivery,
                "interval_order",
            )
        )
        duplicate_document = workload_document()
        duplicate_intervals = duplicate_document["intervals"]
        duplicate_intervals[200] = duplicate_intervals[199]
        cases.append(
            (
                "duplicate intervals",
                base_axes,
                duplicate_document,
                complete_delivery,
                "interval_order",
            )
        )
        duration_document = workload_document()
        duration_document["intervals"][200]["sum_received"]["seconds"] = 0.05
        cases.append(
            (
                "inconsistent interval duration",
                base_axes,
                duration_document,
                complete_delivery,
                "interval_duration",
            )
        )
        cases.append(
            (
                "abnormal exit status",
                {**base_axes, "workload_rc": "137"},
                workload_document(),
                complete_delivery,
                "exit_status",
            )
        )
        cases.append(
            (
                "malformed exit status",
                {**base_axes, "workload_rc": "not-an-integer"},
                workload_document(),
                complete_delivery,
                "exit_status",
            )
        )

        for name, axes, document, delivery, expected_issue in cases:
            with self.subTest(name=name):
                metrics, issues = ANALYZE.workload_completion(
                    axes,
                    document,
                    ANALYZE.iperf_intervals(document),
                    delivery,
                )
                self.assertIn(expected_issue, issues)
                self.assertFalse(metrics["workload_completion_fallback_used"])
                self.assertFalse(metrics["workload_completion_valid"])

        stderr_document = workload_document()
        metrics, issues = ANALYZE.workload_completion(
            base_axes,
            stderr_document,
            ANALYZE.iperf_intervals(stderr_document),
            complete_delivery,
            "segmentation fault",
        )
        self.assertIn("stderr", issues)
        self.assertFalse(metrics["workload_completion_fallback_used"])

    def test_interval_completion_requires_both_bidirectional_series(self) -> None:
        axes = {
            "workload_completion": "interval_complete",
            "workload_rc": "1",
            "duration_s": "60",
            "flows": "16",
            "direction": "bidir",
            "iperf_version": "iperf 3.16",
            "iperf_sha256": "a" * 64,
        }
        delivery = {"covered_bins": 1200, "expected_bins": 1200}
        document = workload_document(
            connected_flows=32,
            bidirectional=True,
        )

        metrics, issues = ANALYZE.workload_completion(
            axes,
            document,
            ANALYZE.iperf_intervals(document),
            delivery,
        )

        self.assertEqual(issues, [])
        self.assertEqual(metrics["workload_connected_flows"], 32)
        self.assertEqual(metrics["workload_bidir_reverse_interval_count"], 599)
        self.assertTrue(metrics["workload_bidir_reverse_interval_shape_valid"])

        missing_reverse = workload_document(
            connected_flows=32,
            bidirectional=True,
        )
        for interval in missing_reverse["intervals"]:
            del interval["sum_bidir_reverse"]
        _, issues = ANALYZE.workload_completion(
            axes,
            missing_reverse,
            ANALYZE.iperf_intervals(missing_reverse),
            delivery,
        )
        self.assertIn("bidir_reverse_interval_shape", issues)
        self.assertIn("bidir_reverse_interval_span", issues)

        missing_primary = workload_document(
            connected_flows=32,
            bidirectional=True,
        )
        for interval in missing_primary["intervals"]:
            del interval["sum"]
        _, issues = ANALYZE.workload_completion(
            axes,
            missing_primary,
            ANALYZE.iperf_intervals(missing_primary),
            delivery,
        )
        self.assertIn("interval_shape", issues)
        self.assertIn("interval_span", issues)

        reordered_reverse = workload_document(
            connected_flows=32,
            bidirectional=True,
        )
        reverse_intervals = reordered_reverse["intervals"]
        left = reverse_intervals[100]["sum_bidir_reverse"]
        right = reverse_intervals[200]["sum_bidir_reverse"]
        reverse_intervals[100]["sum_bidir_reverse"] = right
        reverse_intervals[200]["sum_bidir_reverse"] = left
        _, issues = ANALYZE.workload_completion(
            axes,
            reordered_reverse,
            ANALYZE.iperf_intervals(reordered_reverse),
            delivery,
        )
        self.assertIn("bidir_reverse_interval_order", issues)

    def test_htb_rate_accepts_text_and_json_tc_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "class-pre.json"
            path.write_text(
                "class htb 1:10 root rate 50Mbit ceil 50Mbit\n",
                encoding="ascii",
            )
            self.assertEqual(ANALYZE.htb_rate_mbps(path), 50.0)

            path.write_text(
                json.dumps(
                    [
                        {
                            "kind": "htb",
                            "handle": "1:10",
                            "options": {"rate": 6_250_000},
                        }
                    ]
                ),
                encoding="ascii",
            )
            self.assertEqual(ANALYZE.htb_rate_mbps(path), 50.0)

    def test_qdisc_window_uses_shaped_queue_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)
            start_ns = 1_700_000_000_000_000_000
            rows = [
                {
                    "timestamp": "2023-11-14T22:13:20.000000000Z",
                    "qdisc": [
                        {
                            "kind": "fq_codel",
                            "handle": "30:",
                            "packets": 10_000,
                        },
                        {
                            "kind": "fq_codel",
                            "handle": "20:",
                            "packets": 100,
                            "backlog": 1_000,
                        },
                    ],
                },
                {
                    "timestamp": "2023-11-14T22:13:21.000000000Z",
                    "qdisc": [
                        {
                            "kind": "fq_codel",
                            "handle": "30:",
                            "packets": 20_000,
                        },
                        {
                            "kind": "fq_codel",
                            "handle": "20:",
                            "packets": 140,
                            "backlog": 4_000,
                        },
                    ],
                },
            ]
            (endpoint / "qdisc-series.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="ascii",
            )

            self.assertEqual(
                ANALYZE.qdisc_window_delta(
                    endpoint,
                    "fq_codel",
                    "packets",
                    start_ns,
                    start_ns + 1_000_000_000,
                ),
                40,
            )
            self.assertEqual(
                ANALYZE.qdisc_window_peak(
                    endpoint,
                    "fq_codel",
                    "backlog",
                    start_ns,
                    start_ns + 1_000_000_000,
                ),
                4_000,
            )

    def test_tcp_event_telemetry_requires_complete_well_formed_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)
            (endpoint / "done").touch()
            (endpoint / "clock.txt").write_text(
                "EpochNs=1700000000000000000\nUptimeSeconds=100.0\n",
                encoding="ascii",
            )
            (endpoint / "tcp-events.status").write_text(
                "exit_code=124\nelapsed_ns=10000000000\ncomplete=yes\n",
                encoding="ascii",
            )
            summaries = "".join(
                f"summary,{event},{layer},0,0,0,0,0\n"
                for event in ("rto", "retrans")
                for layer in ("inner", "outer", "competitor")
            )
            (endpoint / "tcp-events.csv").write_text(
                ANALYZE.TCP_EVENTS_HEADER + "\n" + summaries,
                encoding="ascii",
            )

            self.assertEqual(ANALYZE.tcp_event_telemetry_issues(endpoint), [])
            self.assertIn(
                "events_capture_anchor",
                ANALYZE.tcp_event_telemetry_issues(
                    endpoint,
                    require_capture_anchor=True,
                ),
            )

            (endpoint / "tcp-events.status").write_text(
                "exit_code=1\nelapsed_ns=1000000\ncomplete=no\n",
                encoding="ascii",
            )
            self.assertIn(
                "trace_incomplete",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            (endpoint / "tcp-events.status").write_text(
                "exit_code=0\nelapsed_ns=10000000000\ncomplete=yes\n",
                encoding="ascii",
            )
            (endpoint / "tcp-events.csv").write_text(
                ANALYZE.TCP_EVENTS_HEADER + "\n",
                encoding="ascii",
            )
            self.assertIn(
                "events_summary",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

    def test_tcp_event_summary_allows_one_late_raw_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)
            (endpoint / "done").touch()
            (endpoint / "clock.txt").write_text(
                "EpochNs=1700000000000000000\nUptimeSeconds=100.0\n",
                encoding="ascii",
            )
            (endpoint / "tcp-events.status").write_text(
                "exit_code=0\nelapsed_ns=10000000000\ncomplete=yes\n",
                encoding="ascii",
            )
            summaries = "".join(
                f"summary,{event},{layer},0,0,0,0,0\n"
                for event in ("rto", "retrans")
                for layer in ("inner", "outer", "competitor")
            )
            event = "1700000000000000000,retrans,inner,5201,40000,0,0,0\n"
            (endpoint / "tcp-events.csv").write_text(
                ANALYZE.TCP_EVENTS_HEADER + "\n" + event + summaries,
                encoding="ascii",
            )

            self.assertEqual(ANALYZE.tcp_event_telemetry_issues(endpoint), [])

            (endpoint / "tcp-events.csv").write_text(
                ANALYZE.TCP_EVENTS_HEADER
                + "\n"
                + event.replace(",0,0,0", ",2,1,0")
                + summaries,
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_format",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            (endpoint / "tcp-events.csv").write_text(
                ANALYZE.TCP_EVENTS_HEADER + "\n" + event * 2 + summaries,
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_mismatch",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

    def test_tcp_event_per_cpu_summary_requires_exact_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)
            (endpoint / "done").touch()
            (endpoint / "clock.txt").write_text(
                "EpochNs=1700000000000000000\nUptimeSeconds=100.0\n",
                encoding="ascii",
            )
            (endpoint / "tcp-events.status").write_text(
                "exit_code=0\nelapsed_ns=10000000000\ncomplete=yes\n",
                encoding="ascii",
            )
            marker = "summary,format,per_cpu_count,1,0,0,0,0\n"
            event = "1700000000000000000,rto,inner,5201,40000,0,0,0\n"
            aggregate = "@event_counts[1, 1]: 2\n"
            trace = ANALYZE.TCP_EVENTS_HEADER + "\n" + event * 2 + marker + aggregate
            (endpoint / "tcp-events.csv").write_text(trace, encoding="ascii")

            self.assertEqual(ANALYZE.tcp_event_telemetry_issues(endpoint), [])

            (endpoint / "tcp-events.csv").write_text(
                trace.replace(",0,0,0\n", ",2,1,0\n"),
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_format",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            (endpoint / "tcp-events.csv").write_text(
                trace.replace(": 2", ": 1"),
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_mismatch",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            (endpoint / "tcp-events.csv").write_text(
                trace.replace(marker, marker * 2),
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_format",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            (endpoint / "tcp-events.csv").write_text(
                trace.replace(marker, ""),
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_format",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            legacy = "summary,rto,inner,2,0,0,0,0\n"
            (endpoint / "tcp-events.csv").write_text(
                trace + legacy,
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_format",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            (endpoint / "tcp-events.csv").write_text(
                trace + "@event_counts[1, 1]: 2\n",
                encoding="ascii",
            )
            self.assertTrue(
                any(
                    issue.startswith("events_malformed_line_")
                    for issue in ANALYZE.tcp_event_telemetry_issues(endpoint)
                )
            )

    def test_tcp_event_cpu_sequences_require_continuous_detail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)
            (endpoint / "done").touch()
            (endpoint / "clock.txt").write_text(
                "EpochNs=1700000000000000000\nUptimeSeconds=100.0\n",
                encoding="ascii",
            )
            (endpoint / "tcp-events.status").write_text(
                "exit_code=0\nelapsed_ns=10000000000\ncomplete=yes\n",
                encoding="ascii",
            )
            marker = "summary,format,cpu_sequence,1,0,0,0,0\n"
            events = (
                "1700000000000000000,rto,inner,5201,40000,2,1,0\n"
                "1700000000000000001,rto,inner,5201,40001,4,1,0\n"
                "1700000000000000002,rto,inner,5201,40002,2,2,0\n"
            )
            aggregates = (
                "@event_sequences[1, 1, 2]: 2\n"
                "@event_sequences[1, 1, 4]: 1\n"
            )
            trace = (
                ANALYZE.TCP_EVENTS_HEADER
                + "\n"
                + events
                + marker
                + aggregates
            )
            (endpoint / "tcp-events.csv").write_text(trace, encoding="ascii")

            self.assertEqual(ANALYZE.tcp_event_telemetry_issues(endpoint), [])

            (endpoint / "tcp-events.csv").write_text(
                trace.replace(
                    "@event_sequences[1, 1, 2]: 2",
                    "@event_sequences[1, 1, 2]: "
                    + "1"
                    + "0" * 100,
                ),
                encoding="ascii",
            )
            self.assertIn(
                "events_sequence_mismatch",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

            last_event = (
                "1700000000000000002,rto,inner,5201,40002,2,2,0\n"
            )
            for malformed in (
                trace.replace(last_event, last_event.replace(",2,2,0", ",2,3,0")),
                trace.replace(last_event, last_event.replace(",2,2,0", ",2,1,0")),
                trace.replace(last_event, ""),
                trace.replace("[1, 1, 2]: 2", "[1, 1, 2]: 3"),
                trace.replace(last_event, last_event.replace(",2,2,0", ",2,2,1")),
                trace.replace(
                    events,
                    (
                        "1700000000000000002,rto,inner,5201,40002,2,2,0\n"
                        "1700000000000000001,rto,inner,5201,40001,4,1,0\n"
                        "1700000000000000000,rto,inner,5201,40000,2,1,0\n"
                    ),
                ),
            ):
                (endpoint / "tcp-events.csv").write_text(
                    malformed,
                    encoding="ascii",
                )
                self.assertIn(
                    "events_sequence_mismatch",
                    ANALYZE.tcp_event_telemetry_issues(endpoint),
                )

            (endpoint / "tcp-events.csv").write_text(
                trace.replace(marker, ""),
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_format",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

    def test_tcp_event_capture_anchor_is_attached_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)
            (endpoint / "done").touch()
            (endpoint / "clock.txt").write_text(
                "EpochNs=1700000000000000000\nUptimeSeconds=100.0\n",
                encoding="ascii",
            )
            (endpoint / "tcp-events.status").write_text(
                "exit_code=0\n"
                "elapsed_ns=10000000000\n"
                "complete=yes\n"
                "capture_duration_s=9\n"
                "quiescence_s=1\n"
                "cutoff_anchor=attached_command\n"
                "capture_marker_count=1\n",
                encoding="ascii",
            )
            start = 100_000_000_000
            cutoff = start + 9_000_000_000
            marker = f"{start},capture,meta,9,0,{cutoff},0,0\n"
            summaries = "".join(
                f"summary,{event},{layer},0,0,0,0,0\n"
                for event in ("rto", "retrans")
                for layer in ("inner", "outer", "competitor")
            )
            (endpoint / "tcp-events.csv").write_text(
                ANALYZE.TCP_EVENTS_HEADER + "\n" + marker + summaries,
                encoding="ascii",
            )

            self.assertEqual(
                ANALYZE.tcp_event_telemetry_issues(
                    endpoint,
                    require_capture_anchor=True,
                ),
                [],
            )

            late = f"{cutoff + 1},retrans,inner,40000,5201,0,0,0\n"
            late_summaries = summaries.replace(
                "summary,retrans,inner,0,0,0,0,0",
                "summary,retrans,inner,1,0,0,0,0",
            )
            (endpoint / "tcp-events.csv").write_text(
                ANALYZE.TCP_EVENTS_HEADER
                + "\n"
                + marker
                + late
                + late_summaries,
                encoding="ascii",
            )
            self.assertIn(
                "events_capture_window",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

    def test_tcp_event_summaries_use_cpu_sequences(self) -> None:
        for event_id in (1, 2):
            for layer_id in (1, 2, 3):
                self.assertIn(
                    f"@event_sequences[{event_id}, {layer_id}, $event_cpu]",
                    TCP_EVENTS,
                )
        self.assertNotIn("@event_counts", TCP_EVENTS)
        self.assertIn("$event_cpu = cpu;", TCP_EVENTS)
        self.assertIn(
            'printf("summary,format,cpu_sequence,1,0,0,0,0\\n");',
            TCP_EVENTS,
        )
        self.assertNotIn("print(@event_sequences);", TCP_EVENTS)
        self.assertNotIn("clear(@event_sequences);", TCP_EVENTS)

    def test_tcp_event_cutoff_precedes_every_probe_mutation(self) -> None:
        self.assertEqual(ANALYZE.MAX_TRACE_SUMMARY_LAG, 1)
        self.assertIn(
            "@capture_until_ns = @capture_start_ns + $1 * 1000000000;",
            TCP_EVENTS,
        )
        anchor_start = TCP_EVENTS.index("tracepoint:syscalls:sys_enter_execve")
        first_data_probe = TCP_EVENTS.index("tracepoint:tcp:tcp_retransmit_skb")
        anchor = TCP_EVENTS[anchor_start:first_data_probe]
        self.assertIn("pid == cpid && @capture_started == 0", anchor)
        self.assertIn(",capture,meta,", anchor)
        self.assertLess(
            anchor.index("@capture_until_ns ="),
            anchor.index("@capture_started = 1;"),
        )
        probe_starts = [
            match.start()
            for match in re.finditer(
                r"(?m)^(?:tracepoint:tcp|kprobe:tcp)",
                TCP_EVENTS,
            )
        ]
        self.assertEqual(len(probe_starts), 5)
        for index, start in enumerate(probe_starts):
            end = (
                probe_starts[index + 1]
                if index + 1 < len(probe_starts)
                else TCP_EVENTS.index("\nEND\n", start)
            )
            block = TCP_EVENTS[start:end]
            guard = block.index(
                "if (@capture_started && $now <= @capture_until_ns) {"
            )
            mutations = [
                match.start()
                for match in re.finditer(
                    r"@\w+(?:\[[^\n]+\])?\s*(?:\+\+|=)|printf\(\"%llu",
                    block,
                )
            ]
            self.assertTrue(mutations)
            self.assertTrue(all(guard < mutation for mutation in mutations))
        self.assertIn("capture_duration=$((DURATION - 1))", SAMPLER)
        self.assertIn('"$capture_duration" \\', SAMPLER)
        self.assertIn("printf 'quiescence_s=1\\n'", SAMPLER)
        self.assertIn("cutoff_anchor=attached_command", SAMPLER)
        self.assertIn("for _ in {1..250}; do", SAMPLER)

    def test_kernel_anomalies_match_colon_terminated_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary)
            (endpoint / "kernel.log").write_text(
                "BUG: unable to handle page fault\n"
                "Oops: 0000 [#1]\n"
                "WARNING: CPU: 0 PID: 1 at test.c:1\n",
                encoding="ascii",
            )
            self.assertEqual(len(ANALYZE.kernel_anomalies(endpoint)), 3)

    def test_campaign_refuses_empty_or_unmarked_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cells").mkdir()
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                result = ANALYZE.campaign(
                    root, root / "cells.csv", root / "REPORT.md"
                )
            self.assertEqual(result, 1)
            self.assertFalse((root / "REPORT.md").exists())

            cell = root / "cells" / "queue-test-tcp-r1"
            cell.mkdir()
            (cell / "cell.json").write_text(
                json.dumps(
                    {
                        "cell_id": cell.name,
                        "valid": False,
                        "classification": "invalid",
                    }
                ),
                encoding="ascii",
            )
            with contextlib.redirect_stderr(output):
                result = ANALYZE.campaign(
                    root, root / "cells.csv", root / "REPORT.md"
                )
            self.assertEqual(result, 1)
            self.assertFalse((root / "REPORT.md").exists())

    def test_campaign_requires_manifest_to_match_completed_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cell = root / "cells" / "queue-test-tcp-r1"
            cell.mkdir(parents=True)
            campaign_fingerprint = "b" * 64
            cell_fingerprint = "a" * 64
            (cell / "cell.json").write_text(
                json.dumps(
                    {
                        "cell_id": cell.name,
                        "valid": False,
                        "classification": "invalid",
                        "axes": {},
                        "metrics": {},
                    }
                ),
                encoding="ascii",
            )
            (cell / "cell.env").write_text(
                f"campaign_fingerprint={campaign_fingerprint}\n"
                f"cell_fingerprint={cell_fingerprint}\n",
                encoding="ascii",
            )
            (cell / "cell.fingerprint").write_text(
                cell_fingerprint + "\n", encoding="ascii"
            )
            (cell / "cell.complete").touch()
            with contextlib.redirect_stderr(io.StringIO()):
                result = ANALYZE.campaign(
                    root, root / "cells.csv", root / "REPORT.md"
                )
            self.assertEqual(result, 1)
            self.assertFalse((root / "REPORT.md").exists())

            (root / "campaign-status.json").write_text(
                json.dumps(
                    {
                        "status": "ready",
                        "expected_cells": [cell.name],
                        "failed_cells": [],
                        "campaign_fingerprint": campaign_fingerprint,
                        "cell_fingerprints": {
                            cell.name: cell_fingerprint,
                        },
                    }
                ),
                encoding="ascii",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                result = ANALYZE.campaign(
                    root, root / "cells.csv", root / "REPORT.md"
                )
            self.assertEqual(result, 0)
            self.assertTrue((root / "cells.csv").exists())
            self.assertTrue((root / "REPORT.md").exists())

    def test_competitor_requires_successful_full_duration_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            (cell / "competitor-iperf3.json").write_text(
                json.dumps(
                    {
                        "end": {
                            "sum_received": {
                                "bytes": 15_000_000,
                                "seconds": 15.0,
                            }
                        }
                    }
                ),
                encoding="ascii",
            )
            axes = {
                "competitor": "1",
                "competitor_rc": "0",
                "duration_s": "10",
                "warmup_s": "5",
            }

            metrics, issues = ANALYZE.competitor_workload(cell, axes)

            self.assertEqual(issues, [])
            self.assertEqual(metrics["competitor_seconds"], 15.0)
            self.assertGreater(metrics["competitor_goodput_mbps"], 0)

            axes["competitor_rc"] = "1"
            _, issues = ANALYZE.competitor_workload(cell, axes)
            self.assertIn("exit_status", issues)

    def test_carrier_stability_requires_two_unchanged_tuples(self) -> None:
        stable_text = (
            "--- 1700000000.0 ---\n"
            "ESTAB 0 0 10.0.0.1:51821 10.0.0.2:40000\n"
            "\t cubic rto:200\n"
            "ESTAB 0 0 10.0.0.1:50000 10.0.0.2:51821\n"
            "--- 1700000000.2 ---\n"
            "ESTAB 0 0 10.0.0.1:51821 10.0.0.2:40000\n"
            "ESTAB 0 0 10.0.0.1:50000 10.0.0.2:51821\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ss-series.txt"
            path.write_text(stable_text, encoding="ascii")
            path.with_name("ss-series.status").write_text(
                "exit_code=0\ncomplete=yes\n", encoding="ascii"
            )
            stable = ANALYZE.tcp_carrier_stability(path)
            self.assertTrue(stable["stable_dual_carrier"])
            self.assertEqual(stable["tuple_changes"], 0)

            path.write_text(
                stable_text.split("--- 1700000000.2 ---", 1)[0],
                encoding="ascii",
            )
            one_sample = ANALYZE.tcp_carrier_stability(path)
            self.assertFalse(one_sample["stable_dual_carrier"])

            path.write_text(
                stable_text.replace(
                    "10.0.0.1:50000 10.0.0.2:51821\n",
                    "10.0.0.1:50001 10.0.0.2:51821\n",
                    1,
                ),
                encoding="ascii",
            )
            changed = ANALYZE.tcp_carrier_stability(path)
            self.assertFalse(changed["stable_dual_carrier"])
            self.assertEqual(changed["tuple_changes"], 1)

    def test_tcp_below_half_of_matched_udp_is_degraded(self) -> None:
        docs = [
            {
                "cell_id": "queue-q05-tcp-r1",
                "valid": True,
                "classification": "stable",
                "metrics": {"goodput_mbps": 20.0},
                "conditions": {},
            },
            {
                "cell_id": "queue-q05-udp-r1",
                "valid": True,
                "classification": "stable",
                "metrics": {"goodput_mbps": 45.0},
                "conditions": {},
            },
        ]

        ANALYZE.apply_udp_control_comparison(docs)

        self.assertEqual(docs[0]["classification"], "degraded")
        self.assertAlmostEqual(
            docs[0]["metrics"]["udp_control_goodput_ratio"], 20.0 / 45.0
        )
        self.assertTrue(docs[0]["conditions"]["below_half_udp_control"])

    def test_orchestrator_publishes_cells_only_after_cleanup(self) -> None:
        finally_index = ORCHESTRATOR.index("    } finally {")
        publish_index = ORCHESTRATOR.index(
            '(Join-Path $localCell "cell.json")', finally_index
        )
        complete_index = ORCHESTRATOR.index(
            '(Join-Path $localCell "cell.complete")', publish_index
        )
        self.assertLess(finally_index, publish_index)
        self.assertLess(publish_index, complete_index)
        self.assertIn(
            "$competitorDuration = [int]$Row.duration_s + [int]$Row.warmup_s + 5",
            ORCHESTRATOR,
        )
        self.assertIn('Write-CampaignStatus "incomplete"', ORCHESTRATOR)
        self.assertIn("Get-CampaignSourceFingerprint", ORCHESTRATOR)
        self.assertIn('"cell.fingerprint"', ORCHESTRATOR)
        self.assertIn("loaded module or host build identities differ", ORCHESTRATOR)
        self.assertIn('-c "sleep $DURATION"', SAMPLER)
        self.assertIn('$workloadCompletion = "strict"', ORCHESTRATOR)
        self.assertIn(
            '"workload_completion=$workloadCompletion"',
            ORCHESTRATOR,
        )
        self.assertIn(
            '"iperf_version=$runtimeIperfVersion"',
            ORCHESTRATOR,
        )
        self.assertIn(
            '"iperf_sha256=$runtimeIperfHash"',
            ORCHESTRATOR,
        )
        self.assertIn(
            "$runtimeIperfVersionA -ne $runtimeIperfVersionB",
            ORCHESTRATOR,
        )
        self.assertIn(
            "$runtimeIperfHashA -ne $runtimeIperfHashB",
            ORCHESTRATOR,
        )
        self.assertIn("/usr/bin/iperf3 -c $targetIp", ORCHESTRATOR)
        self.assertIn(
            "grep -Fq 'path=/usr/bin/iperf3 ;'",
            ORCHESTRATOR,
        )
        self.assertIn("sudo readlink -f /proc/`$pid/exe", ORCHESTRATOR)
        self.assertIn("sudo sha256sum /proc/`$pid/exe", ORCHESTRATOR)
        self.assertIn("set -e; sudo systemctl restart $unit", ORCHESTRATOR)
        self.assertIn(
            '"wgtcp-meltdown-iperf-competitor.service" $runtimeIperfHash',
            ORCHESTRATOR,
        )
        self.assertIn(
            'Get-EndpointIdentityVerificationCommand "wgtcp-amp-b" $PrivateIpA',
            ORCHESTRATOR,
        )
        self.assertIn(
            'Get-EndpointIdentityVerificationCommand "wgtcp-amp-a" $PrivateIpB',
            ORCHESTRATOR,
        )
        self.assertIn('$expectedPrivateIpA = "10.20.1.6"', ORCHESTRATOR)
        self.assertIn('$expectedPrivateIpB = "10.20.1.7"', ORCHESTRATOR)
        self.assertIn("Get-TopologyVerificationCommand", ORCHESTRATOR)
        self.assertIn(
            '$PrivateIpA "10.99.1.1" "10.99.1.2" "10.99.0.1" "10.99.0.2"',
            ORCHESTRATOR,
        )
        self.assertIn(
            '$PrivateIpB "10.99.1.2" "10.99.1.1" "10.99.0.2" "10.99.0.1"',
            ORCHESTRATOR,
        )
        self.assertIn(
            '$workloadRcPath = Join-Path $localCell "workload.rc"',
            ORCHESTRATOR,
        )
        self.assertGreaterEqual(ORCHESTRATOR.count('"missing"'), 2)
        self.assertIn(
            'Wait-RemoteFiles "$remoteCellA/ready" "$remoteCellB/client/ready" 30',
            ORCHESTRATOR,
        )
        self.assertIn("matrix_expected_cells", ORCHESTRATOR)
        self.assertIn("qualifying_complete", ORCHESTRATOR)
        self.assertIn(
            "$sampleDuration = [int]$Row.duration_s + [int]$Row.warmup_s + 30",
            ORCHESTRATOR,
        )
        self.assertIn("[string[]] $Cell = @()", ORCHESTRATOR)
        self.assertIn("$selectedCells.Contains($cellId)", ORCHESTRATOR)
        restart_index = ORCHESTRATOR.index(
            '"wgtcp-meltdown-iperf-inner.service" $runtimeIperfHash'
        )
        sampler_index = ORCHESTRATOR.index(
            "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $serverUnit)"
        )
        self.assertLess(restart_index, sampler_index)
        topology_index = ORCHESTRATOR.index(
            '$PrivateIpA "10.99.1.1" "10.99.1.2" "10.99.0.1" "10.99.0.2"'
        )
        runtime_index = ORCHESTRATOR.index("$loadedSrcA = @(")
        self.assertLess(topology_index, runtime_index)
        identity_index = ORCHESTRATOR.index(
            'Get-EndpointIdentityVerificationCommand "wgtcp-amp-b" $PrivateIpA'
        )
        package_index = ORCHESTRATOR.index(
            '$archive = Join-Path $env:TEMP "wgtcp-meltdown-$PID.tar.gz"'
        )
        self.assertLess(identity_index, package_index)

    def test_sampler_emits_one_json_object_per_qdisc_sample(self) -> None:
        self.assertIn(
            'qdisc_json="$(tc -s -j qdisc show dev "$IFACE" '
            '2>/dev/null || printf \'[]\')"',
            SAMPLER,
        )
        self.assertIn(
            """printf '{"timestamp":"%s","qdisc":%s}\\n'""",
            SAMPLER,
        )

    def test_shaper_keeps_cleanup_trap_through_status_capture(self) -> None:
        status_index = SHAPER.rindex('tc -s -j qdisc show dev "$IFB"')
        release_index = SHAPER.index("trap - EXIT", status_index)
        self.assertLess(status_index, release_index)


if __name__ == "__main__":
    unittest.main()
