#!/usr/bin/env python3
"""Behavioral tests for the TCP meltdown result analyzer."""

from __future__ import annotations

import contextlib
import csv
from datetime import datetime, timezone
import hashlib
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
TIMED_IMPAIRMENT = (
    ROOT / "perf-test" / "meltdown" / "harness" / "timed-impairment.py"
).read_text(encoding="utf-8")
SYNCHRONIZED_SETUP = (
    ROOT / "perf-test" / "meltdown" / "harness" / "synchronized-setup.sh"
).read_text(encoding="utf-8")
QUALIFY_CARRIERS = (
    ROOT / "perf-test" / "meltdown" / "harness" / "qualify-carriers.sh"
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
BURST_TRANSPORT_QUALIFIED_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-mechanism-burst-transport-qualified.csv"
)
BURST_BREADTH_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-mechanism-burst-breadth.csv"
)
BOUNDARY_SMOKE_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-boundary-smoke.csv"
)
BOUNDARY_CORRELATION_MATRIX = (
    ROOT / "perf-test" / "meltdown" / "matrix-boundary-correlation.csv"
)
BOUNDARY_CORRELATION_REPLICATION_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-boundary-correlation-replication.csv"
)
BOUNDARY_CORRELATION_RT_REPLICATION_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-boundary-correlation-replication-rt.csv"
)
BOUNDARY_CORRELATION_RT2_REPLICATION_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-boundary-correlation-replication-rt2.csv"
)
BOUNDARY_CORRELATION_RT3_REPLICATION_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-boundary-correlation-replication-rt3.csv"
)
BOUNDARY_CORRELATION_RT4_REPLICATION_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-boundary-correlation-replication-rt4.csv"
)
CARRIER_STABILITY_DIAGNOSTIC_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-carrier-stability-diagnostic-ct1.csv"
)
CARRIER_STABILITY_DIAGNOSTIC_CT2_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-carrier-stability-diagnostic-ct2.csv"
)
CARRIER_STABILITY_DIAGNOSTIC_CT3_MATRIX = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "matrix-carrier-stability-diagnostic-ct3.csv"
)
CARRIER_STABILITY_DIAGNOSTIC_CT3_PROTOCOL = (
    ROOT / "perf-test" / "meltdown" / "CARRIER_STABILITY_DIAGNOSTIC_CT3.md"
).read_text(encoding="utf-8")
CARRIER_STABILITY_DIAGNOSTIC_CT2_PROTOCOL = (
    ROOT / "perf-test" / "meltdown" / "CARRIER_STABILITY_DIAGNOSTIC_CT2.md"
).read_text(encoding="utf-8")
CARRIER_STABILITY_DIAGNOSTIC = (
    ROOT / "perf-test" / "meltdown" / "harness" / "diagnose-carrier-stability.sh"
).read_text(encoding="utf-8")
CARRIER_STABILITY_DIAGNOSTIC_RESULT = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "results"
    / "2026-07-23-carrier-stability-ct1"
)
CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "results"
    / "2026-07-24-carrier-stability-ct2"
)
CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT = (
    ROOT
    / "perf-test"
    / "meltdown"
    / "results"
    / "2026-07-24-carrier-stability-ct3"
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
    def test_published_axes_bind_campaign_and_cell_fingerprints(self) -> None:
        self.assertEqual(
            ANALYZE.PUBLISHED_AXIS_FIELDS[-2:],
            ("campaign_fingerprint", "cell_fingerprint"),
        )

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

    def test_burst_transport_qualified_matrix_is_paired_and_bounded(self) -> None:
        with BURST_TRANSPORT_QUALIFIED_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(int(row["repetitions"]) for row in rows), 4)
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual(
            {row["stage"] for row in rows},
            {"burst-transport-qualified-smoke"},
        )
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
        self.assertEqual(
            {row["impairment_validation"] for row in rows},
            {"transport_aware"},
        )
        self.assertEqual({row["inner_cc"] for row in rows}, {"cubic"})
        self.assertEqual({row["direction"] for row in rows}, {"reverse"})
        self.assertEqual({row["competitor"] for row in rows}, {"0"})

    def test_burst_breadth_matrix_is_paired_and_bounded(self) -> None:
        with BURST_BREADTH_MATRIX.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(int(row["repetitions"]) for row in rows), 20)
        self.assertEqual({row["enabled"] for row in rows}, {"1"})
        self.assertEqual({row["stage"] for row in rows}, {"burst-breadth"})
        self.assertEqual({row["tunnel"] for row in rows}, {"tcp", "udp"})
        self.assertEqual({row["rate_mbps"] for row in rows}, {"50"})
        self.assertEqual({row["queue_bdp"] for row in rows}, {"1"})
        self.assertEqual({row["queue_kind"] for row in rows}, {"bfifo"})
        self.assertEqual({row["flows"] for row in rows}, {"16"})
        self.assertEqual({row["duration_s"] for row in rows}, {"60"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"5"})
        self.assertEqual(
            {row["workload_completion"] for row in rows},
            {"interval_complete"},
        )
        self.assertEqual(
            {row["impairment_validation"] for row in rows},
            {"transport_aware"},
        )
        self.assertEqual({row["inner_cc"] for row in rows}, {"cubic"})
        self.assertEqual({row["direction"] for row in rows}, {"reverse"})
        self.assertEqual({row["competitor"] for row in rows}, {"0"})

        actual = [
            (
                row["name"],
                row["tunnel"],
                row["rtt_ms"],
                row["loss_model"],
                row["loss_pct"],
                row["burst_p"],
                row["burst_r"],
                row["burst_h"],
                row["burst_k"],
                row["repetitions"],
            )
            for row in rows
        ]
        self.assertEqual(
            actual,
            [
                (
                    "random7p5-r200-q1-16f",
                    "tcp",
                    "200",
                    "random",
                    "7.5",
                    "0",
                    "0",
                    "0",
                    "0",
                    "2",
                ),
                (
                    "random7p5-r200-q1-16f",
                    "udp",
                    "200",
                    "random",
                    "7.5",
                    "0",
                    "0",
                    "0",
                    "0",
                    "2",
                ),
                (
                    "ge1-25-90-1-r200-q1-16f",
                    "tcp",
                    "200",
                    "gemodel",
                    "0",
                    "1",
                    "25",
                    "90",
                    "1",
                    "2",
                ),
                (
                    "ge1-25-90-1-r200-q1-16f",
                    "udp",
                    "200",
                    "gemodel",
                    "0",
                    "1",
                    "25",
                    "90",
                    "1",
                    "2",
                ),
                (
                    "ge1-12p5-90-1-r200-q1-16f",
                    "tcp",
                    "200",
                    "gemodel",
                    "0",
                    "1",
                    "12.5",
                    "90",
                    "1",
                    "2",
                ),
                (
                    "ge1-12p5-90-1-r200-q1-16f",
                    "udp",
                    "200",
                    "gemodel",
                    "0",
                    "1",
                    "12.5",
                    "90",
                    "1",
                    "2",
                ),
                (
                    "ge2-25-90-1-r400-q1-16f",
                    "tcp",
                    "400",
                    "gemodel",
                    "0",
                    "2",
                    "25",
                    "90",
                    "1",
                    "2",
                ),
                (
                    "ge2-25-90-1-r400-q1-16f",
                    "udp",
                    "400",
                    "gemodel",
                    "0",
                    "2",
                    "25",
                    "90",
                    "1",
                    "2",
                ),
                (
                    "ge4-25-90-1-r200-q1-16f",
                    "tcp",
                    "200",
                    "gemodel",
                    "0",
                    "4",
                    "25",
                    "90",
                    "1",
                    "2",
                ),
                (
                    "ge4-25-90-1-r200-q1-16f",
                    "udp",
                    "200",
                    "gemodel",
                    "0",
                    "4",
                    "25",
                    "90",
                    "1",
                    "2",
                ),
            ],
        )

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

            write_counters("ifb-qdisc-post.json", 1080, 30)
            self.assertEqual(
                ANALYZE.netem_counter_issues(endpoint, axes),
                ["netem_loss_rate"],
            )
            transport_axes = {
                **axes,
                "tunnel": "tcp",
                "impairment_validation": "transport_aware",
            }
            self.assertEqual(
                ANALYZE.netem_counter_issues(endpoint, transport_axes),
                [],
            )
            transport_axes["tunnel"] = "udp"
            self.assertEqual(
                ANALYZE.netem_counter_issues(endpoint, transport_axes),
                ["netem_loss_rate"],
            )

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

    def test_transport_aware_ping_preserves_tcp_rtt_amplification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)

            def write_ping(
                name: str,
                loss: float,
                mean_rtt: float,
                transmitted: int = 10,
                received: int = 10,
            ) -> None:
                (cell / name).write_text(
                    f"{transmitted} packets transmitted, {received} received, "
                    f"{loss:g}% packet loss\n"
                    f"rtt min/avg/max/mdev = 0.1/{mean_rtt:g}/1.0/0.1 ms\n",
                    encoding="ascii",
                )

            write_ping("preimpairment-ping.txt", 0, 0.4)
            write_ping("preflight-ping.txt", 0, 600)
            axes = {
                "tunnel": "tcp",
                "rtt_ms": "200",
                "impairment_validation": "transport_aware",
            }
            metrics, issues = ANALYZE.impairment_ping_validation(cell, axes)
            self.assertEqual(issues, [])
            self.assertTrue(metrics["baseline_preflight_valid"])
            self.assertTrue(metrics["impaired_ping_rtt_valid"])
            baseline, valid = ANALYZE.baseline_preflight(
                cell / "preimpairment-ping.txt"
            )
            self.assertTrue(valid)
            self.assertTrue(baseline["baseline_preflight_valid"])

            _, strict_issues = ANALYZE.impairment_ping_validation(
                cell,
                {**axes, "impairment_validation": "strict"},
            )
            self.assertEqual(strict_issues, ["rtt_not_achieved"])

            _, udp_issues = ANALYZE.impairment_ping_validation(
                cell,
                {**axes, "tunnel": "udp"},
            )
            self.assertEqual(udp_issues, ["rtt_not_achieved"])

            write_ping("preimpairment-ping.txt", 10, 0.4)
            _, baseline_issues = ANALYZE.impairment_ping_validation(cell, axes)
            self.assertEqual(baseline_issues, ["baseline_preflight"])
            _, valid = ANALYZE.baseline_preflight(cell / "preimpairment-ping.txt")
            self.assertFalse(valid)

            write_ping("preimpairment-ping.txt", 0, 0.4, 9, 9)
            _, baseline_issues = ANALYZE.impairment_ping_validation(cell, axes)
            self.assertEqual(baseline_issues, ["baseline_preflight"])

            write_ping("preimpairment-ping.txt", 0, 0.4)
            _, policy_issues = ANALYZE.impairment_ping_validation(
                cell,
                {**axes, "impairment_validation": "transport_aware "},
            )
            self.assertEqual(
                policy_issues,
                ["impairment_validation_policy", "rtt_not_achieved"],
            )

    def test_transport_aware_preflight_precedes_impairment(self) -> None:
        policy = ORCHESTRATOR.index(
            'if ($impairmentValidation -eq "transport_aware")'
        )
        baseline = ORCHESTRATOR.index("preimpairment-ping.txt", policy)
        validation = ORCHESTRATOR.index("$baselinePreflight =", baseline)
        shape = ORCHESTRATOR.index("$serverShaped = $true", baseline)
        self.assertLess(baseline, shape)
        self.assertLess(validation, shape)
        self.assertIn('"safety_stopped"', ORCHESTRATOR)
        self.assertIn('"safety baseline failed:', ORCHESTRATOR)
        self.assertIn('"safety shaping failed:', ORCHESTRATOR)
        self.assertIn('"safety runtime identity failed:', ORCHESTRATOR)
        self.assertIn("Write-CampaignSafetyStop", ORCHESTRATOR)
        self.assertIn("campaign_fingerprint = $CampaignFingerprint", ORCHESTRATOR)
        self.assertIn("Assert-ExistingCampaignIdentity", ORCHESTRATOR)
        self.assertIn(
            "existing campaign identity or selection differs; use a fresh directory",
            ORCHESTRATOR,
        )
        self.assertIn(
            "existing incomplete or mismatched artifacts for $cellId",
            ORCHESTRATOR,
        )
        self.assertIn(
            "existing campaign contains partial cell evidence; use a fresh directory",
            ORCHESTRATOR,
        )
        self.assertIn(
            "existing manifest completion state differs from cell evidence",
            ORCHESTRATOR,
        )
        self.assertIn('"cell.env"', ORCHESTRATOR)
        self.assertIn("$_.Name -ceq $cellId", ORCHESTRATOR)
        self.assertNotIn(
            "Remove-Item -Recurse -Force $localCell",
            ORCHESTRATOR,
        )
        self.assertIn('--exclude="__pycache__"', ORCHESTRATOR)
        self.assertIn('$_.Extension -notin @(".pyc", ".pyo")', ORCHESTRATOR)
        latch = ORCHESTRATOR.index(
            "Test-Path -LiteralPath $campaignSafetyStopPath"
        )
        results_initialization = ORCHESTRATOR.index(
            "New-Item -ItemType Directory -Force -Path "
            "(Join-Path $ResultsDir \"cells\")"
        )
        self.assertLess(latch, results_initialization)
        self.assertIn('"shape_restoration"', ORCHESTRATOR)
        self.assertIn('"unstable_tcp_carriers"', ORCHESTRATOR)
        self.assertIn(
            '"impairment_validation=$impairmentValidation"',
            ORCHESTRATOR,
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

    def test_zero_delivery_runs_preserve_exact_bin_boundaries(self) -> None:
        runs = ANALYZE.zero_delivery_runs(
            [0.0, 0.0, 8000.0, 0.0, 16000.0, 0.0, 0.0, 0.0],
            measurement_start_ns=1_000_000_000,
        )

        self.assertEqual(
            runs,
            [
                {
                    "start_bin": 0,
                    "end_bin_exclusive": 2,
                    "start_ns": 1_000_000_000,
                    "end_ns": 1_200_000_000,
                    "start_s": 0.0,
                    "end_s": 0.2,
                    "duration_ms": 200,
                    "left_censored": True,
                    "right_censored": False,
                },
                {
                    "start_bin": 3,
                    "end_bin_exclusive": 4,
                    "start_ns": 1_300_000_000,
                    "end_ns": 1_400_000_000,
                    "start_s": 0.3,
                    "end_s": 0.4,
                    "duration_ms": 100,
                    "left_censored": False,
                    "right_censored": False,
                },
                {
                    "start_bin": 5,
                    "end_bin_exclusive": 8,
                    "start_ns": 1_500_000_000,
                    "end_ns": 1_800_000_000,
                    "start_s": 0.5,
                    "end_s": 0.8,
                    "duration_ms": 300,
                    "left_censored": False,
                    "right_censored": True,
                },
            ],
        )

    def test_dynamic_episode_metrics_measure_recovery_and_deficit(self) -> None:
        measurement_start_ns = 1_000_000_000
        impairment_start_ns = measurement_start_ns + 15_000_000_000
        impairment_stop_ns = impairment_start_ns + 2_000_000_000
        recovery_start_ns = impairment_stop_ns
        values = (
            [40_000_000.0] * 150
            + [0.0] * 20
            + [10_000_000.0] * 30
            + [40_000_000.0] * 570
        )
        events = [
            {
                "timestamp_ns": impairment_start_ns + 500_000_000,
                "event": "retrans",
                "layer": "outer",
            }
        ]

        metrics, issues = ANALYZE.dynamic_episode_metrics(
            values,
            measurement_start_ns,
            measurement_start_ns + 77_000_000_000,
            impairment_start_ns,
            impairment_stop_ns,
            recovery_start_ns,
            events,
            "tcp",
        )

        self.assertEqual(issues, [])
        self.assertEqual(metrics["pre_median_mbps"], 40.0)
        self.assertEqual(metrics["impairment_mean_mbps"], 0.0)
        self.assertEqual(metrics["episode_longest_stall_ms"], 2000)
        self.assertEqual(metrics["episode_min_5s_mbps"], 6.0)
        self.assertEqual(metrics["recovery_90_ms"], 2400.0)
        self.assertFalse(metrics["recovery_90_right_censored"])
        self.assertTrue(metrics["mechanism_observed"])
        self.assertTrue(metrics["user_visible_disruption"])
        self.assertTrue(metrics["episode_below_half_pre"])
        self.assertAlmostEqual(metrics["bandwidth_deficit_mbit"], 170.0)

    def test_timed_impairment_evidence_validates_schedule_and_epoch_counters(
        self,
    ) -> None:
        scheduled_start_ns = 20_000_000_000
        scheduled_stop_ns = 22_000_000_000

        def netem(
            packets: int,
            drops: int,
            impaired: bool,
        ) -> dict[str, object]:
            options: dict[str, object] = {
                "limit": 100000,
                "delay": {
                    "delay": 0.1,
                    "jitter": 0,
                    "correlation": 0,
                },
                "ecn": False,
                "gap": 0,
            }
            if impaired:
                options["loss-gemodel"] = {
                    "p": 0.01,
                    "r": 0.25,
                    "1-h": 0.90,
                    "1-k": 0.01,
                }
            return {
                "kind": "netem",
                "handle": "40:",
                "packets": packets,
                "drops": drops,
                "options": options,
            }

        def iso(timestamp_ns: int) -> str:
            return datetime.fromtimestamp(
                timestamp_ns / 1_000_000_000,
                timezone.utc,
            ).isoformat().replace("+00:00", "Z")

        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            endpoint_times = {
                "client": (20_005_000_000, 20_010_000_000, 22_002_000_000, 22_010_000_000),
                "server": (20_006_000_000, 20_015_000_000, 22_003_000_000, 22_015_000_000),
            }
            for endpoint_name, (
                start_command,
                start_applied,
                stop_command,
                stop_applied,
            ) in endpoint_times.items():
                endpoint = cell / endpoint_name
                endpoint.mkdir()
                (endpoint / "impairment-ready").touch()
                (endpoint / "impairment-done").touch()
                events = [
                    {
                        "event": "loss_start",
                        "requested_ns": scheduled_start_ns,
                        "command_start_ns": start_command,
                        "command_end_ns": start_applied + 2_000_000,
                        "change_start_ns": start_applied - 3_000_000,
                        "change_end_ns": start_applied,
                        "applied_ns": start_applied,
                        "clock_offset_ns": 100_000,
                        "clock_error_bound_ns": 1_000_000,
                        "success": True,
                        "loss_model": "gemodel",
                        "qdisc": [netem(100, 0, True)],
                    },
                    {
                        "event": "loss_stop",
                        "requested_ns": scheduled_stop_ns,
                        "command_start_ns": stop_command - 1_000_000,
                        "command_end_ns": stop_applied + 2_000_000,
                        "change_start_ns": stop_command,
                        "change_end_ns": stop_applied,
                        "applied_ns": stop_applied,
                        "clock_offset_ns": 100_000,
                        "clock_error_bound_ns": 1_000_000,
                        "success": True,
                        "loss_model": "none",
                        "qdisc": [netem(2100, 80, False)],
                    },
                ]
                (endpoint / "impairment-events.jsonl").write_text(
                    "".join(json.dumps(event) + "\n" for event in events),
                    encoding="utf-8",
                )
                samples = []
                for index, timestamp in enumerate(
                    range(4_990_000_000, 83_000_000_000, 100_000_000)
                ):
                    impaired = 20_020_000_000 <= timestamp < 22_010_000_000
                    drops = (
                        min(
                            80,
                            round(
                                (timestamp - 20_000_000_000)
                                / 2_000_000_000
                                * 80
                            ),
                        )
                        if impaired
                        else (80 if timestamp >= 22_010_000_000 else 0)
                    )
                    samples.append(
                        (timestamp, netem(index * 100, drops, impaired))
                    )
                (endpoint / "ifb-qdisc-series.jsonl").write_text(
                    "".join(
                        json.dumps(
                            {
                                "timestamp": iso(timestamp + 5_000_000),
                                "query_start_ns": timestamp,
                                "query_end_ns": timestamp + 5_000_000,
                                "qdisc": [qdisc],
                            }
                        )
                        + "\n"
                        for timestamp, qdisc in samples
                    ),
                    encoding="utf-8",
                )

            axes = {
                "scheduled_loss_start_ns": str(scheduled_start_ns),
                "scheduled_loss_stop_ns": str(scheduled_stop_ns),
                "loss_epoch_ms": "2000",
                "loss_epoch_start_s": "15",
                "loss_model": "gemodel",
                "loss_pct": "0",
                "burst_p": "1",
                "burst_r": "25",
                "burst_h": "90",
                "burst_k": "1",
                "rtt_ms": "200",
                "tunnel": "tcp",
                "impairment_validation": "transport_aware",
            }
            metrics, endpoints, issues = ANALYZE.timed_impairment_evidence(
                cell,
                axes,
                5_000_000_000,
                83_000_000_000,
            )

            self.assertEqual(issues, [])
            self.assertTrue(metrics["timed_impairment_valid"])
            self.assertEqual(metrics["impairment_start_skew_ms"], 10.0)
            self.assertEqual(metrics["impairment_stop_skew_ms"], 15.0)
            self.assertEqual(metrics["transition_clock_error_bound_ms"], 2.0)
            self.assertEqual(metrics["actual_loss_epoch_ms"], 1987.0)
            self.assertEqual(endpoints["client"]["packets"], 2000)
            self.assertEqual(endpoints["client"]["drops"], 80)

            client_series = cell / "client" / "ifb-qdisc-series.jsonl"
            rows = [
                json.loads(line)
                for line in client_series.read_text(encoding="utf-8").splitlines()
            ]
            rows[-1]["qdisc"][0]["drops"] = 81
            client_series.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            _, _, dirty_recovery_issues = ANALYZE.timed_impairment_evidence(
                cell,
                axes,
                5_000_000_000,
                83_000_000_000,
            )
            self.assertIn("impairment_clean_window", dirty_recovery_issues)

    def test_qdisc_phase_coverage_rejects_sparse_samples(self) -> None:
        qdisc = {"kind": "netem"}
        self.assertFalse(
            ANALYZE.qdisc_phase_coverage_valid(
                [
                    (1_000_000_000, 1_010_000_000, qdisc),
                    (2_000_000_000, 2_010_000_000, qdisc),
                ],
                1_000_000_000,
                2_010_000_000,
            )
        )
        self.assertTrue(
            ANALYZE.qdisc_phase_coverage_valid(
                [
                    (1_000_000_000, 1_010_000_000, qdisc),
                    (1_200_000_000, 1_210_000_000, qdisc),
                    (1_400_000_000, 1_410_000_000, qdisc),
                ],
                950_000_000,
                1_450_000_000,
            )
        )

    def test_timed_netem_signature_rejects_unexpected_impairment_options(
        self,
    ) -> None:
        netem = {
            "options": {
                "limit": 100000,
                "delay": {
                    "delay": 0.1,
                    "jitter": 0,
                    "correlation": 0,
                },
                "loss-gemodel": {
                    "p": 0.01,
                    "r": 0.25,
                    "1-h": 0.90,
                    "1-k": 0.01,
                },
                "ecn": False,
                "gap": 0,
                "duplicate": {"probability": 0.5},
            }
        }
        axes = {"rtt_ms": "200", "loss_model": "gemodel"}

        self.assertEqual(
            ANALYZE.netem_base_configuration_issues(netem, axes),
            ["netem_base_parameters"],
        )

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

    def test_quasi_meltdown_requires_a_full_second_stall(self) -> None:
        docs = [
            {
                "cell_id": "boundary-reference-tcp-r1",
                "valid": True,
                "classification": "degraded",
                "axes": {"impairment_schedule": "timed"},
                "metrics": {
                    "goodput_mbps": 10.0,
                    "episode_min_5s_mbps": 4.0,
                    "episode_below_half_pre": True,
                    "mechanism_observed": True,
                    "user_visible_disruption": True,
                    "episode_longest_stall_ms": 900,
                },
                "conditions": {},
            },
            {
                "cell_id": "boundary-reference-udp-r1",
                "valid": True,
                "classification": "stable",
                "axes": {"impairment_schedule": "timed"},
                "metrics": {
                    "goodput_mbps": 40.0,
                    "episode_min_5s_mbps": 20.0,
                },
                "conditions": {},
            },
        ]

        ANALYZE.apply_udp_control_comparison(docs)
        self.assertFalse(docs[0]["metrics"]["quasi_meltdown_episode"])

        docs[0]["metrics"]["episode_longest_stall_ms"] = 1000
        ANALYZE.apply_udp_control_comparison(docs)
        self.assertTrue(docs[0]["metrics"]["quasi_meltdown_episode"])

        docs[0]["metrics"]["episode_below_half_pre"] = "false"
        ANALYZE.apply_udp_control_comparison(docs)
        self.assertFalse(docs[0]["metrics"]["quasi_meltdown_episode"])

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
            "[string] $ExpectedHostA = \"wgtcp-amp-b\"",
            ORCHESTRATOR,
        )
        self.assertIn(
            "[string] $ExpectedHostB = \"wgtcp-amp-a\"",
            ORCHESTRATOR,
        )
        self.assertIn(
            "Get-EndpointIdentityVerificationCommand $ExpectedHostA $PrivateIpA",
            ORCHESTRATOR,
        )
        self.assertIn(
            "Get-EndpointIdentityVerificationCommand $ExpectedHostB $PrivateIpB",
            ORCHESTRATOR,
        )
        self.assertNotIn("$expectedPrivateIpA", ORCHESTRATOR)
        self.assertNotIn("$expectedPrivateIpB", ORCHESTRATOR)
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
            "$sampleDuration = [int]$workloadDuration + [int]$Row.warmup_s + 30",
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
            "Get-EndpointIdentityVerificationCommand $ExpectedHostA $PrivateIpA"
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
        self.assertIn('> "$OUT/ifb-qdisc-series.jsonl"', SAMPLER)
        self.assertIn('tc -s -j qdisc show dev "$IFB"', SAMPLER)
        self.assertIn('"query_start_ns":%s,"query_end_ns":%s', SAMPLER)

    def test_timed_impairment_runner_uses_absolute_synchronized_schedule(self) -> None:
        self.assertIn(
            '$impairmentSchedule = Get-MatrixValue $Row "impairment_schedule" "static"',
            ORCHESTRATOR,
        )
        self.assertIn(
            'Wait-RemoteNonemptyFile $HostB $PortB '
            '"$remoteCellB/client/first-inner-data.txt" 10',
            ORCHESTRATOR,
        )
        self.assertIn(
            "[decimal]$firstDataText * 1000000000",
            ORCHESTRATOR,
        )
        self.assertIn(
            '$workloadDuration = Get-MatrixValue $Row "workload_duration_s"',
            ORCHESTRATOR,
        )
        self.assertIn("-t $workloadDuration", ORCHESTRATOR)
        self.assertIn('"workload_duration_s=$workloadDuration"', ORCHESTRATOR)
        self.assertIn("--start-ns $scheduledLossStartNs", ORCHESTRATOR)
        self.assertIn(
            'Wait-RemoteFiles "$remoteCellA/impairment-done" '
            '"$remoteCellB/client/impairment-done" $transitionTimeout',
            ORCHESTRATOR,
        )
        done_index = ORCHESTRATOR.index(
            'Wait-RemoteFiles "$remoteCellA/impairment-done"'
        )
        workload_index = ORCHESTRATOR.index(
            'Wait-RemoteFile $HostB $PortB "$remoteCellB/workload.rc"'
        )
        self.assertLess(done_index, workload_index)
        self.assertIn(
            '"safety timed impairment failed: $($_.Exception.Message)"',
            ORCHESTRATOR,
        )
        self.assertIn(
            '$safetyStopReasons = @("timed_impairment")',
            ORCHESTRATOR,
        )
        self.assertIn("timed_impairment", ORCHESTRATOR)

    def test_synchronized_setup_rejects_late_release_and_drives_both_peers(
        self,
    ) -> None:
        self.assertIn("--tcp-role passive", SYNCHRONIZED_SETUP)
        self.assertIn("target - now < 1_000_000_000", SYNCHRONIZED_SETUP)
        self.assertIn("if lateness > 100_000_000:", SYNCHRONIZED_SETUP)
        self.assertIn("endpoint \"$peer_phys:51821\"", SYNCHRONIZED_SETUP)
        self.assertIn("for _ in $(seq 1 50); do", SYNCHRONIZED_SETUP)
        self.assertIn(
            "ping -q -I wg-mt-tcp -c 1 -W 1",
            SYNCHRONIZED_SETUP,
        )
        self.assertIn("required_samples=${2:-80}", QUALIFY_CARRIERS)
        self.assertIn("max_samples=${4:-240}", QUALIFY_CARRIERS)
        self.assertIn("stable_samples=0", QUALIFY_CARRIERS)
        self.assertIn(
            '($3 ~ /:51821$/ || $4 ~ /:51821$/)',
            QUALIFY_CARRIERS,
        )
        self.assertIn('[[ -z $baseline || $tuples != "$baseline" ]]', QUALIFY_CARRIERS)
        self.assertIn("stable_samples >= required_samples", QUALIFY_CARRIERS)
        self.assertIn(
            'printf \'%s\\n\' "$rc" > "$state_prefix.done"',
            SYNCHRONIZED_SETUP,
        )

    def test_timed_impairment_changes_only_active_netem_loss(self) -> None:
        self.assertIn("change-loss)", SHAPER)
        self.assertIn('[[ -e "$MARKER" ]]', SHAPER)
        self.assertIn('tc qdisc change dev "$IFB" root handle 40: netem', SHAPER)
        self.assertIn('"loss_start"', TIMED_IMPAIRMENT)
        self.assertIn('"loss_stop"', TIMED_IMPAIRMENT)
        self.assertIn('"requested_ns"', TIMED_IMPAIRMENT)
        self.assertIn('"applied_ns"', TIMED_IMPAIRMENT)
        self.assertIn('"change_start_ns"', TIMED_IMPAIRMENT)
        self.assertIn('"change_end_ns"', TIMED_IMPAIRMENT)
        self.assertIn('"clock_error_bound_ns"', TIMED_IMPAIRMENT)
        self.assertIn("Root delay", TIMED_IMPAIRMENT)
        self.assertIn("requested_ns - 1_000_000_000", TIMED_IMPAIRMENT)
        self.assertIn("clock_nanosleep", TIMED_IMPAIRMENT)
        self.assertIn("_TIMER_ABSTIME", TIMED_IMPAIRMENT)
        self.assertIn(
            "--property=CPUSchedulingPolicy=fifo",
            ORCHESTRATOR,
        )
        self.assertIn(
            "--property=CPUSchedulingPriority=50",
            ORCHESTRATOR,
        )
        self.assertIn('"event": "failsafe_clear"', TIMED_IMPAIRMENT)

    def test_endpoint_pair_is_bound_into_campaign_fingerprint(self) -> None:
        self.assertIn('$entries += "expected_host_a=$ExpectedHostA"', ORCHESTRATOR)
        self.assertIn('$entries += "expected_host_b=$ExpectedHostB"', ORCHESTRATOR)
        self.assertIn('$entries += "private_ip_a=$PrivateIpA"', ORCHESTRATOR)
        self.assertIn('$entries += "private_ip_b=$PrivateIpB"', ORCHESTRATOR)

    def test_boundary_smoke_matrix_is_exactly_four_timed_executions(self) -> None:
        with BOUNDARY_SMOKE_MATRIX.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(int(row["repetitions"]) for row in rows), 4)
        self.assertEqual({row["tunnel"] for row in rows}, {"tcp", "udp"})
        self.assertEqual({row["impairment_schedule"] for row in rows}, {"timed"})
        self.assertEqual({row["loss_epoch_start_s"] for row in rows}, {"15"})
        self.assertEqual({row["loss_epoch_ms"] for row in rows}, {"2000"})
        self.assertEqual({row["duration_s"] for row in rows}, {"77"})
        self.assertEqual({row["workload_duration_s"] for row in rows}, {"78"})
        self.assertEqual({row["warmup_s"] for row in rows}, {"10"})
        for field in (
            "impairment_schedule",
            "loss_epoch_start_s",
            "loss_epoch_ms",
            "workload_duration_s",
        ):
            self.assertIn(field, ANALYZE.CSV_FIELDS)

    def test_boundary_correlation_matrix_is_exactly_predeclared(self) -> None:
        with BOUNDARY_CORRELATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            rows = list(csv.DictReader(stream))

        expected_points = {
            "ge-res1-d16-r200-q1-16f": ("4", "100"),
            "ge-res2-d16-r200-q1-16f": ("2", "50"),
            "ge-res4-d16-r200-q1-16f": ("1", "25"),
            "ge-res8-d16-r200-q1-16f": ("0.5", "12.5"),
            "ge-res16-d16-r200-q1-16f": ("0.25", "6.25"),
        }
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(int(row["repetitions"]) for row in rows), 30)
        self.assertEqual({row["name"] for row in rows}, set(expected_points))
        self.assertEqual({row["tunnel"] for row in rows}, {"tcp", "udp"})
        self.assertEqual({row["impairment_schedule"] for row in rows}, {"timed"})
        self.assertEqual({row["loss_epoch_start_s"] for row in rows}, {"15"})
        self.assertEqual({row["loss_epoch_ms"] for row in rows}, {"16000"})
        self.assertEqual({row["duration_s"] for row in rows}, {"91"})
        self.assertEqual({row["workload_duration_s"] for row in rows}, {"92"})
        self.assertEqual({row["repetitions"] for row in rows}, {"3"})

        for name, (burst_p, burst_r) in expected_points.items():
            point_rows = [row for row in rows if row["name"] == name]
            self.assertEqual({row["tunnel"] for row in point_rows}, {"tcp", "udp"})
            self.assertEqual({row["burst_p"] for row in point_rows}, {burst_p})
            self.assertEqual({row["burst_r"] for row in point_rows}, {burst_r})
            for row in point_rows:
                p = float(row["burst_p"])
                r = float(row["burst_r"])
                bad_fraction = p / (p + r)
                stationary_loss = (
                    bad_fraction * float(row["burst_h"]) / 100.0
                    + (1.0 - bad_fraction) * float(row["burst_k"]) / 100.0
                )
                self.assertAlmostEqual(stationary_loss, 0.04423076923076923)

    def test_boundary_correlation_replication_is_independent_and_exact(self) -> None:
        with BOUNDARY_CORRELATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            frozen = list(csv.DictReader(stream))
        with BOUNDARY_CORRELATION_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            replication = list(csv.DictReader(stream))

        self.assertEqual(len(replication), 10)
        self.assertEqual(
            sum(int(row["repetitions"]) for row in replication),
            30,
        )
        self.assertEqual(
            {row["stage"] for row in replication},
            {"boundary-correlation-replication"},
        )
        for frozen_row, replication_row in zip(frozen, replication, strict=True):
            self.assertEqual(frozen_row["stage"], "boundary-correlation")
            self.assertEqual(
                {key: value for key, value in frozen_row.items() if key != "stage"},
                {
                    key: value
                    for key, value in replication_row.items()
                    if key != "stage"
                },
            )

    def test_realtime_correlation_replication_is_independent_and_exact(self) -> None:
        with BOUNDARY_CORRELATION_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            prior_replication = list(csv.DictReader(stream))
        with BOUNDARY_CORRELATION_RT_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            realtime_replication = list(csv.DictReader(stream))

        self.assertEqual(len(realtime_replication), 10)
        self.assertEqual(
            sum(int(row["repetitions"]) for row in realtime_replication),
            30,
        )
        self.assertEqual(
            {row["stage"] for row in realtime_replication},
            {"boundary-correlation-replication-rt"},
        )
        for prior_row, realtime_row in zip(
            prior_replication, realtime_replication, strict=True
        ):
            self.assertEqual(
                {key: value for key, value in prior_row.items() if key != "stage"},
                {
                    key: value
                    for key, value in realtime_row.items()
                    if key != "stage"
                },
            )

    def test_fourth_correlation_replication_is_independent_and_exact(self) -> None:
        with BOUNDARY_CORRELATION_RT_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            prior_replication = list(csv.DictReader(stream))
        with BOUNDARY_CORRELATION_RT2_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            fourth_replication = list(csv.DictReader(stream))

        self.assertEqual(len(fourth_replication), 10)
        self.assertEqual(
            sum(int(row["repetitions"]) for row in fourth_replication),
            30,
        )
        self.assertEqual(
            {row["stage"] for row in fourth_replication},
            {"boundary-correlation-replication-rt2"},
        )
        for prior_row, fourth_row in zip(
            prior_replication, fourth_replication, strict=True
        ):
            self.assertEqual(
                {key: value for key, value in prior_row.items() if key != "stage"},
                {
                    key: value
                    for key, value in fourth_row.items()
                    if key != "stage"
                },
            )

    def test_fifth_correlation_replication_is_independent_and_exact(self) -> None:
        with BOUNDARY_CORRELATION_RT2_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            prior_replication = list(csv.DictReader(stream))
        with BOUNDARY_CORRELATION_RT3_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            fifth_replication = list(csv.DictReader(stream))

        self.assertEqual(len(fifth_replication), 10)
        self.assertEqual(
            sum(int(row["repetitions"]) for row in fifth_replication),
            30,
        )
        self.assertEqual(
            {row["stage"] for row in fifth_replication},
            {"boundary-correlation-replication-rt3"},
        )
        for prior_row, fifth_row in zip(
            prior_replication, fifth_replication, strict=True
        ):
            self.assertEqual(
                {key: value for key, value in prior_row.items() if key != "stage"},
                {
                    key: value
                    for key, value in fifth_row.items()
                    if key != "stage"
                },
            )

    def test_sixth_correlation_replication_is_independent_and_exact(self) -> None:
        with BOUNDARY_CORRELATION_RT3_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            prior_replication = list(csv.DictReader(stream))
        with BOUNDARY_CORRELATION_RT4_REPLICATION_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            sixth_replication = list(csv.DictReader(stream))

        self.assertEqual(len(sixth_replication), 10)
        self.assertEqual(
            sum(int(row["repetitions"]) for row in sixth_replication),
            30,
        )
        self.assertEqual(
            {row["stage"] for row in sixth_replication},
            {"boundary-correlation-replication-rt4"},
        )
        for prior_row, sixth_row in zip(
            prior_replication, sixth_replication, strict=True
        ):
            self.assertEqual(
                {key: value for key, value in prior_row.items() if key != "stage"},
                {
                    key: value
                    for key, value in sixth_row.items()
                    if key != "stage"
                },
            )

    def test_carrier_stability_diagnostic_is_predeclared_and_exact(self) -> None:
        with CARRIER_STABILITY_DIAGNOSTIC_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            rows = list(csv.DictReader(stream))

        self.assertEqual(len(rows), 24)
        self.assertEqual(
            {row["stage"] for row in rows},
            {"carrier-stability-diagnostic-ct1"},
        )
        self.assertEqual(
            {
                (
                    row["pair"],
                    row["arm"],
                    row["activation"],
                    row["keepalive_s"],
                    row["expected_carriers"],
                    row["observation_s"],
                    row["interval_s"],
                    row["repetition"],
                )
                for row in rows
            },
            {
                (
                    pair,
                    arm,
                    activation,
                    keepalive,
                    "2",
                    "120",
                    "0.5",
                    repetition,
                )
                for pair in ("primary", "secondary")
                for arm, activation, keepalive in (
                    ("sync-k5", "synchronous", "5"),
                    ("sync-k0", "synchronous", "0"),
                    ("sync-k1", "synchronous", "1"),
                    ("staggered-k5", "staggered", "5"),
                )
                for repetition in ("1", "2", "3")
            },
        )
        self.assertIn(
            "ss -Htn state established",
            CARRIER_STABILITY_DIAGNOSTIC,
        )
        self.assertIn(
            "ss -tin state established '( sport = :51821 or dport = :51821 )'",
            CARRIER_STABILITY_DIAGNOSTIC,
        )
        self.assertIn(
            "dmesg --color=never | tail -n 80",
            CARRIER_STABILITY_DIAGNOSTIC,
        )
        self.assertIn(
            "carrier_diagnostic=failed",
            CARRIER_STABILITY_DIAGNOSTIC,
        )
        self.assertIn("keepalive_s=${10:-5}", SYNCHRONIZED_SETUP)
        self.assertIn(
            'persistent-keepalive "$keepalive_s"',
            SYNCHRONIZED_SETUP,
        )
        self.assertIn(
            "persistent_keepalive_s=%s",
            SYNCHRONIZED_SETUP,
        )

    def test_ct2_carrier_stability_diagnostic_is_independent_and_exact(self) -> None:
        with CARRIER_STABILITY_DIAGNOSTIC_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            ct1_rows = list(csv.DictReader(stream))
        with CARRIER_STABILITY_DIAGNOSTIC_CT2_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            ct2_rows = list(csv.DictReader(stream))

        self.assertEqual(len(ct2_rows), 24)
        self.assertEqual(
            {row["stage"] for row in ct2_rows},
            {"carrier-stability-diagnostic-ct2"},
        )
        self.assertEqual(
            hashlib.sha256(
                CARRIER_STABILITY_DIAGNOSTIC_CT2_MATRIX.read_bytes()
                .replace(b"\r\n", b"\n")
                .replace(b"\r", b"\n")
            ).hexdigest(),
            "8df67b25905b9b079fe89f7438cd94c89b40cfc2fcd14a89f593ff677ad4b983",
        )
        self.assertIn(
            "requires an\nexplicit `-Execute` switch",
            CARRIER_STABILITY_DIAGNOSTIC_CT2_PROTOCOL,
        )
        for ct1_row, ct2_row in zip(ct1_rows, ct2_rows, strict=True):
            self.assertEqual(
                {key: value for key, value in ct1_row.items() if key != "stage"},
                {key: value for key, value in ct2_row.items() if key != "stage"},
            )

    def test_ct3_carrier_stability_diagnostic_is_independent_and_exact(self) -> None:
        with CARRIER_STABILITY_DIAGNOSTIC_CT2_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            ct2_rows = list(csv.DictReader(stream))
        with CARRIER_STABILITY_DIAGNOSTIC_CT3_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            ct3_rows = list(csv.DictReader(stream))

        self.assertEqual(len(ct3_rows), 24)
        self.assertEqual(
            {row["stage"] for row in ct3_rows},
            {"carrier-stability-diagnostic-ct3"},
        )
        self.assertEqual(
            hashlib.sha256(
                CARRIER_STABILITY_DIAGNOSTIC_CT3_MATRIX.read_bytes()
                .replace(b"\r\n", b"\n")
                .replace(b"\r", b"\n")
            ).hexdigest(),
            "3ba54e36831a86fbf32a0b805ff8718c41474e83673724c1a53fcf704b65464a",
        )
        self.assertIn(
            "absence of active package processes or package\nlocks",
            CARRIER_STABILITY_DIAGNOSTIC_CT3_PROTOCOL,
        )
        self.assertIn(
            "temporary services, and enabled maintenance",
            CARRIER_STABILITY_DIAGNOSTIC_CT3_PROTOCOL,
        )
        for ct2_row, ct3_row in zip(ct2_rows, ct3_rows, strict=True):
            self.assertEqual(
                {key: value for key, value in ct2_row.items() if key != "stage"},
                {key: value for key, value in ct3_row.items() if key != "stage"},
            )

    def test_carrier_stability_terminal_disposition_is_complete(self) -> None:
        with CARRIER_STABILITY_DIAGNOSTIC_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            matrix_rows = list(csv.DictReader(stream))
        with (
            CARRIER_STABILITY_DIAGNOSTIC_RESULT / "logical-observations.csv"
        ).open(newline="", encoding="utf-8-sig") as stream:
            logical_rows = list(csv.DictReader(stream))
        with (
            CARRIER_STABILITY_DIAGNOSTIC_RESULT / "attempts.csv"
        ).open(newline="", encoding="utf-8-sig") as stream:
            attempt_rows = list(csv.DictReader(stream))

        self.assertEqual(len(logical_rows), len(matrix_rows))
        self.assertEqual(
            {
                (
                    row["pair"],
                    row["arm"],
                    row["activation"],
                    row["keepalive_s"],
                    row["repetition"],
                )
                for row in logical_rows
            },
            {
                (
                    row["pair"],
                    row["arm"],
                    row["activation"],
                    row["keepalive_s"],
                    row["repetition"],
                )
                for row in matrix_rows
            },
        )
        self.assertEqual(
            [row["status"] for row in logical_rows].count("invalid"),
            1,
        )
        self.assertEqual(
            [row["status"] for row in logical_rows].count("unrun"),
            23,
        )
        self.assertEqual(
            attempt_rows,
            [
                {
                    "sequence": "1",
                    "pair": "primary",
                    "arm": "sync-k5",
                    "repetition": "1",
                    "activation": "synchronous",
                    "keepalive_s": "5",
                    "status": "invalid",
                    "reason": "ssh_connect_timeout_before_host_qualification",
                    "source_status_sha256": (
                        "384111528fd15515bec6232a120ec7412bc478ebf1e61fd9f9d9ac1e6ea9109e"
                    ),
                }
            ],
        )

        status = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_RESULT / "observation-status.json"
            ).read_text(encoding="utf-8")
        )
        composition = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_RESULT / "composition-status.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(status["outcome"], "invalid")
        self.assertIn("Connection timed out", status["error"])
        self.assertEqual(composition["outcome"], "terminal_incomplete")
        self.assertEqual(composition["attempted_observations"], 1)
        self.assertEqual(composition["valid_observations"], 0)
        self.assertEqual(composition["invalid_observations"], 1)
        self.assertEqual(composition["unrun_observations"], 23)
        self.assertEqual(composition["tuple_samples_retained"], 0)
        self.assertEqual(composition["packet_captures_retained"], 0)
        self.assertEqual(
            composition["session_source_status_sha256"],
            attempt_rows[0]["source_status_sha256"],
        )
        self.assertTrue(composition["fleet_deallocated"])

        manifest = {
            name: sha256
            for sha256, name in (
                line.split("  ", maxsplit=1)
                for line in (
                    CARRIER_STABILITY_DIAGNOSTIC_RESULT / "sha256-manifest.txt"
                ).read_text(encoding="utf-8").splitlines()
            )
        }
        self.assertEqual(
            set(manifest),
            {
                "attempts.csv",
                "composition-status.json",
                "logical-observations.csv",
                "observation-status.json",
            },
        )
        for name, expected_hash in manifest.items():
            payload = (
                CARRIER_STABILITY_DIAGNOSTIC_RESULT / name
            ).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_hash)

    def test_ct2_carrier_stability_terminal_disposition_is_complete(self) -> None:
        with CARRIER_STABILITY_DIAGNOSTIC_CT2_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            matrix_rows = list(csv.DictReader(stream))
        with (
            CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT / "logical-observations.csv"
        ).open(newline="", encoding="utf-8-sig") as stream:
            logical_rows = list(csv.DictReader(stream))
        with (
            CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT / "attempts.csv"
        ).open(newline="", encoding="utf-8-sig") as stream:
            attempt_rows = list(csv.DictReader(stream))

        self.assertEqual(len(logical_rows), len(matrix_rows))
        self.assertEqual(
            {
                (
                    row["pair"],
                    row["arm"],
                    row["activation"],
                    row["keepalive_s"],
                    row["repetition"],
                )
                for row in logical_rows
            },
            {
                (
                    row["pair"],
                    row["arm"],
                    row["activation"],
                    row["keepalive_s"],
                    row["repetition"],
                )
                for row in matrix_rows
            },
        )
        self.assertEqual(
            [row["status"] for row in logical_rows].count("invalid"),
            2,
        )
        self.assertEqual(
            [row["status"] for row in logical_rows].count("unrun"),
            22,
        )
        self.assertEqual(
            [row["reason"] for row in attempt_rows],
            [
                "package_process_active_before_host_qualification",
                "residual_inner_iperf_service_after_runner_closeout",
            ],
        )
        composition = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT
                / "composition-status.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(composition["outcome"], "terminal_incomplete")
        self.assertEqual(composition["attempted_observations"], 2)
        self.assertEqual(composition["valid_observations"], 0)
        self.assertEqual(composition["invalid_observations"], 2)
        self.assertEqual(composition["unrun_observations"], 22)
        self.assertEqual(
            composition["secondary_raw_tuple_trace"],
            {
                "server_samples": 240,
                "server_tuple_changes": 18,
                "server_wrong_count_samples": 0,
                "client_samples": 240,
                "client_tuple_changes": 18,
                "client_wrong_count_samples": 0,
                "valid_ct2_observation": False,
            },
        )
        self.assertTrue(composition["fleet_deallocated"])

        primary_status = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT
                / "primary-observation-status.json"
            ).read_text(encoding="utf-8")
        )
        secondary_status = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT
                / "secondary-observation-status.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(primary_status["outcome"], "invalid")
        self.assertIn("package process is active", primary_status["error"])
        self.assertEqual(
            secondary_status["outcome"],
            "tuple_or_count_change_observed",
        )
        self.assertEqual(secondary_status["server_exit_code"], 1)
        self.assertEqual(secondary_status["client_exit_code"], 1)

        manifest = {
            name: sha256
            for sha256, name in (
                line.split("  ", maxsplit=1)
                for line in (
                    CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT
                    / "sha256-manifest.txt"
                ).read_text(encoding="utf-8").splitlines()
            )
        }
        self.assertEqual(
            set(manifest),
            {
                "attempts.csv",
                "composition-status.json",
                "launch-eligibility.json",
                "logical-observations.csv",
                "primary-observation-status.json",
                "raw-carrier-summary.csv",
                "secondary-observation-status.json",
                "secondary-source-manifest.txt",
            },
        )
        for name, expected_hash in manifest.items():
            payload = (
                CARRIER_STABILITY_DIAGNOSTIC_CT2_RESULT / name
            ).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_hash)

    def test_ct3_carrier_stability_terminal_disposition_is_complete(self) -> None:
        with CARRIER_STABILITY_DIAGNOSTIC_CT3_MATRIX.open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            matrix_rows = list(csv.DictReader(stream))
        with (
            CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT / "logical-observations.csv"
        ).open(newline="", encoding="utf-8-sig") as stream:
            logical_rows = list(csv.DictReader(stream))
        with (
            CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT / "attempts.csv"
        ).open(newline="", encoding="utf-8-sig") as stream:
            attempt_rows = list(csv.DictReader(stream))

        self.assertEqual(len(logical_rows), len(matrix_rows))
        self.assertEqual(
            {
                (
                    row["pair"],
                    row["arm"],
                    row["activation"],
                    row["keepalive_s"],
                    row["repetition"],
                )
                for row in logical_rows
            },
            {
                (
                    row["pair"],
                    row["arm"],
                    row["activation"],
                    row["keepalive_s"],
                    row["repetition"],
                )
                for row in matrix_rows
            },
        )
        self.assertEqual(
            [row["status"] for row in logical_rows].count("stable"),
            1,
        )
        self.assertEqual(
            [row["status"] for row in logical_rows].count("invalid"),
            1,
        )
        self.assertEqual(
            [row["status"] for row in logical_rows].count("unrun"),
            22,
        )
        self.assertEqual(
            [row["status"] for row in attempt_rows],
            ["stable", "invalid"],
        )
        self.assertEqual(
            attempt_rows[1]["reason"],
            (
                "carrier_exists_before_synchronized_activation_"
                "and_tunnel_control_failed"
            ),
        )

        composition = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT
                / "composition-status.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(composition["outcome"], "terminal_incomplete")
        self.assertEqual(composition["attempted_observations"], 2)
        self.assertEqual(composition["valid_observations"], 1)
        self.assertEqual(composition["invalid_observations"], 1)
        self.assertEqual(composition["unrun_observations"], 22)
        self.assertEqual(
            composition["primary_valid_tuple_trace"],
            {
                "server_samples": 240,
                "server_tuple_changes": 0,
                "server_wrong_count_samples": 0,
                "client_samples": 240,
                "client_tuple_changes": 0,
                "client_wrong_count_samples": 0,
            },
        )
        self.assertTrue(composition["fleet_deallocated"])

        primary_status = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT
                / "primary-observation-status.json"
            ).read_text(encoding="utf-8")
        )
        secondary_status = json.loads(
            (
                CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT
                / "secondary-observation-status.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(primary_status["outcome"], "stable")
        self.assertEqual(primary_status["restoration"], "valid")
        self.assertEqual(secondary_status["outcome"], "invalid")
        self.assertEqual(secondary_status["restoration"], "valid")

        manifest = {
            name: sha256
            for sha256, name in (
                line.split("  ", maxsplit=1)
                for line in (
                    CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT
                    / "sha256-manifest.txt"
                ).read_text(encoding="utf-8").splitlines()
            )
        }
        self.assertEqual(
            set(manifest),
            {
                "attempts.csv",
                "composition-status.json",
                "launch-eligibility.json",
                "logical-observations.csv",
                "primary-observation-status.json",
                "primary-source-manifest.txt",
                "raw-carrier-summary.csv",
                "secondary-observation-status.json",
                "secondary-source-manifest.txt",
            },
        )
        for name, expected_hash in manifest.items():
            payload = (
                CARRIER_STABILITY_DIAGNOSTIC_CT3_RESULT / name
            ).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_hash)

    def test_raw_collection_retries_transient_scp_failures(self) -> None:
        self.assertIn("for ($attempt = 1; $attempt -le 3; $attempt++)", ORCHESTRATOR)
        self.assertIn("Start-Sleep -Seconds $attempt", ORCHESTRATOR)
        self.assertIn("scp download failed on port $Port after 3 attempts", ORCHESTRATOR)

    def test_raw_collection_rejects_windows_path_overflow_before_workload(self) -> None:
        self.assertIn("function Assert-LocalArtifactCollectionPath", ORCHESTRATOR)
        self.assertIn(
            'Join-Path $LocalCell "client\\impairment-events.jsonl"', ORCHESTRATOR
        )
        self.assertIn("use a shorter ResultsDir before starting the cell", ORCHESTRATOR)
        guard_index = ORCHESTRATOR.index("Assert-LocalArtifactCollectionPath $localCell")
        cell_index = ORCHESTRATOR.index("$localCell =")
        remote_cell_index = ORCHESTRATOR.index("$remoteCellA =", cell_index)
        self.assertGreater(guard_index, cell_index)
        self.assertLess(guard_index, remote_cell_index)

    def test_shaper_keeps_cleanup_trap_through_status_capture(self) -> None:
        status_index = SHAPER.rindex('tc -s -j qdisc show dev "$IFB"')
        release_index = SHAPER.index("trap - EXIT", status_index)
        self.assertLess(status_index, release_index)


if __name__ == "__main__":
    unittest.main()
