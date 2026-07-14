#!/usr/bin/env python3
"""Behavioral tests for the TCP meltdown result analyzer."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
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
                ANALYZE.TCP_EVENTS_HEADER + "\n" + event * 2 + summaries,
                encoding="ascii",
            )
            self.assertIn(
                "events_summary_mismatch",
                ANALYZE.tcp_event_telemetry_issues(endpoint),
            )

    def test_tcp_event_summaries_use_atomic_aggregation(self) -> None:
        for counter in (
            "inner_rto",
            "outer_rto",
            "competitor_rto",
            "inner_retrans",
            "outer_retrans",
            "competitor_retrans",
        ):
            self.assertIn(f"@{counter}++;", TCP_EVENTS)
            self.assertNotIn(f"@{counter} = @{counter} + 1;", TCP_EVENTS)

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
        self.assertIn(
            "$sampleDuration = [int]$Row.duration_s + [int]$Row.warmup_s + 30",
            ORCHESTRATOR,
        )
        self.assertIn("[string[]] $Cell = @()", ORCHESTRATOR)
        self.assertIn("$selectedCells.Contains($cellId)", ORCHESTRATOR)
        restart_index = ORCHESTRATOR.index(
            "sudo systemctl restart wgtcp-meltdown-iperf-inner.service"
        )
        sampler_index = ORCHESTRATOR.index(
            "sudo systemd-run --unit=$(ConvertTo-ShellQuoted $serverUnit)"
        )
        self.assertLess(restart_index, sampler_index)

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
