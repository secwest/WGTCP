import csv
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "perf-test" / "meltdown" / "harness"
sys.path.insert(0, str(HARNESS))
SPEC = importlib.util.spec_from_file_location(
    "compose_campaigns", HARNESS / "compose_campaigns.py"
)
assert SPEC and SPEC.loader
COMPOSE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMPOSE
SPEC.loader.exec_module(COMPOSE)


IDENTITY = {
    "module_srcversion": "ABC123",
    "module_sha256": "a" * 64,
    "tool_sha256": "b" * 64,
    "iperf_version": "iperf 3.16",
    "iperf_sha256": "f" * 64,
}
PROFILE = "boundary-correlation-ge-res1-d16-r200-q1-16f"


def write_matrix(path: Path, repetitions: int = 4) -> list[str]:
    fields = (
        "stage",
        "enabled",
        "name",
        "tunnel",
        "rate_mbps",
        "rtt_ms",
        "repetitions",
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for tunnel in ("tcp", "udp"):
            writer.writerow(
                {
                    "stage": "boundary-correlation",
                    "enabled": "1",
                    "name": "ge-res1-d16-r200-q1-16f",
                    "tunnel": tunnel,
                    "rate_mbps": "50",
                    "rtt_ms": "200",
                    "repetitions": repetitions,
                }
            )
    return [
        f"{PROFILE}-{tunnel}-r{repetition}"
        for tunnel in ("tcp", "udp")
        for repetition in range(1, repetitions + 1)
    ]


def write_campaign(
    path: Path,
    outcomes: dict[str, str],
    matrix_cells: list[str],
    campaign_fingerprint: str,
    updated_at: str,
    *,
    fingerprint_salt: str = "",
    safety_stop_cell: str | None = None,
) -> None:
    completed = [
        cell_id
        for cell_id, outcome in outcomes.items()
        if outcome in {"valid", "invalid"}
    ]
    failed = [
        cell_id
        for cell_id, outcome in outcomes.items()
        if outcome in {"failed", "stopped"}
    ]
    stopped = [
        cell_id for cell_id, outcome in outcomes.items() if outcome == "stopped"
    ]
    stop_cell = safety_stop_cell or (stopped[0] if stopped else None)
    status_name = (
        "safety_stopped"
        if stop_cell
        else ("incomplete" if failed else "complete")
    )
    fingerprints = {
        cell_id: hashlib.sha256(
            f"{cell_id}{fingerprint_salt}".encode("utf-8")
        ).hexdigest()
        for cell_id in outcomes
    }
    for cell_id in completed:
        outcome = outcomes[cell_id]
        tunnel = "tcp" if "-tcp-" in cell_id else "udp"
        cell = path / "cells" / cell_id
        cell.mkdir(parents=True)
        fingerprint = fingerprints[cell_id]
        axes = {"tunnel": tunnel, "rate_mbps": "50", "rtt_ms": "200"}
        env = {
            "cell_id": cell_id,
            "cell_fingerprint": fingerprint,
            "campaign_fingerprint": campaign_fingerprint,
            **axes,
            **IDENTITY,
        }
        (cell / "cell.complete").write_text("complete\n", encoding="ascii")
        (cell / "cell.fingerprint").write_text(fingerprint + "\n", encoding="ascii")
        (cell / "cell.env").write_text(
            "".join(f"{key}={value}\n" for key, value in env.items()),
            encoding="utf-8",
        )
        valid = outcome == "valid"
        document = {
            "cell_id": cell_id,
            "axes": axes,
            "metrics": {
                "goodput_mbps": 40.0 if tunnel == "tcp" else 48.0,
                "delivery_bins": 450,
                "episode_min_5s_mbps": 20.0 if tunnel == "tcp" else 30.0,
            },
            "conditions": {
                "formal_meltdown": False,
                "quasi_meltdown_episode": False,
            },
            "invalid_reasons": [] if valid else ["telemetry"],
            "valid": valid,
            "classification": "stable" if valid else "invalid",
        }
        (cell / "cell.json").write_text(json.dumps(document), encoding="utf-8")

    for cell_id in failed:
        cell = path / "cells" / cell_id
        cell.mkdir(parents=True)
        (cell / "partial.txt").write_text("partial evidence\n", encoding="utf-8")

    path.mkdir(parents=True, exist_ok=True)
    status = {
        "status": status_name,
        "updated_at": updated_at,
        "expected_cells": list(outcomes),
        "matrix_expected_cells": matrix_cells,
        "targeted_selection": set(outcomes) != set(matrix_cells),
        "qualifying_complete": status_name == "complete"
        and set(outcomes) == set(matrix_cells),
        "completed_cells": completed,
        "failed_cells": failed,
        "campaign_fingerprint": campaign_fingerprint,
        "cell_fingerprints": fingerprints,
    }
    (path / "campaign-status.json").write_text(
        json.dumps(status),
        encoding="utf-8",
    )
    if stop_cell:
        (path / "campaign-safety-stop.json").write_text(
            json.dumps(
                {
                    "status": "safety_stopped",
                    "cell_id": stop_cell,
                    "reasons": ["timed_impairment"],
                    "campaign_fingerprint": campaign_fingerprint,
                }
            ),
            encoding="utf-8",
        )


class CampaignCompositionTests(unittest.TestCase):
    def test_published_stage2_composition_is_hash_bound_and_stopped(self) -> None:
        result = (
            ROOT
            / "perf-test"
            / "meltdown"
            / "results"
            / "2026-07-16-boundary-stage2-correlation"
        )
        status = json.loads(
            (result / "composition-status.json").read_text(encoding="utf-8")
        )
        matrix = ROOT / "perf-test" / "meltdown" / "matrix-boundary-correlation.csv"
        self.assertEqual(status["status"], "stopped-incomplete-selection")
        self.assertEqual(
            status["matrix_sha256"],
            hashlib.sha256(matrix.read_bytes()).hexdigest(),
        )
        self.assertEqual(status["matrix_cells"], 30)
        self.assertEqual(status["attempts"], 32)
        self.assertEqual(status["analyzable_attempts"], 31)
        self.assertEqual(status["safety_stops"], 1)
        self.assertEqual(
            status["attempt_outcomes"],
            {"invalid": 8, "stopped": 1, "valid": 23},
        )
        self.assertEqual(
            status["logical_states"],
            {"selected_valid": 23, "stopped": 1, "unrun": 6},
        )
        self.assertEqual(status["selected_classifications"], {"stable": 23})
        self.assertEqual(len(status["source_campaigns"]), 14)

        with (result / "profiles.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            profiles = list(csv.DictReader(handle))
        self.assertEqual(
            [row["qualified_tcp_quasi_meltdowns"] for row in profiles],
            ["0", "1", "0", "0", "0"],
        )
        self.assertEqual(
            [row["state"] for row in profiles],
            ["qualified", "qualified", "qualified", "incomplete", "unrun"],
        )

        with (result / "attempts.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            attempts = list(csv.DictReader(handle))
        with (result / "logical-cells.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            logical = list(csv.DictReader(handle))
        with (result / "selected-cells.csv").open(
            encoding="utf-8", newline=""
        ) as handle:
            selected = list(csv.DictReader(handle))
        self.assertEqual(len(attempts), status["attempts"])
        self.assertEqual(
            sum(row["outcome"] in {"valid", "invalid"} for row in attempts),
            status["analyzable_attempts"],
        )
        self.assertEqual(
            dict(sorted(Counter(row["outcome"] for row in attempts).items())),
            status["attempt_outcomes"],
        )
        self.assertEqual(len(logical), status["matrix_cells"])
        self.assertEqual(
            dict(sorted(Counter(row["state"] for row in logical).items())),
            status["logical_states"],
        )
        self.assertEqual(
            len(selected),
            status["logical_states"]["selected_valid"],
        )

        manifest = {}
        for line in (result / "sha256-manifest.txt").read_text(
            encoding="ascii"
        ).splitlines():
            digest, name = line.split("  ", 1)
            manifest[name] = digest
        self.assertEqual(
            set(manifest),
            {
                path.name
                for path in result.iterdir()
                if path.is_file() and path.name != "sha256-manifest.txt"
            },
        )
        for name, digest in manifest.items():
            self.assertEqual(
                hashlib.sha256((result / name).read_bytes()).hexdigest(),
                digest,
            )

    def test_preserves_selected_invalid_stopped_failed_and_unrun_states(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path)
            tcp_r1 = f"{PROFILE}-tcp-r1"
            udp_r1 = f"{PROFILE}-udp-r1"
            tcp_r2 = f"{PROFILE}-tcp-r2"
            udp_r2 = f"{PROFILE}-udp-r2"
            tcp_r3 = f"{PROFILE}-tcp-r3"

            campaign_specs = (
                (
                    "base-r1",
                    {tcp_r1: "invalid", udp_r1: "valid", tcp_r3: "failed"},
                    "a" * 64,
                ),
                ("base-r2", {tcp_r2: "invalid", udp_r2: "invalid"}, "b" * 64),
                ("rerun-r1", {tcp_r1: "valid"}, "a" * 64),
                (
                    "rerun-r2-stop",
                    {tcp_r2: "valid", udp_r2: "stopped"},
                    "b" * 64,
                ),
            )
            campaign_paths = []
            for index, (name, outcomes, fingerprint) in enumerate(
                campaign_specs,
                start=1,
            ):
                path = root / name
                write_campaign(
                    path,
                    outcomes,
                    matrix_cells,
                    fingerprint,
                    f"2026-01-01T00:00:{index:02d}Z",
                )
                campaign_paths.append(path)

            audit = root / "audit"
            audit.mkdir()
            (audit / "journal.log").write_text("restart\n", encoding="utf-8")
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix) for path in campaign_paths
            ]
            output = root / "composition"
            status = COMPOSE.write_composition(
                matrix,
                campaigns,
                output,
                [("stopped-cell", audit)],
            )

            self.assertEqual(status["status"], "stopped-incomplete-selection")
            self.assertEqual(status["matrix_cells"], 8)
            self.assertEqual(status["attempts"], 8)
            self.assertEqual(status["analyzable_attempts"], 6)
            self.assertEqual(status["safety_stops"], 1)
            self.assertEqual(
                status["attempt_outcomes"],
                {"failed": 1, "invalid": 3, "stopped": 1, "valid": 3},
            )
            self.assertEqual(
                status["logical_states"],
                {"failed": 1, "selected_valid": 3, "stopped": 1, "unrun": 3},
            )
            self.assertEqual(status["selected_classifications"], {"stable": 3})
            self.assertEqual(status["audit_evidence"][0]["file_count"], 1)

            with (output / "attempts.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                attempts = list(csv.DictReader(handle))
            tcp_r1_attempts = [
                row for row in attempts if row["cell_id"] == tcp_r1
            ]
            self.assertEqual(
                [row["outcome"] for row in tcp_r1_attempts],
                ["invalid", "valid"],
            )
            self.assertEqual(
                [row["selected"] for row in tcp_r1_attempts],
                ["false", "true"],
            )
            tcp_r2_attempts = [
                row for row in attempts if row["cell_id"] == tcp_r2
            ]
            self.assertEqual(
                [row["outcome"] for row in tcp_r2_attempts],
                ["invalid", "valid"],
            )
            self.assertEqual(
                tcp_r2_attempts[-1]["campaign_status"],
                "safety_stopped",
            )
            self.assertEqual(tcp_r2_attempts[-1]["selected"], "true")
            stopped = next(row for row in attempts if row["outcome"] == "stopped")
            self.assertEqual(stopped["stop_reasons"], "timed_impairment")
            self.assertEqual(stopped["evidence_file_count"], "1")

            with (output / "logical-cells.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                logical = {
                    row["cell_id"]: row for row in csv.DictReader(handle)
                }
            self.assertEqual(logical[udp_r2]["state"], "stopped")
            self.assertEqual(logical[udp_r2]["rerun_consumed"], "true")
            self.assertEqual(logical[tcp_r3]["state"], "failed")
            self.assertEqual(logical[tcp_r3]["retry_available"], "false")
            self.assertEqual(logical[udp_r1]["retry_available"], "false")
            self.assertTrue((output / "sha256-manifest.txt").is_file())

    def test_rejects_nonexact_rerun_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            base = root / "base"
            rerun = root / "rerun"
            write_campaign(
                base,
                {cell_id: "invalid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            write_campaign(
                rerun,
                {cell_id: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:02Z",
                fingerprint_salt="changed",
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix) for path in (base, rerun)
            ]
            with self.assertRaisesRegex(ValueError, "rerun fingerprint differs"):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_reversed_rerun_chronology(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            base = root / "base"
            rerun = root / "rerun"
            write_campaign(
                base,
                {cell_id: "invalid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            write_campaign(
                rerun,
                {cell_id: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:02Z",
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix) for path in (rerun, base)
            ]
            with self.assertRaisesRegex(ValueError, "rerun chronology is invalid"):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_rerun_with_different_campaign_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            base = root / "base"
            rerun = root / "rerun"
            write_campaign(
                base,
                {cell_id: "invalid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            write_campaign(
                rerun,
                {cell_id: "valid"},
                matrix_cells,
                "2" * 64,
                "2026-01-01T00:00:02Z",
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix) for path in (base, rerun)
            ]
            with self.assertRaisesRegex(
                ValueError,
                "rerun campaign fingerprint differs",
            ):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_rerun_after_safety_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            tcp = f"{PROFILE}-tcp-r1"
            udp = f"{PROFILE}-udp-r1"
            base = root / "base"
            rerun = root / "rerun"
            write_campaign(
                base,
                {udp: "valid", tcp: "invalid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
                safety_stop_cell=tcp,
            )
            write_campaign(
                rerun,
                {tcp: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:02Z",
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix) for path in (base, rerun)
            ]
            with self.assertRaisesRegex(
                ValueError,
                "campaign follows a safety stop",
            ):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_preserves_analyzed_safety_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            tcp = f"{PROFILE}-tcp-r1"
            udp = f"{PROFILE}-udp-r1"
            campaign_path = root / "analyzed-stop"
            write_campaign(
                campaign_path,
                {udp: "valid", tcp: "invalid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
                safety_stop_cell=tcp,
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaign = COMPOSE.validate_shard(campaign_path, matrix)
            output = root / "composition"
            status = COMPOSE.write_composition(matrix, [campaign], output)
            self.assertEqual(status["status"], "stopped-incomplete-selection")
            self.assertEqual(status["safety_stops"], 1)
            self.assertEqual(
                status["attempt_outcomes"],
                {"invalid": 1, "valid": 1},
            )

            with (output / "attempts.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                attempts = {
                    row["cell_id"]: row for row in csv.DictReader(handle)
                }
            self.assertEqual(attempts[tcp]["outcome"], "invalid")
            self.assertEqual(attempts[tcp]["safety_stop"], "true")
            self.assertEqual(attempts[tcp]["stop_reasons"], "timed_impairment")

            with (output / "logical-cells.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                logical = {
                    row["cell_id"]: row for row in csv.DictReader(handle)
                }
            self.assertEqual(logical[tcp]["state"], "invalid")
            self.assertEqual(logical[tcp]["safety_stop"], "true")
            self.assertEqual(logical[tcp]["retry_available"], "false")

    def test_rejects_manifested_attempt_after_stop_cell(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            tcp = f"{PROFILE}-tcp-r1"
            udp = f"{PROFILE}-udp-r1"
            campaign_path = root / "nonterminal-stop"
            write_campaign(
                campaign_path,
                {tcp: "invalid", udp: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
                safety_stop_cell=tcp,
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaign = COMPOSE.validate_shard(campaign_path, matrix)
            with self.assertRaisesRegex(
                ValueError,
                "safety-stop cell is not final",
            ):
                COMPOSE.write_composition(
                    matrix,
                    [campaign],
                    root / "composition",
                )

    def test_rejects_campaign_after_safety_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=2)
            tcp_r1 = f"{PROFILE}-tcp-r1"
            udp_r1 = f"{PROFILE}-udp-r1"
            tcp_r2 = f"{PROFILE}-tcp-r2"
            stopped = root / "stopped"
            later = root / "later"
            write_campaign(
                stopped,
                {tcp_r1: "valid", udp_r1: "invalid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
                safety_stop_cell=udp_r1,
            )
            write_campaign(
                later,
                {tcp_r2: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:02Z",
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix)
                for path in (stopped, later)
            ]
            with self.assertRaisesRegex(
                ValueError,
                "campaign follows a safety stop",
            ):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_rerun_after_failed_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            tcp = f"{PROFILE}-tcp-r1"
            udp = f"{PROFILE}-udp-r1"
            base = root / "base"
            rerun = root / "rerun"
            write_campaign(
                base,
                {tcp: "failed", udp: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            write_campaign(
                rerun,
                {tcp: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:02Z",
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix) for path in (base, rerun)
            ]
            with self.assertRaisesRegex(
                ValueError,
                "only invalid evidence may be rerun",
            ):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_cross_pair_matched_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            tcp = f"{PROFILE}-tcp-r1"
            udp = f"{PROFILE}-udp-r1"
            tcp_campaign = root / "tcp-pair"
            udp_campaign = root / "udp-pair"
            write_campaign(
                tcp_campaign,
                {tcp: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            write_campaign(
                udp_campaign,
                {udp: "valid"},
                matrix_cells,
                "2" * 64,
                "2026-01-01T00:00:02Z",
            )
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [
                COMPOSE.validate_shard(path, matrix)
                for path in (tcp_campaign, udp_campaign)
            ]
            with self.assertRaisesRegex(ValueError, "matched control pair differs"):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_identityless_partial_shard(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            campaign = root / "failed-only"
            write_campaign(
                campaign,
                {cell_id: "failed"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            with self.assertRaisesRegex(
                ValueError,
                "shard runtime identity is unavailable",
            ):
                COMPOSE.validate_shard(
                    campaign,
                    COMPOSE.load_matrix(matrix_path),
                )

    def test_rejects_missing_partial_attempt_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            tcp = f"{PROFILE}-tcp-r1"
            udp = f"{PROFILE}-udp-r1"
            campaign_path = root / "partial"
            write_campaign(
                campaign_path,
                {tcp: "failed", udp: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            (campaign_path / "cells" / tcp / "partial.txt").unlink()
            matrix = COMPOSE.load_matrix(matrix_path)
            campaign = COMPOSE.validate_shard(campaign_path, matrix)
            with self.assertRaisesRegex(ValueError, "attempt evidence is missing"):
                COMPOSE.write_composition(
                    matrix,
                    [campaign],
                    root / "composition",
                )

    def test_rejects_unmanifested_cell_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            tcp = f"{PROFILE}-tcp-r1"
            udp = f"{PROFILE}-udp-r1"
            campaign = root / "campaign"
            write_campaign(
                campaign,
                {tcp: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            omitted = campaign / "cells" / udp
            omitted.mkdir()
            (omitted / "partial.txt").write_text(
                "hidden attempt\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "unmanifested cell evidence is present",
            ):
                COMPOSE.validate_shard(
                    campaign,
                    COMPOSE.load_matrix(matrix_path),
                )

    def test_rejects_string_boolean_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            campaign = root / "campaign"
            write_campaign(
                campaign,
                {cell_id: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            result_path = campaign / "cells" / cell_id / "cell.json"
            document = json.loads(result_path.read_text(encoding="utf-8"))
            document["valid"] = "false"
            result_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid is not boolean"):
                COMPOSE.validate_shard(
                    campaign,
                    COMPOSE.load_matrix(matrix_path),
                )

    def test_rejects_string_boolean_timed_metric(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            campaign = root / "campaign"
            write_campaign(
                campaign,
                {cell_id: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            cell_path = campaign / "cells" / cell_id
            result_path = cell_path / "cell.json"
            document = json.loads(result_path.read_text(encoding="utf-8"))
            document["axes"]["impairment_schedule"] = "timed"
            document["metrics"].update(
                {
                    "episode_below_half_pre": "false",
                    "mechanism_observed": True,
                    "user_visible_disruption": True,
                    "episode_min_5s_mbps": 10.0,
                    "episode_longest_stall_ms": 1000,
                }
            )
            result_path.write_text(json.dumps(document), encoding="utf-8")
            with (cell_path / "cell.env").open("a", encoding="utf-8") as handle:
                handle.write("impairment_schedule=timed\n")
            with self.assertRaisesRegex(
                ValueError,
                "timed metric episode_below_half_pre is not boolean",
            ):
                COMPOSE.validate_shard(
                    campaign,
                    COMPOSE.load_matrix(matrix_path),
                )

            missing = root / "missing"
            write_campaign(
                missing,
                {cell_id: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:02Z",
            )
            missing_cell = missing / "cells" / cell_id
            missing_result = missing_cell / "cell.json"
            document = json.loads(missing_result.read_text(encoding="utf-8"))
            document["axes"]["impairment_schedule"] = "timed"
            document["metrics"].update(
                {
                    "episode_min_5s_mbps": 10.0,
                    "episode_longest_stall_ms": 1000,
                }
            )
            missing_result.write_text(json.dumps(document), encoding="utf-8")
            with (missing_cell / "cell.env").open(
                "a",
                encoding="utf-8",
            ) as handle:
                handle.write("impairment_schedule=timed\n")
            with self.assertRaisesRegex(
                ValueError,
                "timed metric episode_below_half_pre is not boolean",
            ):
                COMPOSE.validate_shard(
                    missing,
                    COMPOSE.load_matrix(matrix_path),
                )

    def test_rejects_directory_symlink_in_evidence_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence"
            target = root / "target"
            evidence.mkdir()
            target.mkdir()
            (target / "outside.txt").write_text("outside\n", encoding="utf-8")
            link = evidence / "linked"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "contains a symlink"):
                COMPOSE.tree_digest(evidence)

    def test_rejects_more_than_one_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            paths = []
            for index, outcome in enumerate(("invalid", "invalid", "valid"), start=1):
                path = root / f"attempt-{index}"
                write_campaign(
                    path,
                    {cell_id: outcome},
                    matrix_cells,
                    "1" * 64,
                    f"2026-01-01T00:00:{index:02d}Z",
                )
                paths.append(path)
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [COMPOSE.validate_shard(path, matrix) for path in paths]
            with self.assertRaisesRegex(ValueError, "more than one rerun"):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_rerun_of_valid_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            paths = []
            for index in range(1, 3):
                path = root / f"attempt-{index}"
                write_campaign(
                    path,
                    {cell_id: "valid"},
                    matrix_cells,
                    "1" * 64,
                    f"2026-01-01T00:00:{index:02d}Z",
                )
                paths.append(path)
            matrix = COMPOSE.load_matrix(matrix_path)
            campaigns = [COMPOSE.validate_shard(path, matrix) for path in paths]
            with self.assertRaisesRegex(ValueError, "valid evidence was rerun"):
                COMPOSE.write_composition(
                    matrix,
                    campaigns,
                    root / "composition",
                )

    def test_rejects_campaign_for_different_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            matrix_path = root / "matrix.csv"
            matrix_cells = write_matrix(matrix_path, repetitions=1)
            cell_id = f"{PROFILE}-tcp-r1"
            path = root / "campaign"
            write_campaign(
                path,
                {cell_id: "valid"},
                matrix_cells,
                "1" * 64,
                "2026-01-01T00:00:01Z",
            )
            status_path = path / "campaign-status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["matrix_expected_cells"] = [
                matrix_cells[0],
                "boundary-correlation-other-udp-r1",
            ]
            status_path.write_text(json.dumps(status), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "matrix expected cells differ"):
                COMPOSE.validate_shard(path, COMPOSE.load_matrix(matrix_path))


if __name__ == "__main__":
    unittest.main()
