import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "perf-test" / "meltdown" / "harness"
sys.path.insert(0, str(HARNESS))
SPEC = importlib.util.spec_from_file_location(
    "merge_campaigns", HARNESS / "merge_campaigns.py"
)
assert SPEC and SPEC.loader
MERGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MERGE
SPEC.loader.exec_module(MERGE)


IDENTITY = {
    "module_srcversion": "ABC123",
    "module_sha256": "a" * 64,
    "tool_sha256": "b" * 64,
}


def write_campaign(
    path: Path,
    cells: dict[str, tuple[bool, str, str]],
    campaign_fingerprint: str,
    identity: dict[str, str] | None = None,
) -> None:
    identity = identity or IDENTITY
    fingerprints: dict[str, str] = {}
    for index, (cell_id, (valid, classification, tunnel)) in enumerate(cells.items()):
        fingerprint = f"{index + 1:064x}"
        fingerprints[cell_id] = fingerprint
        cell = path / "cells" / cell_id
        cell.mkdir(parents=True)
        (cell / "cell.complete").write_text("complete\n", encoding="ascii")
        (cell / "cell.fingerprint").write_text(fingerprint + "\n", encoding="ascii")
        axes = {"tunnel": tunnel, "rate_mbps": "50", "rtt_ms": "100"}
        env = {
            "cell_id": cell_id,
            "cell_fingerprint": fingerprint,
            "campaign_fingerprint": campaign_fingerprint,
            **axes,
            **identity,
        }
        (cell / "cell.env").write_text(
            "".join(f"{key}={value}\n" for key, value in env.items()),
            encoding="utf-8",
        )
        doc = {
            "cell_id": cell_id,
            "axes": axes,
            "metrics": {
                "goodput_mbps": 40.0 if tunnel == "tcp" else 48.0,
                "delivery_bins": 450,
            },
            "conditions": {},
            "invalid_reasons": [] if valid else ["telemetry"],
            "valid": valid,
            "classification": classification,
        }
        (cell / "cell.json").write_text(
            json.dumps(doc),
            encoding="utf-8",
        )

    status = {
        "status": "complete",
        "expected_cells": list(cells),
        "completed_cells": list(cells),
        "failed_cells": [],
        "campaign_fingerprint": campaign_fingerprint,
        "cell_fingerprints": fingerprints,
    }
    path.mkdir(parents=True, exist_ok=True)
    (path / "campaign-status.json").write_text(
        json.dumps(status),
        encoding="utf-8",
    )


class CampaignMergeTests(unittest.TestCase):
    def test_replaces_only_invalid_cells_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / "base"
            replacement = root / "rerun"
            output = root / "qualified"
            write_campaign(
                base,
                {
                    "boundary-x-tcp-r1": (False, "invalid", "tcp"),
                    "boundary-x-udp-r1": (True, "stable", "udp"),
                },
                "c" * 64,
            )
            write_campaign(
                replacement,
                {"boundary-x-tcp-r1": (True, "stable", "tcp")},
                "d" * 64,
            )

            status = MERGE.write_composite(
                MERGE.load_campaign(base),
                MERGE.load_campaign(replacement),
                output,
            )

            self.assertEqual(status["status"], "qualified-composite")
            self.assertEqual(status["counts"], {"stable": 2})
            provenance = (output / "provenance.csv").read_text(encoding="utf-8")
            self.assertIn("base", provenance)
            self.assertIn("rerun", provenance)
            self.assertIn("cell_json_sha256", provenance)
            self.assertIn("true", provenance)
            cells = (output / "cells.csv").read_text(encoding="utf-8")
            self.assertIn("0.8333333333333334", cells)

    def test_rejects_replacement_of_valid_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / "base"
            replacement = root / "rerun"
            write_campaign(
                base,
                {"boundary-x-tcp-r1": (True, "stable", "tcp")},
                "c" * 64,
            )
            write_campaign(
                replacement,
                {"boundary-x-tcp-r1": (True, "stable", "tcp")},
                "d" * 64,
            )
            with self.assertRaisesRegex(ValueError, "overwrite valid evidence"):
                MERGE.write_composite(
                    MERGE.load_campaign(base),
                    MERGE.load_campaign(replacement),
                    root / "qualified",
                )

    def test_rejects_runtime_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base = root / "base"
            replacement = root / "rerun"
            write_campaign(
                base,
                {"boundary-x-tcp-r1": (False, "invalid", "tcp")},
                "c" * 64,
            )
            write_campaign(
                replacement,
                {"boundary-x-tcp-r1": (True, "stable", "tcp")},
                "d" * 64,
                {**IDENTITY, "module_sha256": "e" * 64},
            )
            with self.assertRaisesRegex(ValueError, "runtime identities differ"):
                MERGE.write_composite(
                    MERGE.load_campaign(base),
                    MERGE.load_campaign(replacement),
                    root / "qualified",
                )

    def test_rejects_incomplete_campaign_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "base"
            write_campaign(
                path,
                {"boundary-x-tcp-r1": (False, "invalid", "tcp")},
                "c" * 64,
            )
            status_path = path / "campaign-status.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["completed_cells"] = []
            status_path.write_text(json.dumps(status), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "completed/failed"):
                MERGE.load_campaign(path)


if __name__ == "__main__":
    unittest.main()
