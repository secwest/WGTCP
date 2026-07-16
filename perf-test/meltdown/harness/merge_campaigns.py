#!/usr/bin/env python3
"""Build a qualified composite without erasing invalid source evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyze import CSV_FIELDS, apply_udp_control_comparison, flatten, write_report


IDENTITY_KEYS = (
    "module_srcversion",
    "module_sha256",
    "tool_sha256",
    "iperf_version",
    "iperf_sha256",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
SRCVERSION = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
QUALIFICATION_FIELDS = (
    "matrix_expected_cells",
    "targeted_selection",
    "qualifying_complete",
)
CLASSIFICATIONS = {
    "stable",
    "degraded",
    "near-meltdown",
    "meltdown",
    "invalid",
}


@dataclass(frozen=True)
class Campaign:
    path: Path
    status: dict[str, Any]
    order: list[str]
    docs: dict[str, dict[str, Any]]
    fingerprints: dict[str, str]
    result_hashes: dict[str, str]
    identity: dict[str, str]

    @property
    def fingerprint(self) -> str:
        return str(self.status["campaign_fingerprint"])


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def validate_qualification_metadata(
    path: Path,
    status: dict[str, Any],
    order: list[str],
    complete: bool,
) -> bool:
    present = [field in status for field in QUALIFICATION_FIELDS]
    if not any(present):
        return False
    if not all(present):
        raise ValueError(f"{path.name}: qualification metadata is incomplete")

    matrix_cells = status["matrix_expected_cells"]
    if (
        not isinstance(matrix_cells, list)
        or not matrix_cells
        or not all(isinstance(cell, str) for cell in matrix_cells)
        or len(matrix_cells) != len(set(matrix_cells))
        or not set(order).issubset(set(matrix_cells))
    ):
        raise ValueError(f"{path.name}: qualification matrix cells are invalid")
    targeted = set(order) != set(matrix_cells)
    if status["targeted_selection"] is not targeted:
        raise ValueError(f"{path.name}: targeted selection metadata is invalid")
    if status["qualifying_complete"] is not (complete and not targeted):
        raise ValueError(f"{path.name}: qualifying completion metadata is invalid")
    return True


def validate_result_document(path: Path, cell_id: str, doc: dict[str, Any]) -> None:
    valid = doc.get("valid")
    classification = doc.get("classification")
    conditions = doc.get("conditions")
    invalid_reasons = doc.get("invalid_reasons")
    axes = doc.get("axes")
    metrics = doc.get("metrics")
    if type(valid) is not bool:
        raise ValueError(f"{path.name}/{cell_id}: valid is not boolean")
    if classification not in CLASSIFICATIONS:
        raise ValueError(f"{path.name}/{cell_id}: classification is invalid")
    if valid != (classification != "invalid"):
        raise ValueError(
            f"{path.name}/{cell_id}: validity and classification disagree"
        )
    if not isinstance(conditions, dict) or not all(
        type(value) is bool for value in conditions.values()
    ):
        raise ValueError(f"{path.name}/{cell_id}: conditions are not boolean")
    if not isinstance(axes, dict) or not isinstance(metrics, dict):
        raise ValueError(f"{path.name}/{cell_id}: axes or metrics are invalid")
    if (
        not isinstance(invalid_reasons, list)
        or not all(
            isinstance(reason, str) and reason for reason in invalid_reasons
        )
        or (valid and invalid_reasons)
        or (not valid and not invalid_reasons)
    ):
        raise ValueError(f"{path.name}/{cell_id}: invalid reasons disagree")
    if valid:
        goodput = metrics.get("goodput_mbps")
        if (
            not isinstance(goodput, (int, float))
            or isinstance(goodput, bool)
            or not math.isfinite(goodput)
            or goodput < 0
        ):
            raise ValueError(f"{path.name}/{cell_id}: goodput metric is invalid")
    if valid and axes.get("impairment_schedule") == "timed":
        for name in (
            "episode_below_half_pre",
            "mechanism_observed",
            "user_visible_disruption",
        ):
            if type(metrics.get(name)) is not bool:
                raise ValueError(
                    f"{path.name}/{cell_id}: timed metric {name} is not boolean"
                )
        for name in ("episode_min_5s_mbps", "episode_longest_stall_ms"):
            value = metrics.get(name)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(
                    f"{path.name}/{cell_id}: timed metric {name} is invalid"
                )
        for name in ("formal_meltdown", "quasi_meltdown_episode"):
            if type(conditions.get(name)) is not bool:
                raise ValueError(
                    f"{path.name}/{cell_id}: timed condition {name} is missing"
                )


def load_campaign(path: Path, *, allow_incomplete: bool = False) -> Campaign:
    status_path = path / "campaign-status.json"
    status = json.loads(status_path.read_text(encoding="utf-8-sig"))
    status_name = str(status.get("status", ""))
    complete = status_name == "complete"
    if not complete and not allow_incomplete:
        raise ValueError(f"{path.name}: campaign status is not complete")
    if status_name not in {"complete", "incomplete", "safety_stopped"}:
        raise ValueError(f"{path.name}: unsupported campaign status {status_name!r}")

    order = [str(cell) for cell in status.get("expected_cells", [])]
    expected = set(order)
    completed = {str(cell) for cell in status.get("completed_cells", [])}
    failed = {str(cell) for cell in status.get("failed_cells", [])}
    fingerprints = {
        str(cell): str(value)
        for cell, value in status.get("cell_fingerprints", {}).items()
    }
    if not order or len(order) != len(expected):
        raise ValueError(f"{path.name}: expected cell list is empty or duplicated")
    current_format = validate_qualification_metadata(path, status, order, complete)
    if complete and (expected != completed or failed):
        raise ValueError(f"{path.name}: completed/failed cell sets do not match")
    if not complete and (
        not completed <= expected
        or not failed <= expected
        or completed & failed
    ):
        raise ValueError(f"{path.name}: partial completed/failed cell sets are invalid")
    if set(fingerprints) != expected or not all(
        HEX64.fullmatch(value) for value in fingerprints.values()
    ):
        raise ValueError(f"{path.name}: fingerprint manifest does not match cells")

    campaign_fingerprint = str(status.get("campaign_fingerprint", ""))
    if not HEX64.fullmatch(campaign_fingerprint):
        raise ValueError(f"{path.name}: invalid campaign fingerprint")
    docs: dict[str, dict[str, Any]] = {}
    result_hashes: dict[str, str] = {}
    identities: set[tuple[str, ...]] = set()
    for cell_id in order:
        if cell_id not in completed:
            continue
        cell = path / "cells" / cell_id
        required = (
            cell / "cell.complete",
            cell / "cell.env",
            cell / "cell.fingerprint",
            cell / "cell.json",
        )
        missing = [item.name for item in required if not item.is_file()]
        if missing:
            raise ValueError(
                f"{path.name}/{cell_id}: missing {', '.join(sorted(missing))}"
            )

        fingerprint = (cell / "cell.fingerprint").read_text(encoding="ascii").strip()
        env = read_env(cell / "cell.env")
        doc_bytes = (cell / "cell.json").read_bytes()
        doc = json.loads(doc_bytes.decode("utf-8-sig"))
        if not HEX64.fullmatch(fingerprint):
            raise ValueError(f"{path.name}/{cell_id}: invalid cell fingerprint")
        if fingerprint != fingerprints[cell_id]:
            raise ValueError(f"{path.name}/{cell_id}: fingerprint file mismatch")
        if env.get("cell_fingerprint") != fingerprint:
            raise ValueError(f"{path.name}/{cell_id}: environment fingerprint mismatch")
        if env.get("campaign_fingerprint") != campaign_fingerprint:
            raise ValueError(f"{path.name}/{cell_id}: campaign fingerprint mismatch")
        if doc.get("cell_id") != cell_id:
            raise ValueError(f"{path.name}/{cell_id}: cell document identity mismatch")
        validate_result_document(path, cell_id, doc)
        for key, value in doc.get("axes", {}).items():
            if env.get(key) != str(value):
                raise ValueError(f"{path.name}/{cell_id}: cell axis {key} mismatch")

        identity = tuple(env.get(key, "") for key in IDENTITY_KEYS)
        has_iperf_version = bool(identity[3])
        has_iperf_hash = bool(identity[4])
        if (
            not SRCVERSION.fullmatch(identity[0])
            or not HEX64.fullmatch(identity[1])
            or not HEX64.fullmatch(identity[2])
            or has_iperf_version != has_iperf_hash
            or (current_format and not has_iperf_version)
            or (
                has_iperf_version
                and (
                    len(identity[3]) > 160
                    or not all(" " <= character <= "~" for character in identity[3])
                )
            )
            or (identity[4] and not HEX64.fullmatch(identity[4]))
        ):
            raise ValueError(f"{path.name}/{cell_id}: runtime identity is incomplete")
        identities.add(identity)
        docs[cell_id] = doc
        result_hashes[cell_id] = hashlib.sha256(doc_bytes).hexdigest()

    if len(identities) > 1 or (complete and len(identities) != 1):
        raise ValueError(f"{path.name}: runtime identity changes between cells")
    identity_tuple = identities.pop() if identities else ()
    return Campaign(
        path=path,
        status=status,
        order=order,
        docs=docs,
        fingerprints=fingerprints,
        result_hashes=result_hashes,
        identity=dict(zip(IDENTITY_KEYS, identity_tuple)),
    )


def require_qualifying_base(campaign: Campaign) -> None:
    if not all(field in campaign.status for field in QUALIFICATION_FIELDS):
        raise ValueError(
            f"{campaign.path.name}: explicit qualifying base metadata is required"
        )

    matrix_cells = campaign.status["matrix_expected_cells"]
    if (
        not isinstance(matrix_cells, list)
        or not all(isinstance(cell, str) for cell in matrix_cells)
        or matrix_cells != campaign.order
        or campaign.status["targeted_selection"] is not False
        or campaign.status["qualifying_complete"] is not True
    ):
        raise ValueError(
            f"{campaign.path.name}: targeted or incomplete campaign cannot be a "
            "qualifying base"
        )


def write_composite(
    base: Campaign,
    replacement: Campaign,
    output: Path,
) -> dict[str, Any]:
    require_qualifying_base(base)
    if base.identity != replacement.identity:
        raise ValueError("base and replacement runtime identities differ")

    replacement_ids = set(replacement.order)
    if not replacement_ids <= set(base.order):
        extra = sorted(replacement_ids - set(base.order))
        raise ValueError(f"replacement contains cells absent from base: {extra}")

    for cell_id in replacement.order:
        old = base.docs[cell_id]
        new = replacement.docs[cell_id]
        if old.get("valid") or old.get("classification") != "invalid":
            raise ValueError(f"{cell_id}: replacement would overwrite valid evidence")
        if not new.get("valid") or new.get("classification") == "invalid":
            raise ValueError(f"{cell_id}: replacement evidence is not valid")
        if old.get("axes") != new.get("axes"):
            raise ValueError(f"{cell_id}: replacement matrix axes differ")

    merged = [
        json.loads(json.dumps(replacement.docs.get(cell_id, base.docs[cell_id])))
        for cell_id in base.order
    ]
    apply_udp_control_comparison(merged)
    invalid = [
        str(doc.get("cell_id"))
        for doc in merged
        if not doc.get("valid") or doc.get("classification") == "invalid"
    ]
    if invalid:
        raise ValueError(f"composite still contains invalid cells: {invalid}")

    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    with (output / "cells.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()
        for doc in merged:
            writer.writerow(flatten(doc))
    write_report(output / "REPORT.md", merged)

    provenance_fields = (
        "cell_id",
        "source_campaign",
        "campaign_fingerprint",
        "cell_fingerprint",
        "cell_json_sha256",
        "replaced_base_invalid",
    )
    with (output / "provenance.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=provenance_fields)
        writer.writeheader()
        for cell_id in base.order:
            source = replacement if cell_id in replacement_ids else base
            writer.writerow(
                {
                    "cell_id": cell_id,
                    "source_campaign": source.path.name,
                    "campaign_fingerprint": source.fingerprint,
                    "cell_fingerprint": source.fingerprints[cell_id],
                    "cell_json_sha256": source.result_hashes[cell_id],
                    "replaced_base_invalid": str(cell_id in replacement_ids).lower(),
                }
            )

    counts = Counter(str(doc.get("classification", "unknown")) for doc in merged)
    composite_status = {
        "status": "qualified-composite",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expected_cells": base.order,
        "counts": dict(sorted(counts.items())),
        "runtime_identity": base.identity,
        "source_campaigns": [
            {
                "name": base.path.name,
                "campaign_fingerprint": base.fingerprint,
                "included_cells": len(base.order) - len(replacement_ids),
            },
            {
                "name": replacement.path.name,
                "campaign_fingerprint": replacement.fingerprint,
                "included_cells": len(replacement_ids),
            },
        ],
        "replacements": replacement.order,
        "provenance": "provenance.csv",
    }
    (output / "composite-status.json").write_text(
        json.dumps(composite_status, indent=2) + "\n",
        encoding="utf-8",
    )
    return composite_status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--replacement", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    status = write_composite(
        load_campaign(args.base),
        load_campaign(args.replacement),
        args.output,
    )
    print(json.dumps(status, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
