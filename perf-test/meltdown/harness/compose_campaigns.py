#!/usr/bin/env python3
"""Compose sharded campaign attempts without hiding incomplete evidence."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from analyze import apply_udp_control_comparison
from merge_campaigns import Campaign, QUALIFICATION_FIELDS, load_campaign


MATRIX_METADATA_FIELDS = {"stage", "enabled", "name", "repetitions"}
ATTEMPT_FIELDS = (
    "cell_id",
    "attempt",
    "source_campaign",
    "campaign_status",
    "campaign_fingerprint",
    "cell_fingerprint",
    "outcome",
    "safety_stop",
    "selected",
    "valid",
    "raw_classification",
    "selected_classification",
    "formal_meltdown",
    "quasi_meltdown_episode",
    "invalid_reasons",
    "stop_reasons",
    "cell_json_sha256",
    "evidence_tree_sha256",
    "evidence_file_count",
)
LOGICAL_FIELDS = (
    "cell_id",
    "state",
    "attempts",
    "rerun_consumed",
    "retry_available",
    "selected_campaign",
    "selected_attempt",
    "cell_fingerprint",
    "cell_json_sha256",
    "evidence_tree_sha256",
    "valid",
    "classification",
    "formal_meltdown",
    "quasi_meltdown_episode",
    "latest_outcome",
    "safety_stop",
    "stop_reasons",
)
SELECTED_FIELDS = (
    "cell_id",
    "source_campaign",
    "campaign_fingerprint",
    "cell_fingerprint",
    "cell_json_sha256",
    "evidence_tree_sha256",
    "tunnel",
    "burst_p",
    "burst_r",
    "valid",
    "classification",
    "formal_meltdown",
    "pre_median_mbps",
    "impairment_mean_mbps",
    "episode_min_1s_mbps",
    "episode_min_5s_mbps",
    "udp_control_episode_min_5s_ratio",
    "episode_longest_stall_ms",
    "recovery_90_ms",
    "bandwidth_deficit_mbit",
    "outer_recovery_events",
    "inner_rto",
    "mechanism_observed",
    "user_visible_disruption",
    "quasi_meltdown_episode",
    "timed_impairment_valid",
    "invalid_reasons",
)
SOURCE_FIELDS = (
    "input_order",
    "source_campaign",
    "status",
    "updated_at",
    "campaign_fingerprint",
    "expected_cells",
    "completed_cells",
    "failed_cells",
    "campaign_status_sha256",
    "safety_stop_sha256",
)
PROFILE_FIELDS = (
    "profile",
    "mean_bad_state_residence_packets",
    "planned_cells",
    "selected_valid_cells",
    "selected_valid_tcp",
    "selected_valid_udp",
    "qualified_matched_pairs",
    "qualified_tcp_quasi_meltdowns",
    "selected_formal_meltdowns",
    "unresolved_cells",
    "unrun_cells",
    "onset_rule_met",
    "state",
)
AUDIT_FIELDS = (
    "name",
    "source_directory",
    "file_count",
    "tree_sha256",
)
CELL_PATTERN = re.compile(r"^(.*)-(tcp|udp)-r(\d+)$")
RESIDENCE_PATTERN = re.compile(r"(?:^|-)ge-res([0-9]+(?:\.[0-9]+)?)(?:-|$)")


@dataclass(frozen=True)
class Matrix:
    order: list[str]
    axes: dict[str, dict[str, str]]
    sha256: str


@dataclass
class Attempt:
    cell_id: str
    attempt: int
    campaign: Campaign
    outcome: str
    cell_fingerprint: str
    cell_json_sha256: str
    evidence_tree_sha256: str
    evidence_file_count: int
    stop_reasons: list[str]
    safety_stop: bool
    selected: bool = False

    @property
    def doc(self) -> dict[str, Any] | None:
        return self.campaign.docs.get(self.cell_id)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(path: Path) -> tuple[str, int]:
    if path.is_symlink():
        raise ValueError(f"evidence tree root is a symlink: {path}")
    if not path.is_dir():
        return "", 0
    files: list[Path] = []
    for item in path.rglob("*"):
        if item.is_symlink():
            raise ValueError(f"evidence tree contains a symlink: {item}")
        if item.is_dir():
            continue
        if not item.is_file():
            raise ValueError(f"evidence tree contains a special entry: {item}")
        files.append(item)
    files.sort(key=lambda item: item.relative_to(path).as_posix())
    digest = hashlib.sha256()
    for item in files:
        relative = item.relative_to(path).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(item.read_bytes()).digest())
        digest.update(b"\n")
    return digest.hexdigest(), len(files)


def load_matrix(path: Path) -> Matrix:
    data = path.read_bytes()
    rows = list(csv.DictReader(data.decode("utf-8-sig").splitlines()))
    if not rows:
        raise ValueError("matrix contains no rows")
    required = {"stage", "enabled", "name", "tunnel", "repetitions"}
    if not required <= set(rows[0]):
        raise ValueError("matrix is missing required fields")

    order: list[str] = []
    axes: dict[str, dict[str, str]] = {}
    for row in rows:
        enabled = str(row.get("enabled", ""))
        if enabled not in {"0", "1"}:
            raise ValueError("matrix enabled values must be 0 or 1")
        if enabled == "0":
            continue
        try:
            repetitions = int(str(row["repetitions"]))
        except ValueError as error:
            raise ValueError("matrix repetitions must be integers") from error
        if repetitions <= 0:
            raise ValueError("matrix repetitions must be positive")
        stage = str(row["stage"])
        name = str(row["name"])
        tunnel = str(row["tunnel"])
        if not stage or not name or tunnel not in {"tcp", "udp"}:
            raise ValueError("matrix cell identity is invalid")
        expected_axes = {
            str(key): str(value)
            for key, value in row.items()
            if key not in MATRIX_METADATA_FIELDS
        }
        for repetition in range(1, repetitions + 1):
            cell_id = f"{stage}-{name}-{tunnel}-r{repetition}"
            if cell_id in axes:
                raise ValueError(f"matrix contains duplicate cell {cell_id}")
            order.append(cell_id)
            axes[cell_id] = expected_axes
    if not order:
        raise ValueError("matrix contains no enabled cells")
    return Matrix(order=order, axes=axes, sha256=hashlib.sha256(data).hexdigest())


def campaign_updated_at(campaign: Campaign) -> datetime:
    raw = campaign.status.get("updated_at")
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{campaign.path.name}: updated_at is missing")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{campaign.path.name}: updated_at is invalid") from error
    if value.tzinfo is None:
        raise ValueError(f"{campaign.path.name}: updated_at lacks a timezone")
    return value.astimezone(timezone.utc)


def validate_shard(path: Path, matrix: Matrix) -> Campaign:
    campaign = load_campaign(path, allow_incomplete=True)
    campaign_updated_at(campaign)
    if not campaign.identity:
        raise ValueError(f"{path.name}: shard runtime identity is unavailable")
    if not all(field in campaign.status for field in QUALIFICATION_FIELDS):
        raise ValueError(
            f"{path.name}: explicit matrix qualification metadata required"
        )
    if campaign.status["matrix_expected_cells"] != matrix.order:
        raise ValueError(f"{path.name}: matrix expected cells differ")
    if not set(campaign.order) <= set(matrix.order):
        raise ValueError(f"{path.name}: shard contains cells absent from matrix")

    manifested = set(campaign.status["completed_cells"]) | set(
        campaign.status["failed_cells"]
    )
    cells_path = path / "cells"
    if not cells_path.is_dir():
        raise ValueError(f"{path.name}: cells directory is unavailable")
    for item in cells_path.iterdir():
        if item.is_symlink() or not item.is_dir():
            raise ValueError(f"{path.name}: unexpected cells entry {item.name}")
        if item.name not in manifested and next(item.rglob("*"), None) is not None:
            raise ValueError(
                f"{path.name}/{item.name}: unmanifested cell evidence is present"
            )

    for cell_id, doc in campaign.docs.items():
        doc_axes = doc.get("axes", {})
        for key, value in matrix.axes[cell_id].items():
            if str(doc_axes.get(key, "")) != value:
                raise ValueError(f"{path.name}/{cell_id}: matrix axis {key} differs")
    return campaign


def load_stop(campaign: Campaign) -> tuple[str, list[str], str] | None:
    path = campaign.path / "campaign-safety-stop.json"
    if campaign.status["status"] != "safety_stopped":
        if path.exists():
            raise ValueError(f"{campaign.path.name}: unexpected safety-stop record")
        return None
    if not path.is_file():
        raise ValueError(f"{campaign.path.name}: safety-stop record is missing")
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    cell_id = str(document.get("cell_id", ""))
    reasons = document.get("reasons", [])
    manifested = set(campaign.status["completed_cells"]) | set(
        campaign.status["failed_cells"]
    )
    if (
        document.get("status") != "safety_stopped"
        or cell_id not in manifested
        or document.get("campaign_fingerprint") != campaign.fingerprint
        or not isinstance(reasons, list)
        or not reasons
        or not all(isinstance(reason, str) and reason for reason in reasons)
    ):
        raise ValueError(f"{campaign.path.name}: safety-stop record is invalid")
    return cell_id, list(reasons), sha256_file(path)


def load_attempts(
    campaigns: list[Campaign],
) -> tuple[dict[str, list[Attempt]], list[dict[str, Any]]]:
    attempts: dict[str, list[Attempt]] = defaultdict(list)
    sources: list[dict[str, Any]] = []
    known_identity: dict[str, str] | None = None
    stop_latched = False

    for input_order, campaign in enumerate(campaigns, start=1):
        if known_identity is None:
            known_identity = campaign.identity
        elif known_identity != campaign.identity:
            raise ValueError("campaign runtime identities differ")
        completed = set(campaign.status["completed_cells"])
        failed = set(campaign.status["failed_cells"])
        if stop_latched and (completed or failed):
            raise ValueError(
                f"{campaign.path.name}: campaign follows a safety stop"
            )
        stop = load_stop(campaign)
        stop_cell = stop[0] if stop else ""
        stop_reasons = stop[1] if stop else []
        stop_hash = stop[2] if stop else ""
        manifested = completed | failed
        if stop:
            stop_index = campaign.order.index(stop_cell)
            if any(
                cell_id in manifested
                for cell_id in campaign.order[stop_index + 1 :]
            ):
                raise ValueError(
                    f"{campaign.path.name}: safety-stop cell is not final"
                )

        for cell_id in campaign.order:
            outcome = ""
            reasons: list[str] = []
            if cell_id in completed:
                doc = campaign.docs[cell_id]
                outcome = (
                    "valid"
                    if doc.get("valid") is True
                    and doc.get("classification") != "invalid"
                    else "invalid"
                )
            elif cell_id in failed:
                outcome = "stopped" if cell_id == stop_cell else "failed"
            else:
                continue
            is_stop = cell_id == stop_cell
            reasons = stop_reasons if is_stop else []
            evidence_path = campaign.path / "cells" / cell_id
            evidence_hash, evidence_count = tree_digest(evidence_path)
            if not evidence_hash or evidence_count == 0:
                raise ValueError(
                    f"{campaign.path.name}/{cell_id}: attempt evidence is missing"
                )
            attempts[cell_id].append(
                Attempt(
                    cell_id=cell_id,
                    attempt=len(attempts[cell_id]) + 1,
                    campaign=campaign,
                    outcome=outcome,
                    cell_fingerprint=campaign.fingerprints[cell_id],
                    cell_json_sha256=campaign.result_hashes.get(cell_id, ""),
                    evidence_tree_sha256=evidence_hash,
                    evidence_file_count=evidence_count,
                    stop_reasons=reasons,
                    safety_stop=is_stop,
                )
            )

        sources.append(
            {
                "input_order": input_order,
                "source_campaign": campaign.path.name,
                "status": campaign.status["status"],
                "updated_at": campaign.status["updated_at"],
                "campaign_fingerprint": campaign.fingerprint,
                "expected_cells": len(campaign.order),
                "completed_cells": len(completed),
                "failed_cells": len(failed),
                "campaign_status_sha256": sha256_file(
                    campaign.path / "campaign-status.json"
                ),
                "safety_stop_sha256": stop_hash,
            }
        )
        stop_latched = stop_latched or stop is not None

    for cell_id, cell_attempts in attempts.items():
        if len(cell_attempts) > 2:
            raise ValueError(f"{cell_id}: more than one rerun is present")
        if len(cell_attempts) == 2:
            if campaign_updated_at(
                cell_attempts[0].campaign
            ) >= campaign_updated_at(cell_attempts[1].campaign):
                raise ValueError(f"{cell_id}: rerun chronology is invalid")
            if cell_attempts[0].safety_stop:
                raise ValueError(f"{cell_id}: safety-stopped evidence was rerun")
            if (
                cell_attempts[0].campaign.fingerprint
                != cell_attempts[1].campaign.fingerprint
            ):
                raise ValueError(f"{cell_id}: rerun campaign fingerprint differs")
            if (
                cell_attempts[0].cell_fingerprint
                != cell_attempts[1].cell_fingerprint
            ):
                raise ValueError(f"{cell_id}: rerun fingerprint differs")
            if cell_attempts[0].outcome == "valid":
                raise ValueError(f"{cell_id}: valid evidence was rerun")
            if cell_attempts[0].outcome != "invalid":
                raise ValueError(f"{cell_id}: only invalid evidence may be rerun")
    return attempts, sources


def select_documents(
    matrix: Matrix,
    attempts: dict[str, list[Attempt]],
) -> tuple[dict[str, dict[str, Any]], dict[str, Attempt]]:
    selected_attempts: dict[str, Attempt] = {}
    selected_docs: list[dict[str, Any]] = []
    for cell_id in matrix.order:
        cell_attempts = attempts.get(cell_id, [])
        if cell_attempts and cell_attempts[-1].outcome == "valid":
            selected = cell_attempts[-1]
            selected.selected = True
            selected_attempts[cell_id] = selected
            selected_docs.append(copy.deepcopy(selected.doc))
    for cell_id, selected in selected_attempts.items():
        match = CELL_PATTERN.fullmatch(cell_id)
        if match is None or match.group(2) != "tcp":
            continue
        udp_id = f"{match.group(1)}-udp-r{match.group(3)}"
        udp = selected_attempts.get(udp_id)
        if udp and udp.campaign.fingerprint != selected.campaign.fingerprint:
            raise ValueError(f"{cell_id}: matched control pair differs")
    apply_udp_control_comparison(selected_docs)
    return (
        {str(document["cell_id"]): document for document in selected_docs},
        selected_attempts,
    )


def bool_text(value: Any) -> str:
    return str(bool(value)).lower()


def write_csv(
    path: Path,
    fields: Iterable[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(fields),
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def condition(document: dict[str, Any], name: str) -> bool:
    return document.get("conditions", {}).get(name) is True


def metric(document: dict[str, Any], name: str) -> Any:
    return document.get("metrics", {}).get(name)


def attempt_row(
    attempt: Attempt,
    selected_docs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    document = attempt.doc or {}
    selected_document = (
        selected_docs.get(attempt.cell_id, {}) if attempt.selected else {}
    )
    return {
        "cell_id": attempt.cell_id,
        "attempt": attempt.attempt,
        "source_campaign": attempt.campaign.path.name,
        "campaign_status": attempt.campaign.status["status"],
        "campaign_fingerprint": attempt.campaign.fingerprint,
        "cell_fingerprint": attempt.cell_fingerprint,
        "outcome": attempt.outcome,
        "safety_stop": bool_text(attempt.safety_stop),
        "selected": bool_text(attempt.selected),
        "valid": bool_text(document.get("valid")) if document else "",
        "raw_classification": document.get("classification", ""),
        "selected_classification": selected_document.get("classification", ""),
        "formal_meltdown": bool_text(condition(document, "formal_meltdown"))
        if document
        else "",
        "quasi_meltdown_episode": bool_text(
            condition(document, "quasi_meltdown_episode")
        )
        if document
        else "",
        "invalid_reasons": ";".join(document.get("invalid_reasons", [])),
        "stop_reasons": ";".join(attempt.stop_reasons),
        "cell_json_sha256": attempt.cell_json_sha256,
        "evidence_tree_sha256": attempt.evidence_tree_sha256,
        "evidence_file_count": attempt.evidence_file_count,
    }


def logical_rows(
    matrix: Matrix,
    attempts: dict[str, list[Attempt]],
    selected_docs: dict[str, dict[str, Any]],
    selected_attempts: dict[str, Attempt],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cell_id in matrix.order:
        cell_attempts = attempts.get(cell_id, [])
        selected = selected_attempts.get(cell_id)
        document = selected_docs.get(cell_id, {})
        latest = cell_attempts[-1] if cell_attempts else None
        state = (
            "selected_valid"
            if selected
            else (latest.outcome if latest else "unrun")
        )
        rows.append(
            {
                "cell_id": cell_id,
                "state": state,
                "attempts": len(cell_attempts),
                "rerun_consumed": bool_text(len(cell_attempts) == 2),
                "retry_available": bool_text(
                    len(cell_attempts) == 1
                    and latest is not None
                    and latest.outcome == "invalid"
                    and not latest.safety_stop
                ),
                "selected_campaign": selected.campaign.path.name if selected else "",
                "selected_attempt": selected.attempt if selected else "",
                "cell_fingerprint": (
                    selected.cell_fingerprint
                    if selected
                    else (latest.cell_fingerprint if latest else "")
                ),
                "cell_json_sha256": selected.cell_json_sha256 if selected else "",
                "evidence_tree_sha256": (
                    selected.evidence_tree_sha256
                    if selected
                    else (latest.evidence_tree_sha256 if latest else "")
                ),
                "valid": bool_text(document.get("valid")) if selected else "",
                "classification": document.get("classification", ""),
                "formal_meltdown": bool_text(
                    condition(document, "formal_meltdown")
                )
                if selected
                else "",
                "quasi_meltdown_episode": bool_text(
                    condition(document, "quasi_meltdown_episode")
                )
                if selected
                else "",
                "latest_outcome": latest.outcome if latest else "",
                "safety_stop": bool_text(
                    any(attempt.safety_stop for attempt in cell_attempts)
                ),
                "stop_reasons": ";".join(
                    reason
                    for attempt in cell_attempts
                    for reason in attempt.stop_reasons
                ),
            }
        )
    return rows


def selected_rows(
    matrix: Matrix,
    selected_docs: dict[str, dict[str, Any]],
    selected_attempts: dict[str, Attempt],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cell_id in matrix.order:
        if cell_id not in selected_docs:
            continue
        document = selected_docs[cell_id]
        selected = selected_attempts[cell_id]
        axes = document.get("axes", {})
        rows.append(
            {
                "cell_id": cell_id,
                "source_campaign": selected.campaign.path.name,
                "campaign_fingerprint": selected.campaign.fingerprint,
                "cell_fingerprint": selected.cell_fingerprint,
                "cell_json_sha256": selected.cell_json_sha256,
                "evidence_tree_sha256": selected.evidence_tree_sha256,
                "tunnel": axes.get("tunnel"),
                "burst_p": axes.get("burst_p"),
                "burst_r": axes.get("burst_r"),
                "valid": document.get("valid"),
                "classification": document.get("classification"),
                "formal_meltdown": condition(document, "formal_meltdown"),
                "pre_median_mbps": metric(document, "pre_median_mbps"),
                "impairment_mean_mbps": metric(
                    document, "impairment_mean_mbps"
                ),
                "episode_min_1s_mbps": metric(document, "episode_min_1s_mbps"),
                "episode_min_5s_mbps": metric(document, "episode_min_5s_mbps"),
                "udp_control_episode_min_5s_ratio": metric(
                    document, "udp_control_episode_min_5s_ratio"
                ),
                "episode_longest_stall_ms": metric(
                    document, "episode_longest_stall_ms"
                ),
                "recovery_90_ms": metric(document, "recovery_90_ms"),
                "bandwidth_deficit_mbit": metric(
                    document, "bandwidth_deficit_mbit"
                ),
                "outer_recovery_events": metric(
                    document, "outer_recovery_events"
                ),
                "inner_rto": metric(document, "inner_rto"),
                "mechanism_observed": metric(document, "mechanism_observed"),
                "user_visible_disruption": metric(
                    document, "user_visible_disruption"
                ),
                "quasi_meltdown_episode": condition(
                    document, "quasi_meltdown_episode"
                ),
                "timed_impairment_valid": metric(
                    document, "timed_impairment_valid"
                ),
                "invalid_reasons": ";".join(document.get("invalid_reasons", [])),
            }
        )
    return rows


def profile_rows(
    matrix: Matrix,
    logical: list[dict[str, Any]],
    selected_docs: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    by_cell = {str(row["cell_id"]): row for row in logical}
    profiles: dict[str, list[str]] = {}
    for cell_id in matrix.order:
        match = CELL_PATTERN.fullmatch(cell_id)
        if match:
            profiles.setdefault(match.group(1), []).append(cell_id)

    rows: list[dict[str, Any]] = []
    for profile, cell_ids in profiles.items():
        selected = [cell_id for cell_id in cell_ids if cell_id in selected_docs]
        tcp = [cell_id for cell_id in selected if "-tcp-r" in cell_id]
        udp = [cell_id for cell_id in selected if "-udp-r" in cell_id]
        matched_tcp: list[str] = []
        for tcp_id in tcp:
            match = CELL_PATTERN.fullmatch(tcp_id)
            if match is None:
                raise ValueError(f"selected cell identity is invalid: {tcp_id}")
            udp_id = f"{match.group(1)}-udp-r{match.group(3)}"
            if udp_id in selected_docs:
                matched_tcp.append(tcp_id)
        unresolved = [
            cell_id
            for cell_id in cell_ids
            if by_cell[cell_id]["state"] not in {"selected_valid", "unrun"}
        ]
        unrun = [
            cell_id
            for cell_id in cell_ids
            if by_cell[cell_id]["state"] == "unrun"
        ]
        state = (
            "qualified"
            if len(selected) == len(cell_ids)
            else ("unrun" if len(unrun) == len(cell_ids) else "incomplete")
        )
        residence = RESIDENCE_PATTERN.search(profile)
        quasi_count = sum(
            condition(selected_docs[cell_id], "quasi_meltdown_episode")
            for cell_id in matched_tcp
        )
        rows.append(
            {
                "profile": profile,
                "mean_bad_state_residence_packets": (
                    residence.group(1) if residence else ""
                ),
                "planned_cells": len(cell_ids),
                "selected_valid_cells": len(selected),
                "selected_valid_tcp": len(tcp),
                "selected_valid_udp": len(udp),
                "qualified_matched_pairs": len(matched_tcp),
                "qualified_tcp_quasi_meltdowns": quasi_count,
                "selected_formal_meltdowns": sum(
                    condition(selected_docs[cell_id], "formal_meltdown")
                    for cell_id in selected
                ),
                "unresolved_cells": len(unresolved),
                "unrun_cells": len(unrun),
                "onset_rule_met": bool_text(
                    state == "qualified"
                    and len(matched_tcp) == 3
                    and quasi_count >= 2
                ),
                "state": state,
            }
        )
    return rows


def parse_named_paths(values: list[str]) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    names: set[str] = set()
    for value in values:
        if "=" not in value:
            raise ValueError("audit evidence must use NAME=PATH")
        name, raw_path = value.split("=", 1)
        if not name or name in names:
            raise ValueError("audit evidence names must be nonempty and unique")
        path = Path(raw_path)
        if not path.is_dir():
            raise ValueError(f"audit evidence directory is unavailable: {path}")
        names.add(name)
        result.append((name, path))
    return result


def write_composition(
    matrix: Matrix,
    campaigns: list[Campaign],
    output: Path,
    audit_paths: list[tuple[str, Path]] | None = None,
) -> dict[str, Any]:
    if not campaigns:
        raise ValueError("at least one campaign shard is required")
    names = [campaign.path.name for campaign in campaigns]
    if len(names) != len(set(names)):
        raise ValueError("campaign source directory names must be unique")
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory is not empty: {output}")

    attempts, source_rows = load_attempts(campaigns)
    selected_docs, selected_attempts = select_documents(matrix, attempts)
    logical = logical_rows(matrix, attempts, selected_docs, selected_attempts)
    attempts_flat = [
        attempt
        for cell_id in matrix.order
        for attempt in attempts.get(cell_id, [])
    ]
    audit_rows = []
    for name, path in audit_paths or []:
        digest, count = tree_digest(path)
        audit_rows.append(
            {
                "name": name,
                "source_directory": path.name,
                "file_count": count,
                "tree_sha256": digest,
            }
        )

    output.mkdir(parents=True, exist_ok=True)
    write_csv(
        output / "attempts.csv",
        ATTEMPT_FIELDS,
        (attempt_row(attempt, selected_docs) for attempt in attempts_flat),
    )
    write_csv(output / "logical-cells.csv", LOGICAL_FIELDS, logical)
    write_csv(
        output / "selected-cells.csv",
        SELECTED_FIELDS,
        selected_rows(matrix, selected_docs, selected_attempts),
    )
    profiles = profile_rows(matrix, logical, selected_docs)
    write_csv(output / "profiles.csv", PROFILE_FIELDS, profiles)
    write_csv(output / "source-campaigns.csv", SOURCE_FIELDS, source_rows)
    write_csv(output / "audit-evidence.csv", AUDIT_FIELDS, audit_rows)

    logical_counts = Counter(str(row["state"]) for row in logical)
    attempt_counts = Counter(attempt.outcome for attempt in attempts_flat)
    classification_counts = Counter(
        str(document.get("classification", "unknown"))
        for document in selected_docs.values()
    )
    safety_stop_count = sum(attempt.safety_stop for attempt in attempts_flat)
    stop_present = safety_stop_count > 0
    all_selected = logical_counts.get("selected_valid", 0) == len(matrix.order)
    if stop_present:
        status_name = (
            "stopped-complete-selection"
            if all_selected
            else "stopped-incomplete-selection"
        )
    else:
        status_name = "complete-selection" if all_selected else "incomplete-selection"
    identities = [campaign.identity for campaign in campaigns if campaign.identity]
    status = {
        "status": status_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "matrix_sha256": matrix.sha256,
        "matrix_cells": len(matrix.order),
        "attempts": len(attempts_flat),
        "analyzable_attempts": attempt_counts.get("valid", 0)
        + attempt_counts.get("invalid", 0),
        "safety_stops": safety_stop_count,
        "attempt_outcomes": dict(sorted(attempt_counts.items())),
        "logical_states": dict(sorted(logical_counts.items())),
        "selected_classifications": dict(sorted(classification_counts.items())),
        "runtime_identity": identities[0] if identities else {},
        "source_campaigns": names,
        "audit_evidence": audit_rows,
        "files": {
            "attempts": "attempts.csv",
            "logical_cells": "logical-cells.csv",
            "selected_cells": "selected-cells.csv",
            "profiles": "profiles.csv",
            "source_campaigns": "source-campaigns.csv",
            "audit_evidence": "audit-evidence.csv",
        },
    }
    with (output / "composition-status.json").open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        handle.write(json.dumps(status, indent=2) + "\n")
    manifest_rows = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.name != "sha256-manifest.txt":
            manifest_rows.append(f"{sha256_file(path)}  {path.name}")
    with (output / "sha256-manifest.txt").open(
        "w",
        encoding="ascii",
        newline="\n",
    ) as handle:
        handle.write("\n".join(manifest_rows) + "\n")
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, action="append", required=True)
    parser.add_argument("--audit-evidence", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    matrix = load_matrix(args.matrix)
    campaigns = [validate_shard(path, matrix) for path in args.campaign]
    status = write_composition(
        matrix,
        campaigns,
        args.output,
        parse_named_paths(args.audit_evidence),
    )
    print(json.dumps(status, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
