"""Deterministic, bounded pilot-manifest construction for the RanDS raw release."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
from typing import Any

import yaml

from malweave.config import PROJECT_ROOT
from malweave.data.dataset_config import RandsDatasetConfig
from malweave.data.rands import (
    RandsRecord,
    _validate_manifest_path,
    hash_file_sha256,
    inspect_rands,
)

LABEL_IDS = {"benign": 0, "ransomware": 1}
MANIFEST_FIELDS = (
    "source_sha256",
    "label",
    "label_id",
    "family",
    "extension",
    "arch",
    "packed",
    "year",
    "available",
    "relative_path",
    "selection_rank",
    "family_eligible_count",
    "family_target",
    "source_hash_verified",
    "snapshot",
    "selection_seed",
)


class RandsPilotError(ValueError):
    """Raised when the configured pilot cannot be selected safely."""


@dataclass(frozen=True)
class RandsPilotConfig:
    """Committed selection rules for one local RanDS pilot."""

    name: str
    snapshot: str
    extensions: tuple[str, ...]
    arch: str
    packed: bool
    target_labels: dict[str, int]
    selection_seed: str


@dataclass(frozen=True)
class PilotRecord:
    """One selected source plus the deterministic selection metadata."""

    record: RandsRecord
    selection_rank: str
    family_eligible_count: int | None
    family_target: int | None


@dataclass(frozen=True)
class RandsPilotBuild:
    """The local manifest bytes and aggregate evidence from one build attempt."""

    manifest_bytes: bytes | None
    selected: tuple[PilotRecord, ...]
    summary: dict[str, Any]

    @property
    def passed(self) -> bool:
        return self.manifest_bytes is not None


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RandsPilotError(f"{name} must be a mapping.")
    return value


def _required_string(mapping: dict[str, Any], key: str, scope: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RandsPilotError(f"{scope}.{key} must be a non-empty string.")
    return value


def _required_nonnegative_int(mapping: dict[str, Any], key: str, scope: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RandsPilotError(f"{scope}.{key} must be a non-negative integer.")
    return value


def load_rands_pilot_config(path: Path) -> RandsPilotConfig:
    """Load the small, explicit configuration that controls pilot selection."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RandsPilotError(f"Pilot config does not exist: {path}") from error
    except yaml.YAMLError as error:
        raise RandsPilotError(f"Invalid YAML in pilot config {path}: {error}") from error

    root = _mapping(raw, "config")
    protocol = _mapping(root.get("protocol"), "protocol")
    cohort = _mapping(root.get("cohort"), "cohort")
    required_metadata = _mapping(cohort.get("required_metadata"), "cohort.required_metadata")
    pilot = _mapping(root.get("pilot"), "pilot")
    selection = _mapping(pilot.get("selection"), "pilot.selection")
    targets = _mapping(pilot.get("target_labels"), "pilot.target_labels")

    if protocol.get("phase") != 2:
        raise RandsPilotError("protocol.phase must be 2 for pilot-manifest generation.")
    if selection.get("method") != "sha256_rank":
        raise RandsPilotError("pilot.selection.method must be sha256_rank.")
    allocation = _mapping(
        selection.get("ransomware_family_allocation"),
        "pilot.selection.ransomware_family_allocation",
    )
    if allocation.get("method") != "proportional_largest_remainder":
        raise RandsPilotError(
            "pilot.selection.ransomware_family_allocation.method must be "
            "proportional_largest_remainder."
        )

    extensions_raw = required_metadata.get("extensions")
    if not isinstance(extensions_raw, list) or not extensions_raw:
        raise RandsPilotError("cohort.required_metadata.extensions must be a non-empty list.")
    extensions = tuple(sorted({item.lower() for item in extensions_raw if isinstance(item, str)}))
    if len(extensions) != len(extensions_raw) or any(not extension for extension in extensions):
        raise RandsPilotError(
            "cohort.required_metadata.extensions must contain unique non-empty strings."
        )

    packed = required_metadata.get("packed")
    if not isinstance(packed, (bool, int)) or packed not in {0, 1}:
        raise RandsPilotError("cohort.required_metadata.packed must be 0 or 1.")
    target_labels = {
        label: _required_nonnegative_int(targets, label, "pilot.target_labels")
        for label in LABEL_IDS
    }
    if set(targets) != set(LABEL_IDS) or not all(target_labels.values()):
        raise RandsPilotError(
            "pilot.target_labels must define positive benign and ransomware targets only."
        )
    if _required_nonnegative_int(pilot, "target_samples", "pilot") != sum(target_labels.values()):
        raise RandsPilotError("pilot.target_samples must equal the sum of pilot.target_labels.")

    return RandsPilotConfig(
        name=_required_string(protocol, "name", "protocol"),
        snapshot=_required_string(
            _mapping(root.get("references"), "references"), "rands_snapshot", "references"
        ),
        extensions=extensions,
        arch=_required_string(required_metadata, "arch", "cohort.required_metadata"),
        packed=bool(packed),
        target_labels=target_labels,
        selection_seed=_required_string(selection, "seed", "pilot.selection"),
    )


def _rank(seed: str, value: str, kind: str) -> str:
    return hashlib.sha256(f"{seed}:{kind}:{value}".encode()).hexdigest()


def _cohort_reason(
    record: RandsRecord, present_shas: set[str], config: RandsPilotConfig
) -> str | None:
    if record.sha256 not in present_shas:
        return "unavailable"
    if record.extension not in config.extensions:
        return "unsupported_extension"
    if record.arch != config.arch:
        return "unsupported_architecture"
    if record.packed != config.packed:
        return "packed"
    if record.label == "ransomware" and not record.family:
        return "missing_family"
    return None


def _allocate_families(
    families: dict[str, list[RandsRecord]], target: int, seed: str
) -> dict[str, int]:
    """Allocate the ransomware target proportionally with exact integer remainders."""
    total = sum(len(records) for records in families.values())
    if target > total:
        raise RandsPilotError(
            f"Ransomware target is {target}, but only {total} eligible ransomware samples exist."
        )

    allocations = {family: len(records) * target // total for family, records in families.items()}
    remaining = target - sum(allocations.values())
    ordered = sorted(
        families,
        key=lambda family: (
            -(len(families[family]) * target % total),
            _rank(seed, family, "family"),
            family,
        ),
    )
    for family in ordered[:remaining]:
        allocations[family] += 1
    return allocations


def _select_records(
    records: list[tuple[RandsRecord, str | None]], config: RandsPilotConfig
) -> tuple[list[PilotRecord], dict[str, dict[str, int]]]:
    eligible: dict[str, list[RandsRecord]] = {label: [] for label in LABEL_IDS}
    exclusions: dict[str, Counter[str]] = {label: Counter() for label in LABEL_IDS}

    for record, reason in records:
        if reason is None:
            eligible[record.label].append(record)
        else:
            exclusions[record.label][reason] += 1

    for label, target in config.target_labels.items():
        if len(eligible[label]) < target:
            raise RandsPilotError(
                f"{label} target is {target}, but only {len(eligible[label])} eligible samples exist."
            )

    selected: list[PilotRecord] = []
    for record in sorted(
        eligible["benign"],
        key=lambda item: (_rank(config.selection_seed, item.sha256, "sample"), item.sha256),
    )[: config.target_labels["benign"]]:
        selected.append(
            PilotRecord(
                record=record,
                selection_rank=_rank(config.selection_seed, record.sha256, "sample"),
                family_eligible_count=None,
                family_target=None,
            )
        )

    families: dict[str, list[RandsRecord]] = defaultdict(list)
    for record in eligible["ransomware"]:
        assert record.family is not None
        families[record.family].append(record)
    allocations = _allocate_families(
        families, config.target_labels["ransomware"], config.selection_seed
    )
    for family in sorted(families):
        ranked = sorted(
            families[family],
            key=lambda item: (_rank(config.selection_seed, item.sha256, "sample"), item.sha256),
        )
        for record in ranked[: allocations[family]]:
            selected.append(
                PilotRecord(
                    record=record,
                    selection_rank=_rank(config.selection_seed, record.sha256, "sample"),
                    family_eligible_count=len(families[family]),
                    family_target=allocations[family],
                )
            )

    selection_summary = {
        label: {
            "metadata": sum(1 for record, _ in records if record.label == label),
            "eligible": len(eligible[label]),
            "target": config.target_labels[label],
            "excluded": dict(sorted(exclusions[label].items())),
        }
        for label in LABEL_IDS
    }
    selection_summary["ransomware"]["families"] = {
        family: {
            "eligible": len(families[family]),
            "target": allocations[family],
            "selected": allocations[family],
        }
        for family in sorted(families)
    }
    return selected, selection_summary


def _render_manifest(selected: list[PilotRecord], config: RandsPilotConfig) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=MANIFEST_FIELDS, lineterminator="\n")
    writer.writeheader()
    for pilot_record in sorted(
        selected,
        key=lambda item: (
            LABEL_IDS[item.record.label],
            item.record.family or "",
            item.selection_rank,
            item.record.sha256,
        ),
    ):
        record = pilot_record.record
        writer.writerow(
            {
                "source_sha256": record.sha256,
                "label": record.label,
                "label_id": LABEL_IDS[record.label],
                "family": record.family or "",
                "extension": record.extension,
                "arch": record.arch,
                "packed": int(record.packed),
                "year": record.year,
                "available": 1,
                "relative_path": record.relative_path.as_posix(),
                "selection_rank": pilot_record.selection_rank,
                "family_eligible_count": pilot_record.family_eligible_count or "",
                "family_target": pilot_record.family_target or "",
                "source_hash_verified": 1,
                "snapshot": config.snapshot,
                "selection_seed": config.selection_seed,
            }
        )
    return output.getvalue().encode("utf-8")


def build_rands_pilot(
    dataset_config: RandsDatasetConfig, pilot_config: RandsPilotConfig, root: Path
) -> RandsPilotBuild:
    """Select and verify a local pilot; no PE content is parsed or executed."""
    if dataset_config.snapshot != pilot_config.snapshot:
        raise RandsPilotError(
            "Dataset and pilot configs refer to different RanDS snapshots: "
            f"{dataset_config.snapshot} and {pilot_config.snapshot}."
        )

    inspection, metadata, present_shas = inspect_rands(dataset_config, root)
    if not inspection["contract"]["passed"]:
        raise RandsPilotError("RanDS release contract failed; resolve the audit findings first.")

    records: list[tuple[RandsRecord, str | None]] = []
    for record in metadata.records.values():
        reason = _cohort_reason(record, present_shas, pilot_config)
        records.append((record, reason))

    selected, selection = _select_records(records, pilot_config)
    if len({item.record.sha256 for item in selected}) != len(selected):
        raise RandsPilotError("Pilot selection contains duplicate source SHA-256 values.")

    verification = {"checked": 0, "mismatches": 0, "bytes_read": 0}
    for pilot_record in selected:
        path = root / dataset_config.samples_dir / pilot_record.record.relative_path
        digest, bytes_read = hash_file_sha256(path)
        verification["checked"] += 1
        verification["bytes_read"] += bytes_read
        if digest != pilot_record.record.sha256:
            verification["mismatches"] += 1

    manifest_bytes = None
    manifest_summary: dict[str, Any] = {"written": False, "rows": 0, "sha256": None}
    if verification["mismatches"] == 0:
        manifest_bytes = _render_manifest(selected, pilot_config)
        manifest_summary = {
            "written": True,
            "rows": len(selected),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        }

    summary = {
        "pilot": {
            "name": pilot_config.name,
            "snapshot": pilot_config.snapshot,
            "selection_method": "sha256_rank",
            "selection_seed": pilot_config.selection_seed,
            "passed": manifest_bytes is not None,
        },
        "cohort": selection,
        "verification": verification,
        "manifest": manifest_summary,
    }
    return RandsPilotBuild(
        manifest_bytes=manifest_bytes,
        selected=tuple(selected),
        summary=summary,
    )


def _validate_summary_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "reports":
        raise RandsPilotError("Summary paths inside the repository must be under reports/.")


def write_rands_pilot_outputs(
    build: RandsPilotBuild, manifest_path: Path, summary_path: Path
) -> None:
    """Write local evidence; never write a manifest that failed source verification."""
    _validate_manifest_path(manifest_path)
    _validate_summary_path(summary_path)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(build.summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if build.manifest_bytes is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(build.manifest_bytes)


def pilot_console_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Reduce the full local family report to a readable, hash-free terminal result."""
    ransomware = summary["cohort"]["ransomware"]
    families = ransomware["families"]
    return {
        "pilot": summary["pilot"],
        "cohort": {
            "benign": summary["cohort"]["benign"],
            "ransomware": {
                key: ransomware[key] for key in ("metadata", "eligible", "target", "excluded")
            }
            | {
                "families": {
                    "eligible": len(families),
                    "selected": sum(details["selected"] > 0 for details in families.values()),
                    "zero_selected": sum(
                        details["selected"] == 0 for details in families.values()
                    ),
                    "all_eligible_selected": sum(
                        details["selected"] == details["eligible"] and details["selected"] > 0
                        for details in families.values()
                    ),
                }
            },
        },
        "verification": summary["verification"],
        "manifest": summary["manifest"],
    }
