"""Bounded EXE extraction for a verified local RanDS pilot manifest."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from hashlib import sha256
import io
import json
from pathlib import Path
import time
from typing import Any

from malweave.config import PROJECT_ROOT
from malweave.data.dataset_config import RandsDatasetConfig
from malweave.data.pe_sections import extract_executable_sections
from malweave.data.rands import SHA256_PATTERN, _validate_manifest_path

PILOT_MANIFEST_FIELDS = {
    "source_sha256",
    "label",
    "family",
    "relative_path",
    "source_hash_verified",
    "snapshot",
}
EXE_MANIFEST_FIELDS = (
    "source_sha256",
    "label",
    "family",
    "source_hash_status",
    "extraction_status",
    "extraction_warnings",
    "section_count",
    "executable_section_count",
    "extracted_size",
    "representation_sha256",
    "representation_relative_path",
    "representation_reused",
    "runtime_ms",
    "snapshot",
)


class RandsExeError(ValueError):
    """Raised when a pilot manifest or local EXE output location is unsafe or malformed."""


@dataclass(frozen=True)
class PilotSource:
    """The minimal provenance needed to process one verified pilot source."""

    source_sha256: str
    label: str
    family: str
    relative_path: Path
    snapshot: str


@dataclass(frozen=True)
class ExeManifestRow:
    """One source attempt, including failures that did not produce EXE bytes."""

    source_sha256: str
    label: str
    family: str
    source_hash_status: str
    extraction_status: str
    extraction_warnings: tuple[str, ...]
    section_count: int
    executable_section_count: int
    extracted_size: int
    representation_sha256: str | None
    representation_relative_path: str | None
    representation_reused: bool
    runtime_ms: float
    snapshot: str


@dataclass(frozen=True)
class _SourceAttempt:
    """One source result plus the bytes read while verifying its identity."""

    row: ExeManifestRow
    source_bytes_read: int


def _validate_representation_root(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if tuple(relative.parts[:2]) != ("data", "processed"):
        raise RandsExeError(
            "Representation output inside the repository must be under data/processed."
        )


def _validate_summary_path(path: Path) -> None:
    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "reports":
        raise RandsExeError("Summary paths inside the repository must be under reports/.")


def load_pilot_sources(path: Path) -> list[PilotSource]:
    """Load a locally generated pilot manifest without accepting provider paths."""
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as error:
        raise RandsExeError(f"Could not read pilot manifest: {path}") from error

    with handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or ())
        missing = sorted(PILOT_MANIFEST_FIELDS - fieldnames)
        if missing:
            raise RandsExeError(
                f"Pilot manifest is missing required fields: {', '.join(missing)}."
            )

        sources: list[PilotSource] = []
        seen: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            source_sha256 = (row["source_sha256"] or "").lower()
            if not SHA256_PATTERN.fullmatch(source_sha256):
                raise RandsExeError(f"Invalid source SHA-256 in pilot manifest row {row_number}.")
            if source_sha256 in seen:
                raise RandsExeError(
                    f"Duplicate source SHA-256 in pilot manifest row {row_number}."
                )
            if row["label"] not in {"benign", "ransomware"}:
                raise RandsExeError(f"Invalid label in pilot manifest row {row_number}.")
            if row["source_hash_verified"] != "1":
                raise RandsExeError(
                    f"Pilot manifest row {row_number} was not source-hash-verified."
                )

            relative_path = Path(row["relative_path"] or "")
            expected_path = Path(source_sha256[:2]) / source_sha256
            if relative_path != expected_path:
                raise RandsExeError(
                    f"Unexpected source path in pilot manifest row {row_number}; "
                    "only the canonical SHA-256 shard path is accepted."
                )
            seen.add(source_sha256)
            sources.append(
                PilotSource(
                    source_sha256=source_sha256,
                    label=row["label"],
                    family=row["family"] or "",
                    relative_path=relative_path,
                    snapshot=row["snapshot"],
                )
            )
    return sources


def _write_representation(path: Path, content: bytes, digest: str) -> bool:
    """Write a representation once; retain an existing identical result for safe resume."""
    if path.exists():
        existing = path.read_bytes()
        if sha256(existing).hexdigest() != digest:
            raise RandsExeError(
                f"Existing representation does not match the newly extracted bytes: {path}"
            )
        return True

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_bytes(content)
    temporary_path.replace(path)
    return False


def _failure_row(
    source: PilotSource,
    *,
    source_hash_status: str,
    extraction_status: str,
    runtime_ms: float,
) -> ExeManifestRow:
    return ExeManifestRow(
        source_sha256=source.source_sha256,
        label=source.label,
        family=source.family,
        source_hash_status=source_hash_status,
        extraction_status=extraction_status,
        extraction_warnings=(),
        section_count=0,
        executable_section_count=0,
        extracted_size=0,
        representation_sha256=None,
        representation_relative_path=None,
        representation_reused=False,
        runtime_ms=runtime_ms,
        snapshot=source.snapshot,
    )


def _extract_one_source(
    dataset_config: RandsDatasetConfig,
    root: Path,
    source: PilotSource,
    representation_root: Path,
) -> _SourceAttempt:
    """Re-verify, extract, and persist one source without hiding a failure."""
    started = time.perf_counter()
    source_path = root / dataset_config.samples_dir / source.relative_path
    try:
        content = source_path.read_bytes()
    except OSError:
        return _SourceAttempt(
            _failure_row(
                source,
                source_hash_status="read_error",
                extraction_status="read_error",
                runtime_ms=(time.perf_counter() - started) * 1000,
            ),
            source_bytes_read=0,
        )

    source_bytes_read = len(content)
    if sha256(content).hexdigest() != source.source_sha256:
        return _SourceAttempt(
            _failure_row(
                source,
                source_hash_status="mismatch",
                extraction_status="source_hash_mismatch",
                runtime_ms=(time.perf_counter() - started) * 1000,
            ),
            source_bytes_read=source_bytes_read,
        )

    extracted = extract_executable_sections(content)
    reused = False
    relative_representation_path: str | None = None
    if extracted.status == "success":
        assert extracted.extracted_bytes is not None
        assert extracted.representation_sha256 is not None
        representation_path = representation_root / f"{source.source_sha256}.bin"
        reused = _write_representation(
            representation_path, extracted.extracted_bytes, extracted.representation_sha256
        )
        relative_representation_path = representation_path.name

    return _SourceAttempt(
        ExeManifestRow(
            source_sha256=source.source_sha256,
            label=source.label,
            family=source.family,
            source_hash_status="verified",
            extraction_status=extracted.status,
            extraction_warnings=extracted.warnings,
            section_count=extracted.section_count,
            executable_section_count=extracted.executable_section_count,
            extracted_size=extracted.extracted_size,
            representation_sha256=extracted.representation_sha256,
            representation_relative_path=relative_representation_path,
            representation_reused=reused,
            runtime_ms=(time.perf_counter() - started) * 1000,
            snapshot=source.snapshot,
        ),
        source_bytes_read=source_bytes_read,
    )


def extract_rands_exe(
    dataset_config: RandsDatasetConfig,
    root: Path,
    sources: list[PilotSource],
    representation_root: Path,
) -> tuple[list[ExeManifestRow], dict[str, Any]]:
    """Re-verify and statically extract every requested pilot source exactly once."""
    _validate_representation_root(representation_root)
    rows: list[ExeManifestRow] = []
    source_bytes_read = 0
    for source in sources:
        attempt = _extract_one_source(dataset_config, root, source, representation_root)
        rows.append(attempt.row)
        source_bytes_read += attempt.source_bytes_read

    status_counts = Counter(row.extraction_status for row in rows)
    warning_counts = Counter(warning for row in rows for warning in row.extraction_warnings)
    successful = [row for row in rows if row.extraction_status == "success"]
    representations: dict[str, list[ExeManifestRow]] = defaultdict(list)
    for row in successful:
        assert row.representation_sha256 is not None
        representations[row.representation_sha256].append(row)
    duplicate_groups = [group for group in representations.values() if len(group) > 1]

    summary = {
        "sources": {
            "attempted": len(rows),
            "source_bytes_read": source_bytes_read,
            "source_hash_verified": sum(row.source_hash_status == "verified" for row in rows),
            "source_hash_mismatches": sum(row.source_hash_status == "mismatch" for row in rows),
            "read_errors": sum(row.source_hash_status == "read_error" for row in rows),
        },
        "extraction": {
            "statuses": dict(sorted(status_counts.items())),
            "warnings": dict(sorted(warning_counts.items())),
            "successful": len(successful),
            "failed": len(rows) - len(successful),
            "representation_bytes": sum(row.extracted_size for row in successful),
            "reused_representations": sum(row.representation_reused for row in successful),
            "runtime_ms_total": round(sum(row.runtime_ms for row in rows), 3),
            "runtime_ms_mean": round(sum(row.runtime_ms for row in rows) / len(rows), 3)
            if rows
            else 0.0,
            "runtime_ms_max": round(max((row.runtime_ms for row in rows), default=0.0), 3),
        },
        "labels": {
            label: dict(
                sorted(
                    Counter(row.extraction_status for row in rows if row.label == label).items()
                )
            )
            for label in ("benign", "ransomware")
        },
        "representation_duplicates": {
            "groups": len(duplicate_groups),
            "extra_sources": sum(len(group) - 1 for group in duplicate_groups),
            "cross_label_groups": sum(
                len({row.label for row in group}) > 1 for group in duplicate_groups
            ),
        },
    }
    return rows, summary


def _render_exe_manifest(rows: list[ExeManifestRow]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=EXE_MANIFEST_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "source_sha256": row.source_sha256,
                "label": row.label,
                "family": row.family,
                "source_hash_status": row.source_hash_status,
                "extraction_status": row.extraction_status,
                "extraction_warnings": ";".join(row.extraction_warnings),
                "section_count": row.section_count,
                "executable_section_count": row.executable_section_count,
                "extracted_size": row.extracted_size,
                "representation_sha256": row.representation_sha256 or "",
                "representation_relative_path": row.representation_relative_path or "",
                "representation_reused": int(row.representation_reused),
                "runtime_ms": f"{row.runtime_ms:.3f}",
                "snapshot": row.snapshot,
            }
        )
    return handle.getvalue().encode("utf-8")


def write_rands_exe_outputs(
    rows: list[ExeManifestRow],
    summary: dict[str, Any],
    manifest_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Write ignored EXE metadata and aggregate evidence after every source was attempted."""
    _validate_manifest_path(manifest_path)
    _validate_summary_path(summary_path)
    manifest = _render_exe_manifest(rows)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest)

    completed_summary = {
        **summary,
        "manifest": {"rows": len(rows), "sha256": sha256(manifest).hexdigest()},
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(completed_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return completed_summary


def exe_console_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Return only aggregate extraction evidence for terminal output."""
    return summary
