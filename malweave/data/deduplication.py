"""Digest-based, label-aware sample deduplication.

The digest and selection algorithms are adapted from RawByteClf's data
pipeline.  Local helpers connect those algorithms to RanDS CSV metadata and
the materialized token files used by MalWeave.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
import csv
from dataclasses import asdict, dataclass
from hashlib import md5
import json
from pathlib import Path
import re
import shutil

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class SampleMetadata:
    """Labels and acquisition year joined to an original PE SHA-256."""

    binary_label: str
    family: str | None
    year: int | None
    metadata_file: str


@dataclass(frozen=True)
class DeduplicationDecision:
    """The outcome for one sample under one representation digest policy."""

    sample: str
    digest: str
    binary_label: str
    task_label: str
    year: int | None
    group_size: int
    modal_label: str | None
    representative: str | None
    action: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


# Kept equivalent to RawByteClf/src/data/digests.py::compute_digest.
def compute_digest(b: bytes) -> str:
    """Compute the representation fingerprint used for exact deduplication."""

    m = md5()
    m.update(b)
    h = m.hexdigest()
    return h


def get_digests_from_files(files: Iterable[Path]) -> dict[str, str]:
    """Map each SHA-256 filename stem to the MD5 of its complete contents."""

    return {
        path.stem: compute_digest(path.read_bytes())
        for file in files
        if (path := Path(file)).is_file()
    }


def get_most_popular_label_by_digest(
    sha_label_map: Mapping[str, str],
    sha_digest_map: Mapping[str, str],
) -> dict[str, str]:
    """Choose the most frequent label observed for each content digest."""

    digest_label_map = defaultdict(Counter)
    for s, l in sha_label_map.items():
        d = sha_digest_map[s]
        digest_label_map[d].update([l])
    digest_label_map = {d: c.most_common(1)[0][0] for d, c in digest_label_map.items()}
    return digest_label_map


def select_one_file_per_digest_with_popular_label(
    files: Sequence[Path],
    sha_label_map: Mapping[str, str],
    sha_digest_map: Mapping[str, str],
) -> tuple[list[Path], dict[str, str], dict[str, str]]:
    """Keep the first sample carrying the most popular label for each digest."""

    digest_label_map = get_most_popular_label_by_digest(sha_label_map, sha_digest_map)

    # Input order decides ties and which sample represents a digest, so callers
    # should supply a stable order.
    rm = set()
    digests_added = set()
    for i, f in enumerate(files):
        s = Path(f).stem
        d = sha_digest_map[s]
        l = sha_label_map[s]
        if d in digests_added:
            rm.add(i)
            continue
        if l != digest_label_map[d]:
            rm.add(i)
            continue
        digests_added.add(d)

    retained_files = [f for i, f in enumerate(files) if i not in rm]
    retained_labels = {
        Path(file).stem: digest_label_map[sha_digest_map[Path(file).stem]]
        for file in retained_files
    }
    return retained_files, retained_labels, digest_label_map


def get_cross_class_digests(
    sha_binary_label_map: Mapping[str, str],
    sha_digest_map: Mapping[str, str],
) -> set[str]:
    """Find identical representations occurring in both binary classes."""

    present: dict[str, set[str]] = {"ben": set(), "mal": set()}
    noisy: set[str] = set()
    for s, label in sha_binary_label_map.items():
        if label == "benign":
            k = "ben"
            j = "mal"
        elif label == "ransomware":
            k = "mal"
            j = "ben"
        else:
            raise ValueError(f"Unsupported binary label for {s}: {label!r}")

        d = sha_digest_map[s]
        if d in present[j]:
            noisy.add(d)
        present[k].add(d)
    return noisy


def deduplicate_labeled_files(
    files: Sequence[Path],
    sample_metadata: Mapping[str, SampleMetadata],
    sha_digest_map: Mapping[str, str],
) -> tuple[list[Path], list[DeduplicationDecision], dict[str, str]]:
    """Apply cross-class removal, then modal-family deduplication.

    The returned files use the order supplied by the caller.  Ransomware
    samples use their family as the task label; benign samples use ``benign``.
    """

    ordered_files = [Path(file) for file in files]
    samples = [file.stem for file in ordered_files]
    missing_metadata = [sample for sample in samples if sample not in sample_metadata]
    missing_digests = [sample for sample in samples if sample not in sha_digest_map]
    if missing_metadata:
        raise KeyError(f"Samples without metadata: {missing_metadata[:5]}")
    if missing_digests:
        raise KeyError(f"Samples without digests: {missing_digests[:5]}")

    sha_binary_label_map = {
        sample: sample_metadata[sample].binary_label for sample in samples
    }
    noisy_digests = get_cross_class_digests(sha_binary_label_map, sha_digest_map)
    eligible_files = [
        file for file in ordered_files if sha_digest_map[file.stem] not in noisy_digests
    ]
    sha_task_label_map = {
        sample: sample_metadata[sample].family or sample_metadata[sample].binary_label
        for sample in samples
        if sha_digest_map[sample] not in noisy_digests
    }

    retained_files, _, digest_label_map = select_one_file_per_digest_with_popular_label(
        eligible_files,
        sha_task_label_map,
        sha_digest_map,
    )
    retained_samples = {file.stem for file in retained_files}
    representative_by_digest = {
        sha_digest_map[file.stem]: file.stem for file in retained_files
    }
    group_sizes = Counter(sha_digest_map[sample] for sample in samples)

    decisions = []
    for file in ordered_files:
        sample = file.stem
        digest = sha_digest_map[sample]
        metadata = sample_metadata[sample]
        task_label = metadata.family or metadata.binary_label
        modal_label = digest_label_map.get(digest)
        representative = representative_by_digest.get(digest)
        if digest in noisy_digests:
            action = "drop_binary_conflict"
        elif sample in retained_samples:
            action = "keep"
        elif task_label != modal_label:
            action = "drop_non_modal_label"
        else:
            action = "drop_duplicate"
        decisions.append(
            DeduplicationDecision(
                sample=sample,
                digest=digest,
                binary_label=metadata.binary_label,
                task_label=task_label,
                year=metadata.year,
                group_size=group_sizes[digest],
                modal_label=modal_label,
                representative=representative,
                action=action,
            )
        )
    return retained_files, decisions, digest_label_map


def _is_float(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _ransomware_family(row: Mapping[str, str]) -> str | None:
    """Read family while tolerating the observed RanDS three-column shift."""

    declared_family = (row.get("Family") or "").strip()
    declared_packed = (row.get("Packed") or "").strip()
    declared_entropy = (row.get("Entropy") or "").strip()
    shifted = (
        declared_family in {"0", "1"}
        and _is_float(declared_packed)
        and declared_entropy
        and not _is_float(declared_entropy)
    )
    family = declared_entropy if shifted else declared_family
    return family or None


def load_rands_metadata(
    benign_csv: Path,
    ransomware_csv: Path,
) -> tuple[dict[str, SampleMetadata], dict[str, int]]:
    """Load RanDS binary labels, ransomware family labels, and years."""

    metadata: dict[str, SampleMetadata] = {}
    counts: dict[str, int] = {}
    for binary_label, path in (
        ("benign", Path(benign_csv)),
        ("ransomware", Path(ransomware_csv)),
    ):
        count = 0
        with path.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or "SHA256" not in reader.fieldnames:
                raise ValueError(f"No SHA256 column in {path}: {reader.fieldnames}")
            for row_number, row in enumerate(reader, start=2):
                sample = row["SHA256"].strip().lower()
                if not SHA256_PATTERN.fullmatch(sample):
                    raise ValueError(f"Invalid SHA-256 at {path.name}:{row_number}: {sample!r}")
                if sample in metadata:
                    raise ValueError(f"Repeated SHA-256 across RanDS metadata: {sample}")
                year_text = (row.get("Year") or "").strip()
                metadata[sample] = SampleMetadata(
                    binary_label=binary_label,
                    family=_ransomware_family(row) if binary_label == "ransomware" else None,
                    year=int(year_text) if year_text.isdigit() else None,
                    metadata_file=path.name,
                )
                count += 1
        counts[binary_label] = count
    return metadata, counts


def write_jsonl(path: Path, records: Iterable[Mapping[str, object]]) -> None:
    """Write one audit record per line."""

    with Path(path).open("w") as stream:
        stream.writelines(
            json.dumps(dict(record), sort_keys=True) + "\n" for record in records
        )


def materialize_token_files(
    retained_samples: Sequence[str],
    decisions: Sequence[DeduplicationDecision],
    sha_digest_map: Mapping[str, str],
    token_directories: Mapping[str, Path],
    output_root: Path,
    vocab_size: int,
) -> dict[str, dict[str, int | str]]:
    """Copy the globally retained samples for every representation."""

    retained_samples = list(retained_samples)
    selected_names = {f"{sample}.json" for sample in retained_samples}
    decision_records = [decision.to_dict() for decision in decisions]
    decision_by_sample = {decision.sample: decision for decision in decisions}
    summaries: dict[str, dict[str, int | str]] = {}

    for representation, token_directory in token_directories.items():
        output_directory = Path(output_root) / representation / "bpe" / str(vocab_size)
        output_directory.mkdir(parents=True, exist_ok=True)
        stale_paths = [
            path
            for path in output_directory.glob("*.json")
            if SHA256_PATTERN.fullmatch(path.stem) and path.name not in selected_names
        ]
        for path in stale_paths:
            path.unlink()

        selected_records = []
        for sample in retained_samples:
            source_path = Path(token_directory) / f"{sample}.json"
            if not source_path.is_file():
                raise FileNotFoundError(f"Missing {representation.upper()} token IDs: {source_path}")
            output_path = output_directory / source_path.name
            shutil.copyfile(source_path, output_path)
            token_ids = json.loads(output_path.read_text())
            decision = decision_by_sample[sample]
            selected_records.append(
                {
                    "sample": sample,
                    "binary_label": decision.binary_label,
                    "task_label": decision.task_label,
                    "year": decision.year,
                    "dec_digest": sha_digest_map[sample],
                    "tokens": len(token_ids),
                    "output": str(output_path),
                }
            )

        write_jsonl(output_directory / "manifest.jsonl", decision_records)
        write_jsonl(output_directory / "selected.jsonl", selected_records)
        (output_directory / "digests.json").write_text(
            json.dumps(dict(sha_digest_map), sort_keys=True, indent=2)
        )
        action_counts = Counter(decision.action for decision in decisions)
        summary: dict[str, int | str] = {
            "representation": representation,
            "deduplication_basis": "dec",
            "vocab_size": vocab_size,
            "input_samples": len(decisions),
            "kept_samples": action_counts["keep"],
            "dropped_duplicates": action_counts["drop_duplicate"],
            "dropped_non_modal_labels": action_counts["drop_non_modal_label"],
            "dropped_binary_conflicts": action_counts["drop_binary_conflict"],
            "stale_outputs_removed": len(stale_paths),
        }
        (output_directory / "summary.json").write_text(
            json.dumps(summary, sort_keys=True, indent=2)
        )
        summaries[representation] = summary
    return summaries


__all__ = [
    "DeduplicationDecision",
    "SampleMetadata",
    "compute_digest",
    "deduplicate_labeled_files",
    "get_cross_class_digests",
    "get_digests_from_files",
    "get_most_popular_label_by_digest",
    "load_rands_metadata",
    "materialize_token_files",
    "select_one_file_per_digest_with_popular_label",
]
