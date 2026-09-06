"""Synthetic regression tests for deterministic RanDS pilot selection."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from malweave.cli import main
from malweave.data.dataset_config import (
    RandsDatasetConfig,
    RandsExpectedCounts,
    RandsProtocol,
)
from malweave.data.rands import BENIGN_HEADER, RANSOMWARE_DOCUMENTED_HEADER
from malweave.data.rands_pilot import (
    RandsPilotConfig,
    build_rands_pilot,
    write_rands_pilot_outputs,
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write_csv(path: Path, header: tuple[str, ...], rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def _write_pilot_experiment(path: Path, *, snapshot: str = "test") -> None:
    path.write_text(
        f"""
protocol: {{name: test-pilot, phase: 2}}
references: {{rands_snapshot: {snapshot}}}
cohort:
  required_metadata: {{extensions: [EXE, DLL], arch: I386, packed: 0}}
pilot:
  target_samples: 7
  target_labels: {{benign: 3, ransomware: 4}}
  selection:
    method: sha256_rank
    seed: test-pilot-v1
    ransomware_family_allocation: {{method: proportional_largest_remainder}}
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _fixture(
    tmp_path: Path,
) -> tuple[Path, RandsDatasetConfig, RandsPilotConfig, list[list[str]], list[list[str]]]:
    root = tmp_path / "rands"
    (root / "dataset").mkdir(parents=True)
    benign_rows: list[list[str]] = []
    ransomware_rows: list[list[str]] = []
    counter = 0

    def add_record(
        *,
        label: str,
        family: str = "",
        extension: str = "EXE",
        arch: str = "I386",
        packed: str = "0",
        present: bool = True,
    ) -> None:
        nonlocal counter
        counter += 1
        content = f"MZ synthetic {label} {family} {extension} {arch} {packed} {counter}".encode()
        sha256 = _sha256(content)
        if present:
            shard = root / "dataset" / sha256[:2]
            shard.mkdir(parents=True, exist_ok=True)
            (shard / sha256).write_bytes(content)
        if label == "benign":
            benign_rows.append(
                [
                    sha256,
                    "1" * 40,
                    "2" * 32,
                    str(len(content)),
                    extension,
                    arch,
                    packed,
                    "6.0",
                    "2024",
                    "provider/path/ignored.exe",
                ]
            )
        else:
            # The released header is documented order, while this fixture uses its actual row order.
            ransomware_rows.append(
                [
                    sha256,
                    "3" * 40,
                    "4" * 32,
                    str(len(content)),
                    extension,
                    arch,
                    packed,
                    "7.0",
                    family,
                    "2025",
                    "provider/path/ignored.exe",
                ]
            )

    for _ in range(4):
        add_record(label="benign")
    add_record(label="benign", extension="SYS")
    add_record(label="benign", arch="Amd64")
    add_record(label="benign", packed="1")
    add_record(label="benign", present=False)

    for _ in range(4):
        add_record(label="ransomware", family="Alpha")
    for _ in range(2):
        add_record(label="ransomware", family="Beta", extension="DLL")
    add_record(label="ransomware", family="Gamma")
    add_record(label="ransomware", family="")
    add_record(label="ransomware", family="Alpha", packed="1")

    _write_csv(root / "Benign.csv", BENIGN_HEADER, benign_rows)
    _write_csv(root / "Ransomware.csv", RANSOMWARE_DOCUMENTED_HEADER, ransomware_rows)

    present_rows = [*benign_rows[:-1], *ransomware_rows]
    config = RandsDatasetConfig(
        name="rands",
        snapshot="test",
        root_env="TEST_RANDS_ROOT",
        benign_csv="Benign.csv",
        ransomware_csv="Ransomware.csv",
        samples_dir="dataset",
        expected=RandsExpectedCounts(
            shards=len({row[0][:2] for row in present_rows}),
            files=len(present_rows),
            labels={"benign": len(benign_rows) - 1, "ransomware": len(ransomware_rows)},
        ),
        protocols={"full": RandsProtocol()},
    )
    pilot = RandsPilotConfig(
        name="test-pilot",
        snapshot="test",
        extensions=("dll", "exe"),
        arch="I386",
        packed=False,
        target_labels={"benign": 3, "ransomware": 4},
        selection_seed="test-pilot-v1",
    )
    return root, config, pilot, benign_rows, ransomware_rows


def test_pilot_selection_is_deterministic_and_reports_exclusions(tmp_path: Path) -> None:
    root, config, pilot, benign_rows, ransomware_rows = _fixture(tmp_path)

    first = build_rands_pilot(config, pilot, root)
    _write_csv(root / "Benign.csv", BENIGN_HEADER, list(reversed(benign_rows)))
    _write_csv(
        root / "Ransomware.csv", RANSOMWARE_DOCUMENTED_HEADER, list(reversed(ransomware_rows))
    )
    second = build_rands_pilot(config, pilot, root)

    assert first.passed is True
    assert first.manifest_bytes == second.manifest_bytes
    assert len(first.selected) == 7
    assert first.summary["cohort"]["benign"] == {
        "metadata": 8,
        "eligible": 4,
        "target": 3,
        "excluded": {
            "packed": 1,
            "unavailable": 1,
            "unsupported_architecture": 1,
            "unsupported_extension": 1,
        },
    }
    assert first.summary["cohort"]["ransomware"]["families"] == {
        "Alpha": {"eligible": 4, "target": 2, "selected": 2},
        "Beta": {"eligible": 2, "target": 1, "selected": 1},
        "Gamma": {"eligible": 1, "target": 1, "selected": 1},
    }
    assert first.summary["verification"]["checked"] == 7
    assert first.summary["verification"]["mismatches"] == 0

    rows = list(csv.DictReader(first.manifest_bytes.decode("utf-8").splitlines()))
    assert all("provider/path" not in str(row.values()) for row in rows)
    assert {row["available"] for row in rows} == {"1"}
    assert {row["source_hash_verified"] for row in rows} == {"1"}


def test_hash_mismatch_writes_only_aggregate_failure_summary(tmp_path: Path) -> None:
    root, config, pilot, _, _ = _fixture(tmp_path)
    valid = build_rands_pilot(config, pilot, root)
    selected = valid.selected[0].record
    source_path = root / "dataset" / selected.relative_path
    source_path.write_bytes(b"X" * selected.size_bytes)

    failed = build_rands_pilot(config, pilot, root)
    manifest_path = tmp_path / "local" / "pilot.csv"
    summary_path = tmp_path / "local" / "pilot.json"
    write_rands_pilot_outputs(failed, manifest_path, summary_path)

    assert failed.passed is False
    assert failed.summary["verification"]["mismatches"] == 1
    assert manifest_path.exists() is False
    summary = summary_path.read_text(encoding="utf-8")
    assert json.loads(summary)["pilot"]["passed"] is False
    assert all(item.record.sha256 not in summary for item in failed.selected)


def test_cli_writes_manifest_and_prints_only_aggregate_summary(tmp_path: Path, capsys) -> None:
    root, config, pilot, _, _ = _fixture(tmp_path)
    dataset_path = tmp_path / "rands.yaml"
    dataset_path.write_text(
        f"""
dataset: {{name: rands, snapshot: test, root_env: TEST_RANDS_ROOT}}
layout: {{benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}}
expected:
  shards: {config.expected.shards}
  files: {config.expected.files}
  labels: {{benign: {config.expected.labels["benign"]}, ransomware: {config.expected.labels["ransomware"]}}}
protocols: {{full: {{}}}}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    experiment_path = tmp_path / "pilot.yaml"
    _write_pilot_experiment(experiment_path)
    manifest_path = tmp_path / "local" / "pilot.csv"
    summary_path = tmp_path / "local" / "pilot.json"

    exit_code = main(
        [
            "data",
            "pilot",
            "--dataset",
            "rands",
            "--config",
            str(dataset_path),
            "--experiment",
            str(experiment_path),
            "--root",
            str(root),
            "--manifest",
            str(manifest_path),
            "--summary",
            str(summary_path),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert json.loads(output)["pilot"]["passed"] is True
    assert manifest_path.exists() is True
    assert summary_path.exists() is True
    assert "Alpha" not in output
    assert all(
        item.record.sha256 not in output
        for item in build_rands_pilot(config, pilot, root).selected
    )
