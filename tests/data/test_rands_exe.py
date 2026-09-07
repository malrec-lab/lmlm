"""Synthetic tests for bounded RanDS pilot EXE extraction."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import struct

from malweave.cli import main
from malweave.data.dataset_config import (
    RandsDatasetConfig,
    RandsExpectedCounts,
    RandsProtocol,
)
from malweave.data.pe_sections import IMAGE_SCN_CNT_CODE
from malweave.data.rands_exe import (
    extract_rands_exe,
    load_pilot_sources,
    write_rands_exe_outputs,
)


def _synthetic_pe(*, code: bool, section_byte: bytes = b"X") -> bytes:
    content = bytearray(0x600)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", content, 0x84, 0x14C)
    struct.pack_into("<H", content, 0x86, 1)
    struct.pack_into("<H", content, 0x94, 0xE0)
    struct.pack_into("<H", content, 0x98, 0x10B)
    section_header = 0x178
    content[section_header : section_header + 8] = b".code\0\0\0"
    struct.pack_into("<I", content, section_header + 16, 0x20)
    struct.pack_into("<I", content, section_header + 20, 0x400)
    struct.pack_into("<I", content, section_header + 36, IMAGE_SCN_CNT_CODE if code else 0)
    content[0x400:0x420] = section_byte * 0x20
    return bytes(content)


def _write_pilot_manifest(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = (
        "source_sha256",
        "label",
        "family",
        "relative_path",
        "source_hash_verified",
        "snapshot",
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _fixture(tmp_path: Path) -> tuple[Path, RandsDatasetConfig, Path, dict[str, str]]:
    root = tmp_path / "rands"
    (root / "dataset").mkdir(parents=True)
    manifest_path = tmp_path / "pilot.csv"
    sources: dict[str, str] = {}

    def add(name: str, content: bytes, *, stored_content: bytes | None = None) -> str:
        source_sha256 = hashlib.sha256(content).hexdigest()
        source_path = root / "dataset" / source_sha256[:2]
        source_path.mkdir(parents=True, exist_ok=True)
        (source_path / source_sha256).write_bytes(
            stored_content if stored_content is not None else content
        )
        sources[name] = source_sha256
        return source_sha256

    valid = add("valid", _synthetic_pe(code=True))
    no_code = add("no_code", _synthetic_pe(code=False))
    mismatch = add(
        "mismatch", _synthetic_pe(code=True, section_byte=b"Y"), stored_content=b"changed bytes"
    )
    missing = hashlib.sha256(b"missing fixture").hexdigest()
    sources["missing"] = missing
    _write_pilot_manifest(
        manifest_path,
        [
            {
                "source_sha256": valid,
                "label": "benign",
                "family": "",
                "relative_path": f"{valid[:2]}/{valid}",
                "source_hash_verified": "1",
                "snapshot": "test",
            },
            {
                "source_sha256": no_code,
                "label": "ransomware",
                "family": "Synthetic",
                "relative_path": f"{no_code[:2]}/{no_code}",
                "source_hash_verified": "1",
                "snapshot": "test",
            },
            {
                "source_sha256": mismatch,
                "label": "ransomware",
                "family": "Synthetic",
                "relative_path": f"{mismatch[:2]}/{mismatch}",
                "source_hash_verified": "1",
                "snapshot": "test",
            },
            {
                "source_sha256": missing,
                "label": "benign",
                "family": "",
                "relative_path": f"{missing[:2]}/{missing}",
                "source_hash_verified": "1",
                "snapshot": "test",
            },
        ],
    )
    config = RandsDatasetConfig(
        name="rands",
        snapshot="test",
        root_env="TEST_RANDS_ROOT",
        benign_csv="Benign.csv",
        ransomware_csv="Ransomware.csv",
        samples_dir="dataset",
        expected=RandsExpectedCounts(shards=0, files=0, labels={"benign": 0, "ransomware": 0}),
        protocols={"full": RandsProtocol()},
    )
    return root, config, manifest_path, sources


def test_extract_rands_exe_reports_every_source_and_reuses_valid_output(tmp_path: Path) -> None:
    root, config, pilot_manifest, sources = _fixture(tmp_path)
    representation_root = tmp_path / "representations"

    rows, summary = extract_rands_exe(
        config, root, load_pilot_sources(pilot_manifest), representation_root
    )

    assert [row.extraction_status for row in rows] == [
        "success",
        "no_executable_section",
        "source_hash_mismatch",
        "read_error",
    ]
    assert summary["sources"] == {
        "attempted": 4,
        "source_bytes_read": len(_synthetic_pe(code=True)) + len(_synthetic_pe(code=False)) + 13,
        "source_hash_verified": 2,
        "source_hash_mismatches": 1,
        "read_errors": 1,
    }
    assert summary["extraction"]["successful"] == 1
    assert (representation_root / f"{sources['valid']}.bin").read_bytes() == b"X" * 0x20

    repeated_rows, repeated_summary = extract_rands_exe(
        config, root, load_pilot_sources(pilot_manifest), representation_root
    )
    assert repeated_rows[0].representation_reused is True
    assert repeated_rows[0].representation_sha256 == rows[0].representation_sha256
    assert repeated_summary["extraction"]["reused_representations"] == 1


def test_exe_outputs_and_cli_keep_sample_hashes_out_of_summary(tmp_path: Path, capsys) -> None:
    root, config, pilot_manifest, sources = _fixture(tmp_path)
    representation_root = tmp_path / "representations"
    rows, summary = extract_rands_exe(
        config, root, load_pilot_sources(pilot_manifest), representation_root
    )
    output_manifest = tmp_path / "exe-manifest.csv"
    summary_path = tmp_path / "exe-summary.json"
    completed_summary = write_rands_exe_outputs(rows, summary, output_manifest, summary_path)

    assert completed_summary["manifest"]["rows"] == 4
    assert output_manifest.exists() is True
    summary_text = summary_path.read_text(encoding="utf-8")
    assert json.loads(summary_text)["extraction"]["successful"] == 1
    assert all(source_sha256 not in summary_text for source_sha256 in sources.values())

    config_path = tmp_path / "rands.yaml"
    config_path.write_text(
        """
dataset: {name: rands, snapshot: test, root_env: TEST_RANDS_ROOT}
layout: {benign_csv: Benign.csv, ransomware_csv: Ransomware.csv, samples_dir: dataset}
expected: {shards: 0, files: 0, labels: {benign: 0, ransomware: 0}}
protocols: {full: {}}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    exit_code = main(
        [
            "data",
            "extract-exe",
            "--dataset",
            "rands",
            "--config",
            str(config_path),
            "--root",
            str(root),
            "--pilot-manifest",
            str(pilot_manifest),
            "--representation-dir",
            str(tmp_path / "cli-representations"),
            "--manifest",
            str(tmp_path / "cli-exe-manifest.csv"),
            "--summary",
            str(tmp_path / "cli-exe-summary.json"),
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert json.loads(output)["sources"]["attempted"] == 4
    assert all(source_sha256 not in output for source_sha256 in sources.values())
