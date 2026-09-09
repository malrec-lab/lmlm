from pathlib import Path

from malweave.data.deduplication import (
    SampleMetadata,
    compute_digest,
    deduplicate_labeled_files,
)


def _sample(character: str) -> str:
    return character * 64


def test_compute_digest_matches_md5_reference() -> None:
    assert compute_digest(b"abc") == "900150983cd24fb0d6963f7d28e17f72"


def test_cross_binary_class_digest_is_removed_completely() -> None:
    benign = Path(f"{_sample('a')}.c")
    ransomware = Path(f"{_sample('b')}.c")
    metadata = {
        benign.stem: SampleMetadata("benign", None, 2020, "Benign.csv"),
        ransomware.stem: SampleMetadata("ransomware", "Loki", 2021, "Ransomware.csv"),
    }
    digests = {benign.stem: "same", ransomware.stem: "same"}

    retained, decisions, _ = deduplicate_labeled_files(
        [benign, ransomware], metadata, digests
    )

    assert retained == []
    assert {decision.action for decision in decisions} == {"drop_binary_conflict"}


def test_modal_family_is_selected_then_one_representative_is_kept() -> None:
    first_loki = Path(f"{_sample('a')}.c")
    second_loki = Path(f"{_sample('b')}.c")
    quasar = Path(f"{_sample('c')}.c")
    files = [first_loki, second_loki, quasar]
    metadata = {
        first_loki.stem: SampleMetadata("ransomware", "Loki", 2021, "Ransomware.csv"),
        second_loki.stem: SampleMetadata("ransomware", "Loki", 2022, "Ransomware.csv"),
        quasar.stem: SampleMetadata("ransomware", "Quasar", 2020, "Ransomware.csv"),
    }
    digests = {file.stem: "same" for file in files}

    retained, decisions, modal_labels = deduplicate_labeled_files(
        files, metadata, digests
    )

    assert retained == [first_loki]
    assert modal_labels == {"same": "Loki"}
    assert [decision.action for decision in decisions] == [
        "keep",
        "drop_duplicate",
        "drop_non_modal_label",
    ]
