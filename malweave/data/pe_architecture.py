"""Filter PE samples by CPU architecture using the `file` command-line utility.

Matches the paper's collection step: only 32-bit x86 (PE32) binaries are kept for training,
so pretraining sees one consistent instruction set instead of a mix of x86/x64/ARM.
"""

from __future__ import annotations

from argparse import ArgumentParser
from itertools import islice
import json
from pathlib import Path
from pprint import pformat
import subprocess
import tempfile
from typing import Literal

from tqdm import tqdm

Architecture = Literal["x86", "x64", "unknown"]


def get_pe_architecture(file: Path | str) -> Architecture:
    result = subprocess.run(["file", str(file)], check=True, capture_output=True, text=True)
    description = result.stdout

    # "PE32" is a substring of "PE32+", so the 64-bit marker must be checked first.
    if "PE32+" in description:
        return "x64"
    if "PE32" in description:
        return "x86"
    return "unknown"


def is_32bit_x86(file: Path | str) -> bool:
    return get_pe_architecture(file) == "x86"


def get_pe_architecture_from_bytes(content: bytes, suffix: str = ".exe") -> Architecture:
    # `file` reads from disk, so bytes held in memory need a temp file first.
    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
        tmp.write(content)
        tmp.flush()
        return get_pe_architecture(tmp.name)


def main():
    from malweave.data.io import get_data_from_archives  # deferred: avoid import cost when unused

    parser = ArgumentParser()
    parser.add_argument("--outfile", type=Path, required=True)
    parser.add_argument("--inarchives", type=Path, required=True)
    parser.add_argument("--subset", type=int, default=None)
    args = parser.parse_args()

    print(f"args={pformat(args.__dict__)}")

    archives = sorted(args.inarchives.rglob("*.zip"))
    names = islice((n for n, _ in get_data_from_archives(archives, names=True, contents=False)), args.subset)
    contents = islice((c for _, c in get_data_from_archives(archives, names=False, contents=True)), args.subset)

    result = {}
    for name, content in tqdm(zip(names, contents)):
        result[name] = get_pe_architecture_from_bytes(content, suffix=Path(name).suffix or ".exe")

    args.outfile.parent.mkdir(parents=True, exist_ok=True)
    with open(args.outfile, "w") as fp:
        json.dump(result, fp, indent=4)


if __name__ == "__main__":
    main()
