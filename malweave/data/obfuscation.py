"""Detect obfuscated (packed/protected/encrypted) PE samples via Detect-It-Easy (diec).

Matches the paper's collection step: obfuscated samples are dropped before training,
since their bytes look like noise to a language model and disassembling/decompiling
them is unreliable. `diec` itself only runs in Docker (see docker/diec/), so every
call here goes through scripts/sh/diec.sh instead of calling `diec` directly.
"""

from __future__ import annotations

from argparse import ArgumentParser
from itertools import islice
import json
from pathlib import Path
from pprint import pformat
import subprocess
import tempfile

from tqdm import tqdm

OBFUSCATION_TYPES = {
    "packer", "protector", "protection", "crypter", "cryptor",
    "patcher", "scrambler", "sfx", "archive", "joiner",
}

DIEC_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sh" / "diec.sh"


def run_diec(file: Path | str) -> dict:
    result = subprocess.run(
        [str(DIEC_SCRIPT), "--json", str(file)],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def is_obfuscated(report: dict) -> bool:
    return any(_values_contain_obfuscation(d.get("values", [])) for d in report.get("detects", []))


def _values_contain_obfuscation(values: list[dict]) -> bool:
    # diec nests detections (e.g. a packer wrapping a compiler signature), so this recurses.
    for value in values:
        if "values" in value:
            if _values_contain_obfuscation(value["values"]):
                return True
        elif value.get("type", "").lower() in OBFUSCATION_TYPES:
            return True
    return False


def is_obfuscated_file(file: Path | str) -> bool:
    return is_obfuscated(run_diec(file))


def is_obfuscated_bytes(content: bytes, suffix: str = ".exe") -> bool:
    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
        tmp.write(content)
        tmp.flush()
        return is_obfuscated_file(tmp.name)


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
        result[name] = is_obfuscated_bytes(content, suffix=Path(name).suffix or ".exe")

    args.outfile.parent.mkdir(parents=True, exist_ok=True)
    with open(args.outfile, "w") as fp:
        json.dump(result, fp, indent=4)


if __name__ == "__main__":
    main()
