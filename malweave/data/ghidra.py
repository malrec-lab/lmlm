"""Generate DIS and DEC representations with Ghidra running in Docker.

This module is the Python API for the Ghidra preprocessing stage. The shell
script remains a small Docker backend, matching the design used by
``malweave.data.obfuscation`` for Detect-It-Easy.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import tempfile

GHIDRA_LIFT_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sh" / "ghidra_lift.sh"


@dataclass(frozen=True)
class GhidraLiftResult:
    """Paths materialized by one Ghidra lifting operation."""

    dis_path: Path
    dec_path: Path
    log_path: Path | None
    cached: bool


def normalize_disassembly(text: str) -> str:
    """Keep only the instruction column from Ghidra's structured output.

    Instruction rows contain five tab-separated columns: section, physical
    address, virtual address, instruction bytes, and instruction text.
    Function signatures and blank lines do not have this shape and are dropped.
    """

    instructions = []
    for line in text.splitlines():
        columns = line.split("\t", maxsplit=4)
        if len(columns) == 5 and columns[-1].strip():
            instructions.append(columns[-1].strip())
    return "\n".join(instructions) + ("\n" if instructions else "")


def lift_sample(
    input_file: Path | str,
    output_dir: Path | str,
    *,
    overwrite: bool = False,
) -> GhidraLiftResult:
    """Lift one PE file and materialize normalized DIS, DEC, and Ghidra log.

    ``output_dir`` is the reproduction root. Results are written to its
    ``dis/``, ``dec/``, and ``logs/`` children using the complete input
    filename as the sample ID, so IDs stay aligned with EXE artifacts even
    when the original member name has an extension.
    """

    input_path = Path(input_file).resolve()
    output_root = Path(output_dir).resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"Ghidra input does not exist: {input_path}")
    if not GHIDRA_LIFT_SCRIPT.is_file():
        raise FileNotFoundError(f"Ghidra wrapper does not exist: {GHIDRA_LIFT_SCRIPT}")

    sample_id = input_path.name
    dis_path = output_root / "dis" / f"{sample_id}.asm"
    dec_path = output_root / "dec" / f"{sample_id}.c"
    log_path = output_root / "logs" / f"{sample_id}.log"

    if not overwrite and dis_path.is_file() and dec_path.is_file():
        return GhidraLiftResult(
            dis_path=dis_path,
            dec_path=dec_path,
            log_path=log_path if log_path.is_file() else None,
            cached=True,
        )

    with tempfile.TemporaryDirectory(prefix="malweave-ghidra-") as temporary_directory:
        lift_dir = Path(temporary_directory)
        try:
            subprocess.run(
                [str(GHIDRA_LIFT_SCRIPT), str(input_path), str(lift_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            details = (error.stderr or error.stdout or "no process output").strip()
            raise RuntimeError(f"Ghidra failed for {sample_id}: {details[-2000:]}") from error

        # Lifter.java removes the final input suffix from currentProgram.getName().
        generated_id = input_path.stem if input_path.suffix else input_path.name
        generated_dis = lift_dir / f"{generated_id}.asm"
        generated_dec = lift_dir / f"{generated_id}.c"
        if not generated_dis.is_file() or not generated_dec.is_file():
            generated = ", ".join(sorted(path.name for path in lift_dir.iterdir()))
            raise RuntimeError(
                f"Ghidra did not produce DIS and DEC for {sample_id}; generated: {generated}"
            )

        dis_path.parent.mkdir(parents=True, exist_ok=True)
        dec_path.parent.mkdir(parents=True, exist_ok=True)
        dis_path.write_text(
            normalize_disassembly(generated_dis.read_text(errors="replace")),
            encoding="utf-8",
        )
        shutil.copyfile(generated_dec, dec_path)

        generated_log = lift_dir / "log.txt"
        materialized_log = None
        if generated_log.is_file():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(generated_log, log_path)
            materialized_log = log_path

    return GhidraLiftResult(
        dis_path=dis_path,
        dec_path=dec_path,
        log_path=materialized_log,
        cached=False,
    )
