"""Tests for the Python Ghidra preprocessing API."""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from malweave.data.ghidra import lift_sample, normalize_disassembly


class GhidraTests(unittest.TestCase):
    def test_normalize_disassembly_keeps_only_instruction_column(self) -> None:
        source = """undefined function(void)
.text\t00000100\t00400100\t55\tPUSH EBP
.text\t00000101\t00400101\t89 e5\tMOV EBP,ESP

"""
        self.assertEqual(normalize_disassembly(source), "PUSH EBP\nMOV EBP,ESP\n")

    @patch("malweave.data.ghidra.subprocess.run")
    def test_lift_sample_materializes_outputs_and_preserves_sample_id(self, run) -> None:
        def create_ghidra_outputs(command, **kwargs):
            del kwargs
            lift_dir = Path(command[2])
            (lift_dir / "sample.asm").write_text(
                ".text\t00000100\t00400100\t55\tPUSH EBP\n"
            )
            (lift_dir / "sample.c").write_text("void sample(void) {}\n")
            (lift_dir / "log.txt").write_text("analysis complete\n")
            return subprocess.CompletedProcess(command, 0, "", "")

        run.side_effect = create_ghidra_outputs
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "sample.exe"
            input_path.write_bytes(b"MZ")

            result = lift_sample(input_path, root / "output")

            self.assertEqual(result.dis_path.name, "sample.exe.asm")
            self.assertEqual(result.dec_path.name, "sample.exe.c")
            self.assertEqual(result.dis_path.read_text(), "PUSH EBP\n")
            self.assertEqual(result.dec_path.read_text(), "void sample(void) {}\n")
            self.assertEqual(result.log_path.read_text(), "analysis complete\n")
            self.assertFalse(result.cached)

    @patch("malweave.data.ghidra.subprocess.run")
    def test_lift_sample_reuses_existing_outputs(self, run) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "sample"
            input_path.write_bytes(b"MZ")
            dis_path = root / "output" / "dis" / "sample.asm"
            dec_path = root / "output" / "dec" / "sample.c"
            dis_path.parent.mkdir(parents=True)
            dec_path.parent.mkdir(parents=True)
            dis_path.write_text("RET\n")
            dec_path.write_text("void sample(void) {}\n")

            result = lift_sample(input_path, root / "output")

            run.assert_not_called()
            self.assertTrue(result.cached)


if __name__ == "__main__":
    unittest.main()
