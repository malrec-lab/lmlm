"""Regression checks for representation-specific tokenization."""

from pathlib import Path
import tempfile
import unittest

from malweave.tokenization import (
    SPECIALS,
    LiftLevel,
    TokenizationAlgorithm,
    TokenizationTrainingIterator,
    TrainTokenizer,
    bytes_to_str_utf8,
)


class TokenizationTests(unittest.TestCase):
    def test_raw_byte_mapping_is_bijective_and_uses_private_unicode_offset(self) -> None:
        source = bytes(range(256))
        mapped = bytes_to_str_utf8(source)

        self.assertEqual(len(mapped), 256)
        self.assertEqual(len(set(mapped)), 256)
        self.assertEqual([ord(character) - 10752 for character in mapped], list(source))

    def test_iterator_uses_16_byte_raw_words_and_newline_code_words(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sample.bin"
            path.write_bytes(bytes(range(17)))
            raw_iterator = TokenizationTrainingIterator(
                [path], LiftLevel.RAW, batch_size=8, block_size=1024, show_progress=False
            ).build()
            self.assertEqual(
                raw_iterator.decompose_document(path.read_bytes()),
                [bytes(range(16)), bytes([16])],
            )

            self.assertEqual(
                raw_iterator.decompose_document(b"one\ntwo"),
                [b"one\ntwo"],
            )
            dis_iterator = TokenizationTrainingIterator(
                [path], LiftLevel.DIS, batch_size=8, block_size=1024, show_progress=False
            )
            self.assertEqual(dis_iterator.decompose_document(b"one\ntwo"), [b"one", b"two"])

    def test_bpe_trainer_preserves_special_token_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sample.asm"
            path.write_bytes(b"MOV EAX,EBX\nRET\nMOV EAX,ECX")
            iterator = TokenizationTrainingIterator(
                [path], LiftLevel.DIS, batch_size=2, block_size=1024, show_progress=False
            ).build()
            tokenizer = TrainTokenizer(
                iterator,
                LiftLevel.DIS,
                TokenizationAlgorithm.BPE,
                vocab_size=32,
                max_token_length=16,
                show_progress=False,
            )()

            for expected_id, token in enumerate(SPECIALS.values()):
                self.assertEqual(tokenizer.token_to_id(token), expected_id)
            self.assertTrue(tokenizer.encode("MOV EAX,EBX").ids)


if __name__ == "__main__":
    unittest.main()
