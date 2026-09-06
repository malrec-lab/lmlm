"""Train representation-specific tokenizers from local preprocessing outputs."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from tokenizers import Tokenizer, models, trainers
from tokenizers.normalizers import Normalizer
from tokenizers.pre_tokenizers import PreTokenizer
from tqdm import tqdm

from .decompiled import get_dec_normalizer, get_dec_pretokenizer
from .disassembled import get_dis_normalizer, get_dis_pretokenizer
from .enums import LiftLevel, TokenizationAlgorithm
from .raw import get_raw_normalizer, get_raw_pretokenizer
from .special_tokens import SPECIALS

RAW_WORD_SIZE = 16
BYTE_TO_UTF8 = tuple(chr(value + 10752) for value in range(256))


def bytes_to_str_utf8(data: bytes) -> str:
    """Map every byte bijectively to a dedicated private Unicode symbol."""

    return "".join(BYTE_TO_UTF8[value] for value in data)


class TokenizationTrainingIterator(Iterator[list[str]]):
    """Decompose local artifacts into batches of tokenizer-training words."""

    def __init__(
        self,
        files: Iterable[Path],
        lift_level: LiftLevel,
        batch_size: int,
        block_size: int,
        num_files: int | None = None,
        show_progress: bool = True,
    ) -> None:
        self.files = [Path(path) for path in files]
        if num_files is not None:
            self.files = self.files[:num_files]
        self.lift_level = LiftLevel(lift_level)
        self.batch_size = batch_size
        self.block_size = block_size
        self.show_progress = show_progress
        self.stream: list[tuple[bytes, ...]] = []
        self.decomposition_records: list[dict[str, object]] = []
        self.idx: int | None = None
        self.num_characters = 0

    def build(self) -> TokenizationTrainingIterator:
        """Read files, decompose documents, and prepare training batches."""

        batch: list[bytes] = []
        documents = tqdm(
            self.files,
            total=len(self.files),
            desc="Decomposing documents",
            disable=not self.show_progress,
        )
        for path in documents:
            document = path.read_bytes()
            words = self.decompose_document(document)
            self.decomposition_records.append(
                {"file": path.name, "bytes": len(document), "words": len(words)}
            )
            for word in words:
                self.num_characters += len(word)
                batch.append(word)
                if len(batch) == self.batch_size:
                    self.stream.append(tuple(batch))
                    batch.clear()
        if batch:
            self.stream.append(tuple(batch))
        self.idx = 0
        return self

    # Support both iterator.build() and iterator() for concise training calls.
    __call__ = build

    def __iter__(self) -> TokenizationTrainingIterator:
        if self.idx is None:
            raise RuntimeError("Call build() before iterating")
        return self

    def __len__(self) -> int:
        if self.idx is None:
            raise RuntimeError("Call build() before requesting the length")
        return len(self.stream)

    def __next__(self) -> list[str]:
        if self.idx is None:
            raise RuntimeError("Call build() before iterating")
        if self.idx == len(self.stream):
            raise StopIteration
        batch = [self.bytes_to_str(word) for word in self.stream[self.idx]]
        self.idx += 1
        return batch

    @property
    def bytes_to_str(self) -> Callable[[bytes], str]:
        if self.lift_level in (LiftLevel.RAW, LiftLevel.NOP):
            return bytes_to_str_utf8
        if self.lift_level in (LiftLevel.DIS, LiftLevel.DEC):
            return bytes.decode
        raise ValueError(f"Unsupported lift level: {self.lift_level}")

    def decompose_document(self, document: bytes) -> list[bytes]:
        if self.lift_level in (LiftLevel.RAW, LiftLevel.NOP):
            return [
                document[index : index + RAW_WORD_SIZE]
                for index in range(0, len(document), RAW_WORD_SIZE)
            ]
        if self.lift_level in (LiftLevel.DIS, LiftLevel.DEC):
            return document.split(b"\n")
        raise ValueError(f"Unsupported lift level: {self.lift_level}")


class TrainTokenizer:
    """Configure and train a tokenizer for one input representation."""

    def __init__(
        self,
        iterator: TokenizationTrainingIterator,
        lift_level: LiftLevel,
        algorithm: TokenizationAlgorithm,
        vocab_size: int,
        max_token_length: int | None = None,
        show_progress: bool = True,
    ) -> None:
        self.iterator = iterator
        self.lift_level = LiftLevel(lift_level)
        self.algorithm = TokenizationAlgorithm(algorithm)
        self.vocab_size = vocab_size
        self.max_token_length = max_token_length
        self.show_progress = show_progress
        if (
            self.lift_level in (LiftLevel.RAW, LiftLevel.NOP)
            and self.algorithm == TokenizationAlgorithm.WORDLEVEL
        ):
            raise ValueError("Raw-byte WordLevel tokenization does not need training")

    def __call__(self) -> Tokenizer:
        tokenizer = Tokenizer(self.get_model())
        if (normalizer := self.get_normalizer()) is not None:
            tokenizer.normalizer = normalizer
        if (pretokenizer := self.get_pretokenizer()) is not None:
            tokenizer.pre_tokenizer = pretokenizer
        tokenizer.train_from_iterator(
            self.iterator,
            self.get_trainer(),
            length=len(self.iterator) * self.iterator.batch_size,
        )
        return tokenizer

    def get_normalizer(self) -> Normalizer | None:
        if self.lift_level in (LiftLevel.RAW, LiftLevel.NOP):
            return get_raw_normalizer(self.algorithm)
        if self.lift_level == LiftLevel.DIS:
            return get_dis_normalizer(self.algorithm)
        if self.lift_level == LiftLevel.DEC:
            return get_dec_normalizer(self.algorithm)
        raise ValueError(f"Unsupported lift level: {self.lift_level}")

    def get_pretokenizer(self) -> PreTokenizer | None:
        if self.lift_level in (LiftLevel.RAW, LiftLevel.NOP):
            return get_raw_pretokenizer(self.algorithm)
        if self.lift_level == LiftLevel.DIS:
            return get_dis_pretokenizer(self.algorithm)
        if self.lift_level == LiftLevel.DEC:
            return get_dec_pretokenizer(self.algorithm)
        raise ValueError(f"Unsupported lift level: {self.lift_level}")

    def get_model(self) -> models.Model:
        if self.algorithm == TokenizationAlgorithm.BPE:
            return models.BPE()
        if self.algorithm == TokenizationAlgorithm.UNIGRAM:
            return models.Unigram()
        if self.algorithm == TokenizationAlgorithm.WORDPIECE:
            return models.WordPiece()
        if self.algorithm == TokenizationAlgorithm.WORDLEVEL:
            return models.WordLevel()
        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def get_trainer(self) -> trainers.Trainer:
        special_tokens = list(SPECIALS.values())
        vocab_size = self.vocab_size + len(special_tokens)
        if self.algorithm == TokenizationAlgorithm.BPE:
            return trainers.BpeTrainer(
                vocab_size=vocab_size,
                special_tokens=special_tokens,
                max_token_length=self.max_token_length,
                show_progress=self.show_progress,
            )
        if self.algorithm == TokenizationAlgorithm.UNIGRAM:
            return trainers.UnigramTrainer(
                vocab_size=vocab_size,
                special_tokens=special_tokens,
                unk_token=SPECIALS["unk_token"],
                max_piece_length=self.max_token_length,
                show_progress=self.show_progress,
            )
        if self.algorithm == TokenizationAlgorithm.WORDPIECE:
            return trainers.WordPieceTrainer(
                vocab_size=vocab_size,
                special_tokens=special_tokens,
                show_progress=self.show_progress,
            )
        if self.algorithm == TokenizationAlgorithm.WORDLEVEL:
            return trainers.WordLevelTrainer(
                vocab_size=vocab_size,
                special_tokens=special_tokens,
                show_progress=self.show_progress,
            )
        raise ValueError(f"Unsupported algorithm: {self.algorithm}")
