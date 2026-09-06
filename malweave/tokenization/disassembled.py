"""Disassembled-instruction tokenizer configuration."""


from tokenizers import Regex, pre_tokenizers
from tokenizers.normalizers import Normalizer
from tokenizers.pre_tokenizers import PreTokenizer

from .enums import TokenizationAlgorithm


def get_dis_normalizer(algorithm: TokenizationAlgorithm) -> Normalizer | None:
    """Keep normalized DIS text unchanged before training."""

    del algorithm
    return None


def get_dis_pretokenizer(algorithm: TokenizationAlgorithm) -> PreTokenizer | None:
    """Split DIS text into instructions or word-level components."""

    if algorithm != TokenizationAlgorithm.WORDLEVEL:
        return pre_tokenizers.Sequence(
            [pre_tokenizers.Split(Regex(r"\n"), behavior="removed")]
        )
    return pre_tokenizers.Sequence(
        [
            pre_tokenizers.Split(Regex(r"\n"), behavior="removed"),
            pre_tokenizers.Split(Regex(r"[^a-zA-Z0-9_]"), behavior="isolated"),
            pre_tokenizers.Split(Regex(r"\s"), behavior="removed"),
            pre_tokenizers.Split(Regex(r"(0x)|[0-9A-F]"), behavior="isolated"),
        ]
    )
