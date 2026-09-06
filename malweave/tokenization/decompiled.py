"""Decompiled-code tokenizer configuration."""


from tokenizers import Regex, pre_tokenizers
from tokenizers.normalizers import Normalizer
from tokenizers.pre_tokenizers import PreTokenizer

from .enums import TokenizationAlgorithm


def get_dec_normalizer(algorithm: TokenizationAlgorithm) -> Normalizer | None:
    """Keep normalized DEC text unchanged before training."""

    del algorithm
    return None


def get_dec_pretokenizer(algorithm: TokenizationAlgorithm) -> PreTokenizer | None:
    """Split DEC text into newline-delimited code fragments."""

    if algorithm != TokenizationAlgorithm.WORDLEVEL:
        return pre_tokenizers.Sequence(
            [pre_tokenizers.Split(Regex(r"\n"), behavior="removed")]
        )
    raise NotImplementedError("DEC WordLevel tokenization is not implemented")
