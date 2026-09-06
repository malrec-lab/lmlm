"""Representation and tokenizer algorithm names."""

from enum import Enum


class LiftLevel(Enum):
    """Input representation consumed by a tokenizer."""

    RAW = "raw"
    DIS = "dis"
    DEC = "dec"
    NOP = "nop"
    ALL = "all"


class TokenizationAlgorithm(Enum):
    """Supported tokenization algorithms."""

    BPE = "bpe"
    UNIGRAM = "uni"
    WORDPIECE = "wdp"
    WORDLEVEL = "wdl"
