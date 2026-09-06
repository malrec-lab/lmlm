"""Raw executable-byte tokenizer configuration."""

from tokenizers.normalizers import Normalizer
from tokenizers.pre_tokenizers import PreTokenizer

from .core import SENTINEL_NORMALIZER, SENTINEL_PRETOKENIZER
from .enums import TokenizationAlgorithm


def get_raw_normalizer(algorithm: TokenizationAlgorithm) -> Normalizer:
    """Return a no-op normalizer so executable bytes remain unchanged."""

    del algorithm
    return SENTINEL_NORMALIZER


def get_raw_pretokenizer(algorithm: TokenizationAlgorithm) -> PreTokenizer:
    """Return a no-op pre-tokenizer so BPE receives the mapped byte stream."""

    del algorithm
    return SENTINEL_PRETOKENIZER
