"""Shared no-op tokenizer primitives."""

from tokenizers import Regex, normalizers, pre_tokenizers

SENTINEL_PATTERN = Regex(r"a^")
SENTINEL_NORMALIZER = normalizers.Replace(SENTINEL_PATTERN, "")
SENTINEL_PRETOKENIZER = pre_tokenizers.Split(SENTINEL_PATTERN, "isolated")
