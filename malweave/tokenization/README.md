# Tokenization

This package converts the three preprocessing representations into token
sequences suitable for model training.

## Representation behavior

| Representation | Training units | Pre-tokenization |
| --- | --- | --- |
| EXE (`LiftLevel.RAW`) | 16-byte words | Bytes are mapped bijectively to private Unicode symbols |
| DIS | One instruction per line | Newlines separate instructions |
| DEC | One code fragment per line | Newlines separate code fragments |

`TokenizationTrainingIterator` reads artifact paths, decomposes each document,
and yields batches of strings. `TrainTokenizer` selects the model, normalizer,
pre-tokenizer, and trainer for BPE, Unigram, WordPiece, or WordLevel.

The default reproduction flow uses BPE with:

- a requested vocabulary of 16,384 tokens;
- seven special tokens;
- a maximum token length of 16 characters.

Training creates `tokenizer.json`, which contains the vocabulary and merge
rules. Applying that tokenizer creates one JSON token-ID sequence per sample.

Third-party licensing notices for incorporated components are retained in
`LICENSE.rawbyteclf`.
