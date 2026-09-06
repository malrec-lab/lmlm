# LMLM on RanDS Protocol

This is the short research contract for the first RanDS pilot. Its companion config is
`configs/experiments/lmlm-rands-pilot.yaml`. It records decisions before any PE content is parsed.

MalWeave adapts the LMLM methodology to RanDS. It does not reproduce the original paper dataset or
claim the paper's reported scores. The task is ransomware-versus-benign classification, not general
malware detection.

## Reference points

| Source | What MalWeave uses |
| --- | --- |
| Paper | *Beyond Raw Bytes: Towards Large Malware Language Models*, NDSS 2026, DOI `10.14722/ndss.2026.230103` |
| Implementation reference | RawByteClf commit `2502450e40ac00363e168106662aac29821d4a93` |
| New corpus | RanDS snapshot `2026-09-02` |

The paper defines the research intent. RawByteClf clarifies operational details when the paper does
not specify them. A conflict stays documented; source code does not silently overrule the paper.

## Pilot decisions

| Topic | Decision | Why |
| --- | --- | --- |
| Labels | Benign `0`, ransomware `1` | RanDS is a ransomware corpus, so this is an adaptation. |
| Input files | EXE and DLL, `Arch=I386`, `Packed=0`, file must exist | Closest available RanDS proxy for the paper's PE, x86, and unpacked filters. |
| Pilot size | 500 benign + 500 ransomware | Small, balanced engineering cohort; not a prevalence estimate or scientific split. |
| Pilot ranking | SHA-256 of `lmlm-rands-pilot-v1:sample:<source SHA-256>` | Stable across input ordering and supported operating systems. |
| Ransomware allocation | Proportional largest remainder across eligible families | Preserves the aggregate family mix without forcing every low-support family into 500 slots. |
| First representation | EXE | Fastest code-only representation; DIS and DEC wait for their own cost/failure gates. |
| EXE bytes | Concatenate executable-or-code sections in section-table order | Matches the paper and RawByteClf behavior. |
| Identity | SHA-256 for source and exact representation bytes | Enables source verification and representation-level leakage prevention. |
| Duplicates | Group exact equal representations before splitting | Identical model inputs must not cross scientific partitions. |
| Tokenization later | 16-byte EXE words, then BPE/unigram | Matches the paper's basic vectorization idea. |

`I386` and `Packed=0` are metadata adaptations. They are not claims that RanDS used the exact
Linux `file` and Detect-It-Easy filtering process from the paper.

## What happens next

Phase 2 creates a deterministic 1,000-sample local manifest, verifies every selected source hash,
and reports exclusions by class and ransomware family. A family with no allocated slot is reported;
a family whose target equals its eligible count is also reported. It must not start PE parsing yet.

Phase 3 compares a small parser adapter with the RawByteClf EXE rules using synthetic PE fixtures,
then extracts EXE bytes with structured failures and representation SHA-256 digests.

The following remain intentionally open until evidence exists: LIEF versus pefile, scientific split
proportions, padding/model choice, and all Ghidra toolchains. They are not hidden defaults.
