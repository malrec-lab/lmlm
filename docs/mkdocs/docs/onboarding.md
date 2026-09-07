# Onboarding a Research Task

Use this page when you are new to MalWeave or when you are about to implement a new research task.
The project is deliberately phased: do not start a later task just because its code appears
independent.

## Know the current boundary

MalWeave currently implements three RanDS operations:

```text
local RanDS release -> metadata and filesystem audit -> aggregate JSON or local manifest
local RanDS release -> deterministic pilot selection -> source-hash-verified local manifest
verified pilot manifest -> static EXE-section extraction -> local representations and report
```

No operation executes a PE. The EXE command statically parses and extracts sections, but the project
does not yet train tokenizers or models, or run Ghidra. Those are planned phases, not hidden
features. [LMLM on RanDS](workflows/lmlm-rands.md) is the source of truth for the implemented
commands and outputs.

## Read in this order

| Read | Why it comes now |
| --- | --- |
| `README.md` | Understand the project scope and the top-level workflow. |
| [Getting Started](getting-started.md) | Set up the locked Python environment and machine-local data path. |
| `AGENTS.md` | Learn non-negotiable malware safety, testing, and leakage rules. |
| [Project Structure](project-structure.md) | Learn where code, tests, configs, docs, and ignored artifacts belong. |
| [RanDS dataset card](datasets/rands.md) | Learn the corpus layout, metadata caveats, and use restrictions. |
| [LMLM on RanDS](workflows/lmlm-rands.md) | Understand the implemented audit and its local outputs. |
| [LMLM on RanDS roadmap](workflows/lmlm-rands-roadmap.md) | Confirm which phase is allowed to start. |
| The focused test, then its implementation | Learn the expected behavior before reading the code. |

For the current implementation, read `tests/data/test_pe_sections.py` before
`malweave/data/pe_sections.py`, then `tests/data/test_rands_exe.py` before
`malweave/data/rands_exe.py`. Read the pilot and audit tests afterward. The tests use synthetic
bytes and show the contracts without exposing a real sample.

## Implement a new task

Follow this sequence for every durable task:

1. Find the phase in the roadmap. If it is not `NEXT`, stop and resolve the earlier gate first.
2. Write one sentence describing the input, output, and scientific purpose.
3. List failure cases that must be reported rather than silently discarded.
4. Record dataset-specific choices in a committed config when they affect a result.
5. Write a synthetic focused test before or alongside reusable code.
6. Put reusable data logic in `malweave/data/`; put split and metric logic in
   `malweave/evaluation/`; put model code in `malweave/models/`; put run orchestration in
   `malweave/training/`.
7. Add a CLI command only after its library function and tests are clear. A command is for a
   repeatable user workflow, not a substitute for code structure.
8. Update the relevant dataset/workflow document with the command, outputs, and interpretation.
9. Run the focused test, then `make check`.
10. Review the diff with a maintainer before committing. Do not commit raw samples, manifests,
    representation bytes, model outputs, or local paths.

## Where things go

| Item | Location | Versioned? |
| --- | --- | --- |
| Release contract or experiment choice | `configs/` | Yes, if non-sensitive |
| Raw corpus and generated manifest | `data/raw/`, `data/interim/`, `data/processed/` | No |
| Reusable RanDS/PE processing | `malweave/data/` | Yes |
| Split, leakage, and metric behavior | `malweave/evaluation/` | Yes |
| Tokenizer and neural-network components | `malweave/models/` | Yes |
| Training and run orchestration | `malweave/training/` | Yes |
| Regression test | Mirror the code under `tests/` | Yes |
| Checkpoints and predictions | `models/` | No |
| Run-specific reports and figures | `reports/` | No |

## Worked example: the active RanDS task

Phase 2 creates a deterministic, local 1,000-sample pilot manifest. The exact cohort rules,
selection seed, family-allocation policy, and phase boundary live in the
[protocol](workflows/lmlm-rands-protocol.md) and [roadmap](workflows/lmlm-rands-roadmap.md); do
not create a second source of truth in code comments or shell scripts.

The implementation begins with a synthetic manifest-selection test in `tests/data/`, then a small
function in `malweave/data/`. Reuse the normalized metadata reader in `malweave/data/rands.py`
instead of duplicating CSV parsing. Phase 2 must not parse PEs, extract EXE bytes, run Ghidra, fit a
tokenizer, train a model, or create a scientific split. Phase 3 remains blocked until the Phase 2
gate has maintainer-reviewed local evidence.
