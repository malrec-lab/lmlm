# LMLM on RanDS Research Roadmap

This is the canonical execution plan for reproducing the LMLM methodology on RanDS. It is both a
review document for maintainers and a routing document for AI assistants. Implementation details
must not exist only in chat history.

The project reproduces a methodology on a new corpus. It does not claim to reproduce the paper's
original dataset or reported scores.

## How to use this plan

Statuses have the following meanings:

| Status | Meaning |
| --- | --- |
| `COMPLETED` | The phase gate passed and evidence is recorded. |
| `IN REVIEW` | Implementation exists but is not yet merged and verified on `main`. |
| `NEXT` | The only phase approved to begin after the current review completes. |
| `NOT STARTED` | Work must not begin until earlier gates pass. |
| `BLOCKED` | Progress requires a recorded maintainer decision or external prerequisite. |

Rules for maintainers and AI assistants:

1. Keep at most one implementation phase marked `NEXT` or actively in progress.
2. Do not skip a phase gate because later work appears independent.
3. Update this file in the same pull request that completes or materially changes a phase.
4. Record intentional differences among the paper, RawByteClf, and MalWeave.
5. Treat proposed commands and paths as interfaces to review, not existing functionality.
6. Never commit raw samples, sample hashes, local manifests, representations, or run artifacts.

## Current state

| Phase | Status | Outcome |
| --- | --- | --- |
| 0. Repository and RanDS inventory foundation | `COMPLETED` | Read-only corpus contract, CLI, tests, docs, `.env`, and cross-platform CI |
| 0.5. Repository hygiene | `IN REVIEW` | Remove unsolicited dependency automation and isolate documentation concurrency |
| 1. Reproduction protocol | `NEXT` | Reconcile paper, RawByteClf, and RanDS decisions before preprocessing |
| 2. Deterministic pilot manifest | `NOT STARTED` | Select and fully verify a bounded 1,000-sample cohort |
| 3. PE validation and EXE extraction | `NOT STARTED` | Produce deterministic executable-section bytes with failure accounting |
| 4. RAW versus EXE data products | `NOT STARTED` | Freeze representation rules and quantify truncation and redundancy |
| 5. Pilot baselines and RawByteClf port | `NOT STARTED` | Validate training and evaluation without leakage |
| 6. DIS representation | `NOT STARTED` | Add pinned, isolated headless disassembly after EXE is stable |
| 7. DEC representation | `NOT STARTED` | Add bounded decompilation with timeout and failure reporting |
| 8. Controlled scaling | `NOT STARTED` | Scale from 1,000 to 10,000 and then the approved full protocol |
| 9. Adapted reproduction | `NOT STARTED` | Run frozen multi-seed experiments on RanDS |
| 10. Research improvements | `NOT STARTED` | Evaluate improvements only against the frozen baseline |

## Phase 0: Repository and inventory foundation

### Delivered

- A versioned RanDS snapshot contract and normalized metadata loader.
- A read-only `malweave data inspect` command with bounded content-hash verification.
- Safe aggregate summaries and explicit local manifests.
- Machine-local corpus configuration through an ignored `.env`.
- Synthetic regression tests and Ubuntu, macOS, and Windows quality CI.
- Safety, reproducibility, and leakage rules in `AGENTS.md`.

### Gate evidence

- The real snapshot passed its release contract with 256 shards and 215,404 PE files.
- A deterministic 256-file content-hash sample had zero mismatches.
- `make check` passed before the phase was merged into `main`.

## Phase 0.5: Repository hygiene

### Deliverables

- Remove scheduled dependency-version update automation that was not maintainer-requested.
- Prevent documentation builds for unrelated pull requests from cancelling one another.
- Restrict GitHub Pages write and OIDC permissions to the deploy job.
- Keep dependency updates manual, narrow, reviewed, and separately tested.

### Gate

- [x] Source changes implemented and locally validated.
- [ ] Hygiene pull request merged into `main`.
- [ ] Quality and Documentation workflows pass on the merged commit.
- [ ] Unrequested dependency-update pull requests are closed.

Phase 1 must not modify preprocessing code until this gate is complete.

## Phase 1: Reproduction protocol

### Objective

Freeze what MalWeave is reproducing before porting implementation. The paper describes the
research claim, RawByteClf reveals operational details, and RanDS imposes new corpus constraints.
Conflicts among these sources must be documented rather than silently resolved.

### Required investigation

- Identify the exact paper revision and RawByteClf revision used as references.
- Trace collection filters, file types, architectures, packed-sample handling, and label rules.
- Trace RAW, EXE, DIS, and DEC construction, including ordering, truncation, padding, and failures.
- Trace split construction, random seeds, model inputs, training settings, and reported metrics.
- Classify each MalWeave choice as `faithful`, `dataset adaptation`, or `intentional extension`.

### Deliverables

- `configs/experiments/lmlm-rands-pilot.yaml` with reviewed protocol decisions.
- A maintained comparison table linking paper claims, RawByteClf code, and MalWeave choices.
- A list of unresolved decisions; no placeholder may silently become a default.
- Focused tests for any reusable protocol validation added in this phase.

### Open decisions

- Whether the adapted cohort includes EXE only or both EXE and DLL.
- The exact interpretation of `I386` and unpacked filtering.
- The faithful split policy and the additional family- or time-aware evaluation policy.
- Representation length, truncation direction, padding value, and empty-input behavior.
- Primary metrics and the number of seeds required for reported experiments.

### Gate

- [ ] Every open decision is resolved or explicitly deferred with a reason.
- [ ] Every divergence from the paper is labelled and reviewable.
- [ ] A second reader can derive the same cohort rules from config and documentation alone.
- [ ] `make check` passes.

## Phase 2: Deterministic 1,000-sample pilot

### Objective

Create a bounded cohort that validates the complete data path without paying full-corpus cost.
This pilot is engineering evidence, not the final evaluation dataset.

### Proposed local outputs

```text
data/interim/rands/2026-09-02/inventory.csv
data/interim/rands/2026-09-02/pilot-1000.csv
reports/rands/2026-09-02/pilot-1000.json
```

### Deliverables

- Deterministic selection based on a recorded seed and stable SHA-256-derived ranking.
- A reviewed class target, initially proposed as 500 benign and 500 ransomware samples.
- Ransomware-family stratification with explicit handling of low-support families.
- Full source SHA-256 verification for every selected sample.
- Selection, exclusion, availability, and verification fields in the pilot manifest.
- A manifest digest that is identical when regenerated from the same snapshot and config.

### Gate

- [ ] Exactly 1,000 unique available samples satisfy the approved protocol.
- [ ] All 1,000 source hashes match their canonical SHA-256 identifiers.
- [ ] No source or equivalent group crosses a pilot split.
- [ ] Regeneration produces a byte-identical manifest on supported platforms.
- [ ] Class and family distributions plus all exclusions are reported.

## Phase 3: PE validation and EXE extraction

### Objective

Extract bytes from executable/code PE sections without executing samples or mutating raw files.

### Deliverables

- A small parser adapter chosen after comparison with RawByteClf behavior.
- A deterministic section-selection and concatenation policy.
- Source and representation SHA-256 digests.
- Per-sample section count, extracted size, runtime, and structured status.
- Explicit failures such as `not_pe`, `truncated_header`, `invalid_section_table`,
  `no_executable_section`, `section_out_of_bounds`, and `read_error`.
- Synthetic PE fixtures and regression tests; no RanDS bytes in the test suite.

### Gate

- [ ] Every pilot sample is attempted exactly once or resumed idempotently.
- [ ] Every exclusion and failure has a stable machine-readable reason.
- [ ] Repeated successful extraction produces identical representation digests.
- [ ] Coverage, runtime, output size, and class-specific failures are reported.
- [ ] No Ghidra work has started.

## Phase 4: RAW versus EXE data products

### Deliverables

- Frozen RAW and EXE serialization, padding, and truncation rules.
- Representation manifests linked to source SHA-256 and protocol version.
- Truncation, empty-output, duplicate, and cross-sample redundancy reports.
- Storage and runtime estimates for the 10,000-sample canary and approved full cohort.

### Gate

- [ ] RAW and EXE pilot datasets regenerate deterministically.
- [ ] Representation-level leakage groups can be enforced before splitting.
- [ ] Output size and full-scale cost are acceptable or the protocol is revised.

## Phase 5: Pilot baselines and RawByteClf port

### Deliverables

- A deliberately simple baseline that can expose label, split, or metric errors.
- A tiny-batch overfit test before any full pilot training.
- RawByteClf components ported one unit at a time with attribution and regression tests.
- Frozen split manifests and deterministic evaluation code.
- Metrics reported by class, not only as one aggregate score.

### Gate

- [ ] The simple baseline and RawByteClf path run end to end on the pilot.
- [ ] A tiny cohort can be overfit, showing that optimization and labels are connected.
- [ ] Repeated evaluation of fixed predictions produces identical metrics.
- [ ] No tokenizer, normalizer, selector, resampler, or tuner is fit before splitting.

## Phases 6 and 7: DIS and DEC

DIS and DEC are separate phases because their costs and failure modes differ. Both require a
pinned Ghidra version, Java version, headless invocation, analysis options, script digest,
per-sample timeout, resume behavior, and isolated execution environment.

DIS begins with 50-100 samples before the 1,000-sample pilot. DEC begins only after DIS passes its
gate. Each phase must report coverage, timeout rate, runtime, output length, empty outputs,
representation duplicates, and storage requirements.

## Phase 8: Controlled scaling

Scale only through explicit gates:

```text
1,000-sample pilot -> 10,000-sample canary -> approved full protocol
```

The approved full protocol is expected to begin with `lmlm_x86_unpacked`, currently 83,235
available files. The 215,404-file corpus is a separate protocol and requires its own research
question. Storage tooling such as DVC and object storage must be selected from measured artifact
sizes and dataset terms, not added pre-emptively.

## Phase 9: Adapted reproduction

Run the frozen protocol with immutable manifests, representation digests, exact dependencies, Git
commit, seeds, hardware record, and at least the approved number of repeated runs. Report central
tendency and variation, class-wise metrics, failure coverage, and family support. Compare methods
within RanDS; do not present RanDS scores as exact reproduction of the paper's original results.

## Phase 10: Research improvements

Only compare improvements against the frozen Phase 9 baseline. Candidate studies include RAW vs
EXE vs DIS vs DEC, representation fusion, family-disjoint evaluation, time-aware evaluation,
packed/unpacked and architecture ablations, EXE/DLL effects, truncation length, and generalization
to unseen ransomware families.

## Phase completion record

When a phase completes, add one entry:

```text
YYYY-MM-DD | Phase N | commit/tag | config | local/CI evidence | approved deviations
```

Current evidence:

```text
2026-09-03 | Phase 0 | c596b77 | rands-raw-2026.yaml | real-corpus contract + make check | RanDS methodology adaptation
```
