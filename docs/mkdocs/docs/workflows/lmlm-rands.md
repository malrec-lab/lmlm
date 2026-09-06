# LMLM on RanDS Workflow

This workflow reproduces the data methodology from "Beyond Raw Bytes" on a new ransomware
corpus. It is not a reproduction of the paper's exact datasets or reported scores.

Use the [research roadmap](lmlm-rands-roadmap.md) as the canonical phase plan and completion
checklist. This page documents the implemented inventory and pilot-manifest workflows.

## Implemented milestone: inventory the raw release

The first milestone is read-only. It validates metadata, paths, release counts, and protocol
coverage before any PE representation is extracted.

Do not run this workflow from a directory synchronized to public cloud storage. Raw RanDS files
are live malware and must remain in an isolated, access-controlled location.

## 1. Point MalWeave at the local corpus

Create a machine-local configuration file from the committed template:

```bash
cp .env.example .env
```

Set the extracted corpus path in `.env`:

```dotenv
MALWEAVE_RANDS_DIR=/path/to/RanDS_PE_Dataset
```

The CLI loads the root `.env` automatically and the file is ignored by Git. Do not commit local
paths, credentials, or private storage URLs. For CI or a one-off shell, the variable may instead be
exported directly:

```bash
export MALWEAVE_RANDS_DIR=/path/to/RanDS_PE_Dataset
```

Root resolution uses this precedence, from highest to lowest:

1. The explicit `--root /path/to/RanDS_PE_Dataset` CLI argument.
2. `MALWEAVE_RANDS_DIR` already supplied by the shell or CI environment.
3. `MALWEAVE_RANDS_DIR` loaded from the root `.env` file.

The configured root must contain:

```text
Benign.csv
Ransomware.csv
dataset/
  00/
  01/
  ...
  ff/
```

## 2. Run the read-only audit

```bash
uv run --locked malweave data inspect --dataset rands
```

The command prints aggregate JSON only. It does not print sample hashes, execute binaries, create
directories, or write a manifest by default.

Exit status meanings:

| Status | Meaning |
| ---: | --- |
| `0` | The local corpus matches the committed release contract. |
| `1` | Inspection completed, but expected counts or integrity checks failed. |
| `2` | Configuration, schema, path, or I/O error prevented inspection. |

## 3. Interpret the release contract

The audited `2026-09-02` snapshot expects:

| Item | Expected |
| --- | ---: |
| SHA-256 shards | 256 |
| Available PE files | 215,404 |
| Available benign files | 110,788 |
| Available ransomware files | 104,616 |

The CSV files advertise more samples than the archive contains. This is expected for this
snapshot: unavailable metadata rows remain visible in the audit and in an optional manifest.

The released `Ransomware.csv` also has a schema mismatch. Its header says
`Family, Packed, Entropy`, while its rows store `Packed, Entropy, Family`. MalWeave detects the
value layout and normalizes it. Do not bypass the loader with a plain `csv.DictReader`.

## 4. Verify a bounded content sample

Hashing one deterministic PE per shard provides a stronger check without reading the full corpus:

```bash
uv run --locked malweave data inspect \
  --dataset rands \
  --verify-hashes sample
```

`--verify-hashes all` reads every byte in the roughly 170 GiB corpus. Use it only as an explicit
integrity job, not as part of routine development.

## 5. Save local outputs when needed

An aggregate summary contains no sample hashes and may be written explicitly:

```bash
uv run --locked malweave data inspect \
  --dataset rands \
  --summary reports/rands/2026-09-02/inspection.json
```

A manifest contains sample hashes and must remain ignored or outside the repository:

```bash
uv run --locked malweave data inspect \
  --dataset rands \
  --manifest data/interim/rands/2026-09-02/inventory.csv
```

Manifests written inside the repository are accepted only under `data/interim/` or
`data/processed/`, both of which are ignored. Provider machine paths are deliberately excluded.
This full-release inventory is an optional Phase 0 diagnostic/provenance artifact, not an input to
the Phase 2 pilot command.

## Protocols reported by the audit

`full` includes every available PE. `lmlm_x86_unpacked` retains samples whose metadata says
`Arch=I386` and `Packed=0`, matching the paper's principal collection filters more closely.

Keep these protocols separate. The full corpus has strong class correlations with architecture
and packing status; the filtered protocol changes class balance and removes many low-support
ransomware families.

## 6. Build the deterministic Phase 2 pilot

After the audit release contract passes, build the local pilot with explicit output paths:

```bash
uv run --locked malweave data pilot \
  --dataset rands \
  --manifest data/interim/rands/2026-09-02/pilot-1000.csv \
  --summary reports/rands/2026-09-02/pilot-1000.json
```

The command uses the committed `lmlm-rands-pilot.yaml` by default. It filters available metadata
to EXE/DLL, `I386`, and unpacked samples, then ranks source SHA-256 values using the recorded seed.
It selects 500 benign samples directly. For ransomware it allocates 500 slots proportionally across
eligible families with the largest-remainder method, breaking exact ties with a SHA-256-derived
family rank. It then selects the best ranked sources within each family.

The command first reads metadata and the filesystem through the Phase 0 release contract. It reads
the bytes of exactly the selected 1,000 source files only to calculate SHA-256; it does not parse,
execute, or modify a PE. It writes:

- `pilot-1000.csv`: source identities, cohort metadata, deterministic selection fields, and a
  `source_hash_verified=1` field. It contains sample hashes and remains ignored.
- `pilot-1000.json`: aggregate targets, exclusions, family allocation, bytes read, verification
  counts, and the manifest digest. It contains no individual sample hashes and remains ignored.

If the release contract fails, selection stops. If any selected file has the wrong SHA-256, the
command writes only a failure summary and returns status `1`; it never writes a valid manifest.
Status `2` means configuration, path, or I/O prevented completion.

Run the same command again with a different local filename to compare manifest digests or bytes.
Given an unchanged snapshot and config, the manifest is byte-identical across supported platforms.
This pilot is engineering evidence only: it is not a scientific train/validation/test split, and it
does not yet establish representation-equivalence groups.

## Protocol review

Phase 1 decisions are recorded in the short [LMLM on RanDS protocol](lmlm-rands-protocol.md) and
its experiment config. The deterministic 1,000-sample pilot is in maintainer review. Do not start
executable-section extraction, Ghidra disassembly, or decompilation until its roadmap gate passes.
