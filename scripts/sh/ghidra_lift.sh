#!/bin/bash
set -e

cd "$(dirname "$0")/../.."

if [ -z "$(docker images -q malweave:ghidra 2>/dev/null)" ]; then
  echo "Image malweave:ghidra not found locally. Building it now (one-time setup, several minutes)..." >&2
  docker build --platform linux/amd64 -t malweave:ghidra docker/ghidra
fi

if [ $# -lt 2 ]; then
  echo "Usage: $0 <binary_file> <output_dir>" >&2
  echo "Env vars: GHIDRA_CPUS (default 2), GHIDRA_MEMORY (default 4g)" >&2
  exit 1
fi

file="$1"
outdir="$2"

dir=$(cd "$(dirname "$file")" && pwd)
name=$(basename "$file")

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)

project_dir=$(mktemp -d)
trap 'rm -rf "$project_dir"' EXIT

docker run --rm --platform linux/amd64 \
  --cpus="${GHIDRA_CPUS:-2}" \
  --memory="${GHIDRA_MEMORY:-4g}" \
  -v "$dir":/input:ro \
  -v "$outdir":/output \
  -v "$project_dir":/project \
  -v "$(pwd)/docker/ghidra/scripts":/scripts:ro \
  malweave:ghidra \
  /project ghidra_proj \
  -overwrite \
  -log /output/log.txt \
  -processor x86:LE:32:default \
  -loader PeLoader \
  -analysisTimeoutPerFile 300 \
  -import "/input/$name" \
  -scriptPath /scripts \
  -postScript Disassembler.java /output 60 30 \
  -postScript Decompiler.java /output 300 60
