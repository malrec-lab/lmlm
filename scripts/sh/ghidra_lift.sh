#!/bin/bash
set -e

cd "$(dirname "$0")/../.."

if [ -z "$(docker images -q malweave:ghidra 2>/dev/null)" ]; then
  echo "Image malweave:ghidra not found locally. Building it now (one-time setup, several minutes)..." >&2
  docker build --platform linux/amd64 -t malweave:ghidra docker/ghidra
fi

if [ $# -lt 2 ]; then
  echo "Usage: $0 <binary_file> <output_dir>" >&2
  echo "Env vars: GHIDRA_CPUS (default 2), GHIDRA_MEMORY (default 4g), GHIDRA_WALL_TIMEOUT (default 720s)" >&2
  exit 1
fi

file="$1"
outdir="$2"

file=$(cd "$(dirname "$file")" && pwd)/$(basename "$file")
name=$(basename "$file")

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)

staging_dir=$(mktemp -d)
container_name="malweave-ghidra-$$"
cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  rm -rf "$staging_dir"
}
trap cleanup EXIT INT TERM

# The repository may itself be a Docker Desktop bind mount (as it is in a
# Dev Container/WSL workspace). Such paths cannot reliably be bind-mounted
# into a second container, so stage all container inputs in native /tmp.
mkdir -p "$staging_dir/input" "$staging_dir/output" "$staging_dir/project" "$staging_dir/scripts"
cp -- "$file" "$staging_dir/input/$name"
cp -- docker/ghidra/scripts/*.java "$staging_dir/scripts/"

status=0
timeout --signal=TERM --kill-after=15s "${GHIDRA_WALL_TIMEOUT:-720}" \
docker run --rm --name "$container_name" --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  --cpus="${GHIDRA_CPUS:-2}" \
  --memory="${GHIDRA_MEMORY:-4g}" \
  --mount "type=bind,src=$staging_dir/input,dst=/input,readonly" \
  --mount "type=bind,src=$staging_dir/output,dst=/output" \
  --mount "type=bind,src=$staging_dir/project,dst=/project" \
  --mount "type=bind,src=$staging_dir/scripts,dst=/scripts,readonly" \
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
  -postScript Decompiler.java /output 300 60 || status=$?

cp -a "$staging_dir/output/." "$outdir/"
exit "$status"
