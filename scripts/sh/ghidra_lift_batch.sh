#!/bin/bash
set -e

cd "$(dirname "$0")/../.."

if [ $# -lt 2 ]; then
  echo "Usage: $0 <inarchives_dir> <output_dir>" >&2
  echo "  <inarchives_dir>: directory containing .zip archives of samples" >&2
  echo "  <output_dir>: each sample's .asm/.c/log.txt go into <output_dir>/<sample_name>/" >&2
  exit 1
fi

inarchives="$1"
outdir="$2"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

for zip in "$inarchives"/*.zip; do
  echo "Extracting: $zip"
  unzip -j -o -q "$zip" -d "$tmpdir"
done

mkdir -p "$outdir"

for f in "$tmpdir"/*; do
  name=$(basename "$f")
  echo "Processing: $name"
  scripts/sh/ghidra_lift.sh "$f" "$outdir/$name"
done

echo "Done. Results in: $outdir"
