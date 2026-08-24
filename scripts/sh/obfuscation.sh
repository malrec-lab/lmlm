#!/bin/bash
set -e

cd "$(dirname "$0")/../.."
source .venv/bin/activate

python -m malweave.data.obfuscation \
  --inarchives data/ranDS/raw \
  --outfile data/ranDS/processed/obfuscation/obfuscation.json
