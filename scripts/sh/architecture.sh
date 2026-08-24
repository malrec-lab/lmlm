#!/bin/bash
set -e

cd "$(dirname "$0")/../.."
source .venv/bin/activate

python -m malweave.data.architecture \
  --inarchives data/ranDS/raw \
  --outfile data/ranDS/processed/architecture/arch.json
