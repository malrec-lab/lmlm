#!/bin/bash
set -e

cd "$(dirname "$0")/../.."

if [ -z "$(docker images -q horsicq:diec 2>/dev/null)" ]; then
  echo "Image horsicq:diec not found locally. Building it now (one-time setup)..." >&2
  docker build --platform linux/amd64 -t horsicq:diec docker/diec
fi

if [ $# -lt 1 ]; then
  echo "Usage: $0 [diec options] <file>" >&2
  exit 1
fi

file="${@: -1}"
opts=("${@:1:$#-1}")

dir=$(cd "$(dirname "$file")" && pwd)
name=$(basename "$file")

docker run --rm --platform linux/amd64 -v "$dir":/work horsicq:diec "${opts[@]}" "/work/$name"
