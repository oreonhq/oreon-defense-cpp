#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
exec >/dev/null 2>&1
SPEC=$(ls packaging/*.spec 2>/dev/null | head -1)
NAME=$(awk '/^Name:/{print $2; exit}' "$SPEC")
VER=$(awk '/^Version:/{print $2; exit}' "$SPEC")
OUT="${NAME}-${VER}.tar.gz"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "${STAGE}/${NAME}-${VER}"
tar -C . --exclude='./build' --exclude='./.git' --exclude='./*.tar.gz' --exclude='./buildsrc.sh' \
  -cf - . | tar -C "${STAGE}/${NAME}-${VER}" -xf -
tar -C "$STAGE" -czf "$OUT" "${NAME}-${VER}"
