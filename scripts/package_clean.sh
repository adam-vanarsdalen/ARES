#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if ! git diff --quiet || ! git diff --cached --quiet; then
  printf 'Warning: uncommitted changes are not included in the source package.\n' >&2
fi

mkdir -p dist
revision="$(git rev-parse --short HEAD)"
output="$repo_root/dist/ares-source-${revision}.zip"

rm -f "$output"
git archive \
  --format=zip \
  --output="$output" \
  HEAD \
  -- \
  . \
  ':(exclude).env' \
  ':(exclude)audit_logs/**' \
  ':(exclude)reports/**' \
  ':(exclude)ares.db' \
  ':(exclude)ares.db-shm' \
  ':(exclude)ares.db-wal'

zip -q "$output" reports/.gitkeep
printf '%s\n' "$output"
