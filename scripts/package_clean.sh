#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

mkdir -p dist

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  identifier="$(git rev-parse --short HEAD)"
else
  identifier="$(date -u +%Y%m%d%H%M%S)"
fi

output="$repo_root/dist/ares-clean-source-${identifier}.zip"
rm -f "$output"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    printf 'Warning: uncommitted changes are not included in the Git archive.\n' >&2
  fi
  git archive --format=zip --output="$output" HEAD
else
  if ! command -v zip >/dev/null 2>&1; then
    printf 'Error: neither git archive nor zip is available.\n' >&2
    exit 1
  fi
  zip -q -r "$output" . \
    -x '.git/*' \
    -x 'venv/*' \
    -x '.venv/*' \
    -x '__MACOSX/*' \
    -x '*/__pycache__/*' \
    -x '.pytest_cache/*' \
    -x '.mypy_cache/*' \
    -x '.ruff_cache/*' \
    -x '*/.DS_Store' \
    -x 'ares.db' \
    -x '*.db' \
    -x 'audit_logs/*' \
    -x 'reports/*' \
    -x 'dist/*' \
    -x '*.zip' \
    -x '.env' \
    -x '.env.local'

  if [[ -f reports/.gitkeep ]]; then
    zip -q "$output" reports/.gitkeep
  fi
fi

size="$(du -h "$output" | awk '{print $1}')"
printf 'Clean ARES source package: %s (%s)\n' "$output" "$size"
printf 'Share this ZIP, not a manually Finder-compressed working folder.\n'
