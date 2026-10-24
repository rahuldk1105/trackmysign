#!/usr/bin/env bash
# Print the release notes for a tag (v1.2.3) from its CHANGELOG.md section.
set -euo pipefail
tag="$1"
ver="${tag#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"
section="$(awk -v v="$ver" '
  $0 ~ "^## \\[" v "\\]" { f = 1; next }
  /^## \[/ { f = 0 }
  f' "$root/CHANGELOG.md" | sed '/./,$!d')"
prev="$(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$root/CHANGELOG.md" |
  grep -A1 -F "[$ver]" | tail -n +2 | tr -d '#[] ')"
if [[ -n "$section" ]]; then
  printf '%s\n' "$section"
else
  echo "See [CHANGELOG.md](https://github.com/rahuldk1105/trackmysign/blob/main/CHANGELOG.md)."
fi
if [[ -n "$prev" ]]; then
  printf '\n**Full changelog:** https://github.com/rahuldk1105/trackmysign/compare/v%s...%s\n' "$prev" "$tag"
fi
