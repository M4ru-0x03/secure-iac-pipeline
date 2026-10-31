#!/usr/bin/env bash
# Print a Markdown summary of Conftest JSON results (violations and warnings).
# Usage: bash scripts/conftest-summary.sh <results.json> <title>
set -euo pipefail

results="${1:?usage: conftest-summary.sh <results.json> <title>}"
title="${2:?usage: conftest-summary.sh <results.json> <title>}"

echo "## ${title}"

violations="$(jq '[.[] | (.failures // []) | length] | add // 0' "$results")"
if [ "$violations" -eq 0 ]; then
  echo "No policy violations."
else
  echo "**${violations} violation(s)**"
  echo
  echo "| File | Policy | Finding |"
  echo "|---|---|---|"
  jq -r '.[] | .filename as $f | .namespace as $n | (.failures // [])[] | "| \($f) | \($n) | \(.msg) |"' "$results"
fi

# Warnings never fail the job, but they must stay visible.
warnings="$(jq '[.[] | (.warnings // []) | length] | add // 0' "$results")"
if [ "$warnings" -gt 0 ]; then
  echo
  echo "**${warnings} warning(s)** (these do not block the merge)"
  echo
  echo "| File | Policy | Warning |"
  echo "|---|---|---|"
  jq -r '.[] | .filename as $f | .namespace as $n | (.warnings // [])[] | "| \($f) | \($n) | \(.msg) |"' "$results"
fi
