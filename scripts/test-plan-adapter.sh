#!/usr/bin/env bash
# Check scripts/plan-to-input.jq against the cases in fixtures/plan/cases.
# Usage: bash scripts/test-plan-adapter.sh
set -uo pipefail
cd "$(dirname "$0")/.."

passed=0
failed=0
for input in fixtures/plan/cases/*.input.json; do
  name="$(basename "$input" .input.json)"
  expected="fixtures/plan/cases/${name}.expected.json"
  if diff <(jq -S . "$expected") <(jq -S -f scripts/plan-to-input.jq "$input" 2>&1) > /dev/null; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: ${name}"
    diff <(jq -S . "$expected") <(jq -S -f scripts/plan-to-input.jq "$input" 2>&1) | head -15
  fi
done

echo "${passed} passed, ${failed} failed"
[ "$failed" -eq 0 ]
