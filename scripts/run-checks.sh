#!/usr/bin/env bash
# Run the same checks as CI against one Terraform directory.
# Usage: bash scripts/run-checks.sh [terraform-dir]    (default: terraform/fixed/gcp)
# Exits non-zero if any check fails. Pointing it at terraform/vulnerable/gcp is expected to fail.
set -uo pipefail

cd "$(dirname "$0")/.."
dir="${1:-terraform/fixed/gcp}"

for tool in terraform conftest checkov; do
  command -v "$tool" > /dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

failed=0
run() {
  local title="$1"
  shift
  echo
  echo "== ${title}"
  "$@" || failed=1
}

validate() {
  terraform -chdir="$1" init -backend=false -input=false > /dev/null && terraform -chdir="$1" validate
}

run "terraform fmt" terraform fmt -check -recursive "$dir"
run "terraform validate" validate "$dir"
run "policy unit tests" conftest verify
run "policies on ${dir}" conftest test --all-namespaces --parser hcl2 "$dir"/*.tf
run "plan adapter tests" bash scripts/test-plan-adapter.sh
run "policies on the plan of ${dir}" bash scripts/plan-check.sh "$dir"
run "checkov on ${dir}" checkov -d "$dir" --framework terraform --compact --quiet

echo
if [ "$failed" -eq 0 ]; then
  echo "All checks passed for ${dir}"
else
  echo "Some checks failed for ${dir}"
fi
exit "$failed"
