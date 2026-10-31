#!/usr/bin/env bash
# Plan a Terraform directory offline and run the Rego policies on the plan.
# Usage: bash scripts/plan-check.sh [terraform-dir] [extra conftest flags]
#   bash scripts/plan-check.sh terraform/vulnerable/gcp -o json
# Exits non-zero if a policy fails. `terraform apply` is never run.
set -uo pipefail

cd "$(dirname "$0")/.."
dir="${1:-terraform/fixed/gcp}"
shift || true

for tool in terraform conftest jq; do
  command -v "$tool" > /dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A fake token keeps the Google provider from looking for real credentials.
unset GOOGLE_APPLICATION_CREDENTIALS GOOGLE_CREDENTIALS GOOGLE_CLOUD_KEYFILE_JSON GCLOUD_KEYFILE_JSON
export GOOGLE_OAUTH_ACCESS_TOKEN="fake-token-not-real"

terraform -chdir="$dir" init -backend=false -input=false > "$work/init.log" 2>&1 \
  || { cat "$work/init.log" >&2; exit 1; }
terraform -chdir="$dir" plan -refresh=false -lock=false -input=false -out="$work/plan.bin" > "$work/plan.log" 2>&1 \
  || { cat "$work/plan.log" >&2; exit 1; }
terraform -chdir="$dir" show -json "$work/plan.bin" | jq -f scripts/plan-to-input.jq > "$work/input.json" \
  || exit 1

# The plan goes through stdin so findings show "<dir> (plan)" instead of a temporary path.
# (A file named conftest.json in the working directory would be read as Conftest's config.)
conftest test --all-namespaces --parser json --stdin-filename "${dir} (plan)" "$@" - < "$work/input.json"
