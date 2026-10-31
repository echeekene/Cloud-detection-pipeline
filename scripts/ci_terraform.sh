#!/usr/bin/env bash
# Plan or deploy one delivery module from GitHub Actions. See docs/CICD.md.
#   bash scripts/ci_terraform.sh plan   <module>   read only role, no state lock, writes a fingerprint
#   bash scripts/ci_terraform.sh deploy <module>   deploy role, re-plans and applies only if the
#                                             changes match the reviewed plan's fingerprint
# Needs AWS_ACCOUNT_ID and AWS credentials in the environment. Run from the repository root.
set -euo pipefail

# It overwrites tfvars and infra/backend.hcl, so it refuses to run on a workstation by accident.
[[ "${GITHUB_ACTIONS:-}" == "true" || "${CI_TERRAFORM_LOCAL:-}" == "1" ]] || { echo "Runs in GitHub Actions only (set CI_TERRAFORM_LOCAL=1 to override)" >&2; exit 1; }

mode="${1:?plan or deploy}"
module="${2:?module name}"
case "$module" in api|alerts|simulator|monitoring) ;; *) echo "CI does not deploy '$module'" >&2; exit 1 ;; esac
[[ "${AWS_ACCOUNT_ID:-}" =~ ^[0-9]{12}$ ]] || { echo "AWS_ACCOUNT_ID must be a 12-digit account ID" >&2; exit 1; }

root="$(pwd)"
dir="infra/$module"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
fingerprint_file="$root/plan-fingerprint-$module.txt"

# Shared backend settings (the file is gitignored, so CI writes its own).
sed "s/ACCOUNT_ID/$AWS_ACCOUNT_ID/" infra/backend.hcl.example > infra/backend.hcl

# Inputs: build the Lambda package fresh from this commit. The build is deterministic, so an
# unchanged commit produces the same checksum and no code update.
if [[ "$module" == "monitoring" ]]; then
  printf '{"expected_account_id": "%s"}\n' "$AWS_ACCOUNT_ID" > "$dir/terraform.tfvars.json"
else
  rm -f "work/$module-package.zip"
  python scripts/build_api_package.py --target "$module" --output "work/$module-package.zip" \
    --tfvars "$dir/terraform.tfvars.json" --account "$AWS_ACCOUNT_ID" > /dev/null
fi

tf() { terraform -chdir="$dir" "$@"; }
tf init -input=false -lockfile=readonly -backend-config=../backend.hcl > /dev/null

lock_flag=()
[[ "$mode" == "plan" ]] && lock_flag=(-lock=false)   # the plan role cannot write the lock file

set +e
tf plan -input=false -no-color -detailed-exitcode "${lock_flag[@]}" -out=ci.tfplan > plan.log 2>&1
code=$?
set -e
redact() { sed "s/$AWS_ACCOUNT_ID/<account-id>/g"; }
if [[ $code -eq 1 ]]; then
  redact < plan.log
  { echo "### $module: plan failed"; echo '```'; tail -n 40 plan.log | redact; echo '```'; } >> "$summary"
  exit 1
fi

tf show -json ci.tfplan | python scripts/plan_fingerprint.py > "$fingerprint_file" 2> changes.txt
{
  if [[ $code -eq 0 ]]; then
    echo "### $module: no changes"
  else
    echo "### $module: $(wc -l < changes.txt) resource change(s)"
    echo '```'; redact < changes.txt; echo '```'
    echo "<details><summary>Full plan</summary>"; echo; echo '```'
    { tf show -no-color ci.tfplan | redact | head -c 60000; } || true; echo '```'; echo "</details>"
  fi
  echo
} >> "$summary"
tail -n 3 plan.log | redact

if [[ "$mode" == "plan" ]]; then
  exit 0
fi

# Deploy: apply only what was reviewed.
reviewed="${REVIEWED_FINGERPRINT_FILE:?path to the plan job fingerprint}"
if ! cmp -s "$reviewed" "$fingerprint_file"; then
  echo "The changes differ from the reviewed plan (state or AWS changed since). Re-run the workflow." >&2
  echo "### $module: refused, changes differ from the reviewed plan" >> "$summary"
  exit 1
fi
if [[ $code -eq 0 ]]; then
  echo "No changes for $module."
  exit 0
fi
tf apply -input=false -no-color ci.tfplan 2>&1 | redact
echo "### $module: applied" >> "$summary"
