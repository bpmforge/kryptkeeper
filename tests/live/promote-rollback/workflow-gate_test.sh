#!/usr/bin/env bash
# W25-19 AC2: the promote and rollback workflows bind their deploy job to a
# GitHub environment, gate it behind the verification job, and can only be
# started by hand. This proves the workflow DEFINITION only: the required
# reviewers themselves are repo settings, checked by the owner with the `gh api`
# command printed at the end (see docs/release/UAT_PROMOTE_ROLLBACK_v0.13.md).
set -u
set -o pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WF_DIR="${WF_DIR:-$REPO/.github/workflows}"   # override only to prove the test can fail
FAILED=0
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }

# PyYAML as openapi-validate.yml uses; some workstations ship none, so fall back
# to Ruby's bundled YAML parser for the same data (no package is installed).
load_yaml_json() {
  if python3 -c 'import yaml' >/dev/null 2>&1; then
    python3 -c 'import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))' "$1"
  elif command -v ruby >/dev/null 2>&1; then
    ruby -ryaml -rjson -e 'puts JSON.dump(YAML.safe_load(File.read(ARGV[0]), aliases: true))' "$1"
  else
    echo "no YAML parser (PyYAML or ruby) available" >&2; return 1
  fi
}

check() { # file deploy_job gate_job
  local file="$1" deploy="$2" gate="$3" js name
  name="$(basename "$file")"
  js="$(load_yaml_json "$WF_DIR/$file")" || { FAIL "$name: cannot parse"; return; }
  # YAML 1.1 parsers turn the bare key `on` into boolean true.
  local env needs triggers
  env="$(echo "$js" | jq -r --arg j "$deploy" '.jobs[$j].environment // "" | if type=="object" then (.name // "") else . end')"
  needs="$(echo "$js" | jq -r --arg j "$deploy" '.jobs[$j].needs // [] | if type=="array" then . else [.] end | join(",")')"
  triggers="$(echo "$js" | jq -r '(.on // .["true"] // {}) | if type=="object" then keys|join(",") elif type=="array" then join(",") else . end')"
  [ -n "$env" ] && PASS "workflow_environment_bound: $name job '$deploy' environment='$env'" \
    || FAIL "workflow_environment_bound: $name job '$deploy' has no environment"
  case ",$needs," in *",$gate,"*) PASS "workflow_gate_needed: $name job '$deploy' needs '$gate'" ;;
    *) FAIL "workflow_gate_needed: $name job '$deploy' needs '$needs', not '$gate'" ;; esac
  [ "$triggers" = "workflow_dispatch" ] && PASS "workflow_no_push_trigger: $name on=[$triggers] only" \
    || FAIL "workflow_no_push_trigger: $name on=[$triggers]"
}

check promote-by-digest.yml deploy-target verify-signature
check rollback-by-digest.yml deploy-rollback precheck

echo "NOTE: environment protection rules live in repo settings, not YAML. the owner runs:"
echo "  gh api repos/bpmforge/kryptkeeper/environments/production --jq '.protection_rules[].type'   # expect required_reviewers"
[ "$FAILED" = 0 ] && { echo "ALL PASS (0 FAIL)"; exit 0; } || { echo "SOME FAILED"; exit 1; }
