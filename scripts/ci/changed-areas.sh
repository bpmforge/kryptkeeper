#!/usr/bin/env bash
# Prints which areas of the repo a change touches, one `area=true|false` per
# line, for ci-pr's job filters and the local `make gate`.
#
# Usage: scripts/ci/changed-areas.sh [base-ref]   (default: merge base with origin/main)
# Areas: go ui api docker ansible site docs ci all. `ci` (workflows, scripts,
# Makefile, build config) or an unknown base sets `all`, so a change to how
# things are built or tested always runs everything.
set -euo pipefail

base="${1:-}"
if [ -z "$base" ]; then
  base=$(git merge-base HEAD origin/main 2>/dev/null || true)
fi

# Plain variables, not an associative array: macOS still ships bash 3.2.
go=false ui=false api=false docker=false ansible=false site=false docs=false ci=false
if [ -z "$base" ] || ! files=$(git diff --name-only "$base"...HEAD 2>/dev/null); then
  ci=true
  files=""
fi

while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    .github/*|scripts/*|Makefile|.golangci*|.goreleaser*|.gitattributes|.dockerignore) ci=true ;;
    ui/*) ui=true ;;
    docs/openapi.yaml) api=true ;;
    Dockerfile*|docker-compose*|charts/*|nginx.conf|packaging/*|env.example) docker=true ;;
    ansible/*) ansible=true ;;
    site/*) site=true ;;
    go.mod|go.sum|*.go|cmd/*|internal/*|sdk/*|plugins/*|tests/*|terraform-provider-kryptkeeper/*|deploy/*) go=true ;;
    *) docs=true ;;
  esac
done <<< "$files"

all=$ci
for k in go ui api docker ansible site docs ci; do
  if [ "$all" = true ]; then echo "$k=true"; else echo "$k=${!k}"; fi
done
echo "all=$all"
