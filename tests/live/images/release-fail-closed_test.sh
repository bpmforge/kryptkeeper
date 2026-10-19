#!/usr/bin/env bash
# W25-18 AC2 (workflow-definition test): a failed image build must fail the
# release. Images are built inside the single `goreleaser` job (dockers: in
# .goreleaser.yaml), which also creates the GitHub release, so one failing
# image fails that job and, via needs:, every job after it. This static test
# pins that structure; if a separate image job is introduced later, extend it.
# No PyYAML/yq dependency: the workflow is parsed with a small indentation
# scan (top-level `jobs:` children and their `needs:`).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WF="$ROOT/.github/workflows/release.yml"
GR="$ROOT/.goreleaser.yaml"
FAILED=0
PASS() { echo "PASS: $*"; }
FAIL() { echo "FAIL: $*"; FAILED=1; }

n="$(grep -v '^[[:space:]]*#' "$WF" | grep -c 'continue-on-error')"
if [ "$n" -eq 0 ]; then PASS "release.yml has 0 continue-on-error"; else FAIL "release.yml has $n continue-on-error lines"; fi

# job -> space-separated needs, e.g. "goreleaser=test".
JOBS="$(python3 - "$WF" <<'PY'
import re, sys
jobs, cur, injobs = {}, None, False
for line in open(sys.argv[1]):
    if line.startswith("jobs:"): injobs = True; continue
    if not injobs: continue
    if re.match(r"^\S", line) and not line.startswith("#"): break
    m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
    if m: cur = m.group(1); jobs[cur] = []; continue
    m = re.match(r"^    needs:\s*(.*)$", line)
    if m and cur:
        jobs[cur] = re.findall(r"[A-Za-z0-9_-]+", m.group(1))
for j, n in jobs.items(): print(j + "=" + " ".join(n))
PY
)"
echo "$JOBS" | sed 's/^/  job /'

needs_of() { echo "$JOBS" | awk -F= -v j="$1" '$1==j{print $2}'; }
reaches() { # reaches <from> <to>: transitive needs
  local from="$1" to="$2" n
  for n in $(needs_of "$from"); do
    [ "$n" = "$to" ] && return 0
    reaches "$n" "$to" && return 0
  done
  return 1
}

echo "$JOBS" | grep -q '^goreleaser=' || FAIL "no goreleaser job (the job that builds the images and creates the release)"
reaches goreleaser test && PASS "goreleaser (images + release) needs test" || FAIL "goreleaser does not depend on test"
for j in $(echo "$JOBS" | cut -d= -f1); do
  [ "$j" = test ] && continue
  [ "$j" = goreleaser ] && continue
  reaches "$j" goreleaser && PASS "job $j depends (transitively) on goreleaser" || FAIL "job $j publishes without depending on goreleaser"
done

# The images: all four must be in a docker_manifests entry with both arches.
for img in kryptkeeper kryptkeeper-agent kryptkeeper-mcp kryptkeeper-certmanager; do
  for arch in amd64 arm64; do
    grep -q "ghcr.io/bpmforge/${img}:{{ .Version }}-${arch}" "$GR" \
      && PASS "docker_manifests lists $img $arch" || FAIL "docker_manifests missing $img $arch"
  done
done
grep -q '^docker_signs:' "$GR" && PASS "docker_signs present (keyless image signing)" || FAIL "no docker_signs in .goreleaser.yaml"

[ "$FAILED" -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL"; exit 1
