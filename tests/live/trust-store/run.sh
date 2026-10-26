#!/usr/bin/env bash
# W40-03 live run: the real kryptkeeper-agent pushing a CA root into the OS trust
# store of a Debian-family and a RHEL-family container. Podman only.
#
#   bash tests/live/trust-store/run.sh [image ...]
#
# Default images: docker.io/library/debian:12 docker.io/library/rockylinux:9.
# The hub is a stub (tests/live/trust-store/stubhub): this run proves the agent
# half against real distributions; hub approval gating is covered by unit tests.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/podman.sh"
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$ROOT/tests/live/trust-store"
# The podman machine only virtiofs-mounts $HOME, so the work dir lives there.
WORK="$(mktemp -d "$HOME/.kk-trust-store.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

GOARCH="$(kk_goarch)"
echo "podman GOARCH=$GOARCH"
(cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORK/kryptkeeper-agent" ./cmd/kryptkeeper-agent) || { echo "FAIL: build agent"; exit 1; }
(cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$WORK/stubhub" ./tests/live/trust-store/stubhub) || { echo "FAIL: build stubhub"; exit 1; }
cp "$HERE/inner.sh" "$WORK/inner.sh"

images=("$@")
[ ${#images[@]} -gt 0 ] || images=(docker.io/library/debian:12 docker.io/library/rockylinux:9)

rc=0
for img in "${images[@]}"; do
  name="kk-trust-$(openssl rand -hex 3)"
  rm -f "$WORK/results.jsonl" "$WORK/agent.log" "$WORK/action"
  rm -rf "$WORK/pki"
  echo "=== $img ==="
  if ! podman run --rm --name "$name" -v "$WORK:/work" "$img" sh /work/inner.sh; then
    rc=1
  fi
done
exit $rc
