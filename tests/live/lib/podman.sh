# Sourced by tests/live/*/run.sh (and fixture/lib helpers) that drive podman.
# One copy of the runner workarounds that used to be pasted per harness. None
# of them changes what a harness asserts.

# kk_rm NAME...: one `podman rm -f` per name. podman 4.9 (Linux) removes
# nothing when any name in a single `rm -f a b` does not exist, so a container
# that never started used to leave its siblings (and the network) behind and
# break the next run's "network create". KK_RM_TIMEOUT (seconds) is passed as
# `-t` when set; unset keeps podman's default graceful stop.
kk_rm() {
  local n
  for n in "$@"; do
    [ -n "$n" ] || continue
    podman rm -f ${KK_RM_TIMEOUT:+-t "$KK_RM_TIMEOUT"} "$n" >/dev/null 2>&1 || true
  done
}

# kk_goarch: the GOARCH matching podman's host (the podman machine VM on
# macOS), so a cross-built Linux binary runs in the containers. Falls back to
# amd64 when podman does not answer.
kk_goarch() {
  case "$(podman info --format '{{.Host.Arch}}' 2>/dev/null)" in
    arm64 | aarch64) echo arm64 ;;
    *) echo amd64 ;;
  esac
}

# kk_wait_dns NETWORK NAME [SECONDS]: wait until NAME resolves from a fresh
# container on NETWORK. Returns non-zero on timeout; callers MUST check it and
# fail their step (`kk_wait_dns ... || fail ...`), otherwise the blackout
# resurfaces later as a misleading http-01 "could not fetch" error.
#
# On Ubuntu 24.04's podman 4.9 stack (netavark/aardvark-dns 1.4) the network's
# DNS server stops answering for about 35 s after any container is removed
# from it (measured 2026-10-18: nslookup from a surviving container times out,
# then recovers). A name published meanwhile (the next lego client) is not
# resolvable, so the hub's http-01 fetch hangs in the resolver. Podman 5 does
# not do this.
kk_wait_dns() {
  local net="$1" name="$2" limit="${3:-120}" i
  for ((i = 0; i < limit; i += 2)); do
    if podman run --rm --network "$net" docker.io/library/alpine:3 nslookup "$name" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "ERROR: $name did not resolve on $net within ${limit}s" >&2
  return 1
}

# kk_free_port: print a currently-unbound 127.0.0.1 TCP port. Harnesses used
# fixed host ports (5555 moto, 8098 hub), so one leftover listener from an
# earlier harness (a leaked container or hub) made the next run fail with
# "address already in use" or, worse, talk to the wrong hub (401 on a stale
# one). Explicit overrides (KK_MOTO_PORT, HUB_PORT, ...) still win.
kk_free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
