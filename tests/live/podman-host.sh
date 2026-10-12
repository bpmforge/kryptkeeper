# Sourced by tests/live/*/run.sh. Containers reach the hub on the host as
# host.containers.internal, and the hub's TLS certificate names it.
#
# On macOS, podman 5.x and later (pasta inside the podman machine VM)
# resolve that name to 169.254.1.2, the VM's own host side, which does not
# forward to the Mac: every connection is refused, whether the hub binds
# loopback or all interfaces (measured 2026-10-08, podman 6.1.3 client,
# 5.8.8 machine, applehv). gvproxy's gateway, 192.168.127.254, does reach
# the Mac, loopback included. Pointing the same name there keeps TLS
# verification against the same SAN. Linux podman resolves it correctly.
#
# KK_PODMAN_HOST_GATEWAY overrides the address; set it to "none" to leave
# podman's own mapping alone.
KK_PODMAN_HOST_ARGS=""
kk_gw="${KK_PODMAN_HOST_GATEWAY:-}"
if [ -z "$kk_gw" ] && [ "$(uname -s)" = Darwin ]; then
  kk_gw=192.168.127.254
fi
if [ -n "$kk_gw" ] && [ "$kk_gw" != none ]; then
  KK_PODMAN_HOST_ARGS="--add-host=host.containers.internal:$kk_gw"
fi
unset kk_gw
