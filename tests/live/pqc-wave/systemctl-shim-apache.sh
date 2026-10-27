#!/bin/sh
# Stand-in for `systemctl reload apache2` inside a container (see Containerfile.apache): graceful restart.
[ "$1" = reload ] && [ "$2" = apache2 ] || { echo "systemctl shim: unsupported: $*" >&2; exit 1; }
exec httpd -k graceful
