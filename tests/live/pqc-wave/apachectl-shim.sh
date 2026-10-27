#!/bin/sh
# Alpine ships no apachectl; the installer runs `apachectl configtest` before reload. Map to httpd directly.
[ "$1" = configtest ] && exec httpd -t
exec httpd "$@"
