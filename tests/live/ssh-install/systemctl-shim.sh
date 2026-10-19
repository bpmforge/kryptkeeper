#!/bin/sh
# W27-08: `systemctl` stand-in for a container without systemd. Maps ONLY the
# verbs the installers use; any other unit or verb exits non-zero so a wrong
# unit name fails visibly instead of silently "succeeding".
verb="$1"; unit="$2"
case "$verb $unit" in
  "reload haproxy")
    exec haproxy -f /etc/haproxy/haproxy.cfg -D -p /run/haproxy.pid -sf "$(cat /run/haproxy.pid)"
    ;;
  "restart tomcat")
    # `stop 10 -force` waits (via CATALINA_PID) for the JVM to exit so the
    # new JVM can bind :443.
    /opt/tomcat/bin/catalina.sh stop 10 -force >/dev/null 2>&1
    setsid /opt/tomcat/bin/startup.sh >/dev/null 2>&1 </dev/null
    exit 0
    ;;
  *)
    echo "systemctl-shim: unsupported: $*" >&2
    exit 5
    ;;
esac
