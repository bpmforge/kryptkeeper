# Autopilot fixture: the tests/live/agent image with its placeholder leaf
# re-issued for the name "agenthost" instead of "localhost". The hub's ACME
# server refuses localhost names (RFC 6761) and refuses to http-01-fetch from
# loopback, so the agent-mode renewal needs a real, non-loopback DNS name; on
# the podman network the container name is that name. Self-signed, 2 days, so
# the agent flags it auto-renewable and the hub tasks it immediately.
ARG BASE
FROM ${BASE}
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
      -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt \
      -days 2 -nodes -subj "/CN=agenthost" -addext "subjectAltName=DNS:agenthost"
