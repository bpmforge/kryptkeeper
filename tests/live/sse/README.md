# W30-19: SSE through the shipped nginx

```
bash tests/live/sse/run.sh            # 600 s soak (acceptance 3)
KK_SSE_SECONDS=90 bash tests/live/sse/run.sh   # smoke only; the 10-data-frame bar is expected to fail
```

Runs the repo's `docker-compose.yml` with `podman compose` in a throwaway
project. A generated override bind-mounts this checkout's `nginx.conf` over
the dashboard image's baked-in `default.conf` (so the file under test is the
one on disk) and publishes the dashboard on a free loopback port.

Images: defaults to the existing `kryptkeeper:local` and
`kryptkeeper-dashboard:local` (`--no-build`, offline friendly); the hub image
must contain `GET /api/v1/events` (the script fails fast on a 404).
`KK_SSE_BUILD=1` rebuilds both (needs registry access). Token and keystore
passphrase are generated per run and never printed.

## Assertions

Stream opened with `curl -sN` via nginx for the full duration, two
`POST /api/v1/discovery/scans` per minute (each queues one event frame):
first `: heartbeat` within 20 s; largest gap between received lines <= 20 s
(hub heartbeat is 15 s); >= 10 `data:` frames; curl still connected at
t=600 s; `Content-Type: text/event-stream`; `X-Accel-Buffering` absent or
`no`.

Hub lifecycle bounds that matter for the soak: idle timeout 300 s since the
last real event (scans every 60 s keep it open), max lifetime 1800 s.

## Proxy fixes shipped with this ticket

- `nginx.conf`: exact-match `location = /api/v1/events` before `/api/`, with
  `proxy_buffering off`, `proxy_cache off`, HTTP/1.1, 3600 s read/send
  timeouts. Verified with `nginx -t` in `docker.io/library/nginx:alpine`.
- `charts/kryptkeeper/templates/ingress.yaml`: default ingress-nginx
  annotations (`proxy-buffering: "off"`, `proxy-read-timeout: "3600"`,
  `proxy-send-timeout: "3600"`) merged under user annotations.

Note: the hub already sends `X-Accel-Buffering: no`, which nginx honours and
strips, so this soak alone does not prove the `proxy_buffering off` line is
what keeps the stream flowing; the 3600 s timeouts are what it would exercise
past nginx's 60 s default (the 15 s heartbeat resets `proxy_read_timeout`
either way).
