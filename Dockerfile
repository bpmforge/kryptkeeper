# syntax=docker/dockerfile:1.7

# Dual-mode release Dockerfile:
# - real mode (default): compile app from Go source
# - placeholder mode: emergency fallback when app sources are unavailable
#
# G-29: this image also always builds and ships /kryptkeeper-mcp (from
# ./cmd/kryptkeeper-mcp) alongside the primary APP_BUILD_PATH binary at
# /kryptkeeper -- ENTRYPOINT stays the primary binary; kryptkeeper-mcp is
# invoked via `docker run --entrypoint /kryptkeeper-mcp ...`. It supports
# both the stdio and HTTP/StreamableHTTP transports (KRYPTKEEPER_MCP_TRANSPORT);
# stdio (the default) has nothing for this image's HEALTHCHECK to probe, so
# run it with KRYPTKEEPER_MCP_TRANSPORT=http if you need the healthcheck.
#
# Build commands:
# - Real mode (default):
#   docker build --build-arg BUILD_MODE=real --build-arg APP_BUILD_PATH=./cmd/kryptkeeper -t kryptkeeper:real .
# - Placeholder fallback mode:
#   docker build --build-arg BUILD_MODE=placeholder -t kryptkeeper:placeholder .

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64
ARG BUILD_MODE=real
ARG APP_BUILD_PATH=./cmd/kryptkeeper
ARG HEALTHCHECK_URL=http://127.0.0.1:8080/healthz
# W20-02: stamps /meta (cmd/kryptkeeper/main.go's version/commit/date vars) --
# .goreleaser.yaml passes these as build-args so the image's binary reports
# the same version a tarball/deb/rpm from the same tag would.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /src

# Keep context available for real-mode builds; placeholder mode ignores it.
COPY . /src

RUN --mount=type=cache,target=/root/.cache/go-build <<'EOF'
set -eu
mkdir -p /out /tmp/generated

if [ "${BUILD_MODE}" = "real" ]; then
  if [ ! -f /src/go.mod ]; then
    echo "BUILD_MODE=real requires go.mod at repository root; use --build-arg BUILD_MODE=placeholder for emergency fallback" >&2
    exit 1
  fi

  # Require explicit/known package path for deterministic builds.
  if [ ! -e "/src/${APP_BUILD_PATH#./}" ]; then
    echo "BUILD_MODE=real requires app entrypoint '${APP_BUILD_PATH}' in build context; use --build-arg BUILD_MODE=placeholder for emergency fallback" >&2
    exit 1
  fi

  # W19-23: the healthcheck binary now lives at cmd/healthcheck/ as a real,
  # tested package (HEALTHCHECK_CA_FILE support, needed once the hub's
  # default listener serves a self-issued TLS certificate) instead of an
  # inline plain-HTTP-only probe.
  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags='-s -w' -o /out/healthcheck ./cmd/healthcheck

  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/kryptkeeper "${APP_BUILD_PATH}"

  # G-29: always ship the MCP server binary too, independent of
  # APP_BUILD_PATH -- this is a fixed source path, not the configurable
  # primary-binary one above.
  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags='-s -w' -o /out/kryptkeeper-mcp ./cmd/kryptkeeper-mcp
elif [ "${BUILD_MODE}" = "placeholder" ]; then
  # Placeholder mode has no module tree beyond this single file, so it gets
  # the same tiny inline HTTP-only probe the real binary replaced -- this
  # matches the placeholder app below, which only ever serves cleartext.
  cat > /tmp/generated/healthcheck.go <<'EOGO'
package main

import (
    "fmt"
    "net/http"
    "os"
    "time"
)

func main() {
    url := os.Getenv("HEALTHCHECK_URL")
    if url == "" {
        url = "http://127.0.0.1:8080/healthz"
    }

    client := &http.Client{Timeout: 2 * time.Second}
    resp, err := client.Get(url)
    if err != nil {
        fmt.Fprintf(os.Stderr, "healthcheck request failed: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 400 {
        fmt.Fprintf(os.Stderr, "healthcheck status not healthy: %d\n", resp.StatusCode)
        os.Exit(1)
    }
}
EOGO

  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags='-s -w' -o /out/healthcheck /tmp/generated/healthcheck.go

  # Placeholder path for release safety before app sources are wired.
  cat > /tmp/generated/placeholder.go <<'EOGO'
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
        _, _ = fmt.Fprintln(w, "kryptkeeper placeholder image: app binary not yet wired")
    })
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusOK)
        _, _ = fmt.Fprintln(w, "ok")
    })

    addr := ":8080"
    log.Printf("starting placeholder service on %s", addr)
    if err := http.ListenAndServe(addr, mux); err != nil {
        log.Fatalf("server exited: %v", err)
    }
}
EOGO

  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags='-s -w' -o /out/kryptkeeper /tmp/generated/placeholder.go

  # No real app sources are available in this mode (that is the whole
  # premise of the fallback), so kryptkeeper-mcp gets the same placeholder
  # binary rather than a second compile of it.
  cp /out/kryptkeeper /out/kryptkeeper-mcp
else
  echo "Invalid BUILD_MODE='${BUILD_MODE}'. Supported values: real, placeholder" >&2
  exit 1
fi
EOF

FROM gcr.io/distroless/static-debian12:nonroot

ARG HEALTHCHECK_URL=http://127.0.0.1:8080/healthz

LABEL org.opencontainers.image.title="kryptkeeper"
LABEL org.opencontainers.image.description="Release baseline image for Kryptkeeper (placeholder + real build modes)"
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY:-unknown}"

COPY --from=builder /out/kryptkeeper /kryptkeeper
COPY --from=builder /out/kryptkeeper-mcp /kryptkeeper-mcp
COPY --from=builder /out/healthcheck /healthcheck

ENV HEALTHCHECK_URL=${HEALTHCHECK_URL}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/healthcheck"]

USER nonroot:nonroot
ENTRYPOINT ["/kryptkeeper"]
