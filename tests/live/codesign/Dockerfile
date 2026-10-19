# Toolbox for tests/live/codesign/run.sh: SoftHSM2, OpenSC's pkcs11-tool,
# osslsigncode with the libp11 PKCS#11 engine, and a Go toolchain with cgo so the
# hub can be built with -tags pkcs11 inside the container. The harness mounts the
# repository read-only at /src; nothing from this image is shipped.
FROM docker.io/library/golang:1.26-bookworm AS go

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl openssl python3 gcc libc6-dev libltdl-dev \
      softhsm2 opensc osslsigncode libengine-pkcs11-openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH \
    GOFLAGS=-buildvcs=false \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1
WORKDIR /src
