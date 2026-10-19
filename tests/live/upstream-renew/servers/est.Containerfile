# Independent EST server for the W27-10 live UAT: Cisco libest `estserver`
# (C, RFC 7030) built from the pinned release tag, so nothing of Kryptkeeper's
# own internal/est is involved. Ubuntu 20.04 because libest 3.2.0 targets
# OpenSSL 1.1.1. -fsigned-char: estserver stores getopt's return in a plain
# char, which is unsigned on arm64 and turns the end-of-options -1 into 255
# (usage printed, server never starts). Base image pinned by index digest.
FROM docker.io/library/ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214 AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential autoconf automake libtool libssl-dev git ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch r3.2.0 https://github.com/cisco/libest /src
WORKDIR /src
RUN git rev-parse HEAD > /libest-commit && ./configure --prefix=/opt/libest CFLAGS='-O2 -fsigned-char' >/dev/null && make -j4 >/dev/null 2>&1 && make install >/dev/null 2>&1 \
    && ls /opt/libest/bin
COPY est-entry.sh /usr/local/bin/est-entry.sh
RUN mkdir -p /out
ENTRYPOINT ["/usr/local/bin/est-entry.sh"]
