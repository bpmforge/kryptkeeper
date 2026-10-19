# Throwaway authoritative DNS for the local RFC2136 leg: BIND 9 from the
# Ubuntu archive, native on arm64 and amd64 (the ISC image is amd64 only and
# segfaults under qemu on Apple Silicon). Zone and TSIG key are mounted in by
# lib.sh; nothing here is a secret.
FROM docker.io/library/ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends bind9 bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/named && chown bind:bind /run/named
