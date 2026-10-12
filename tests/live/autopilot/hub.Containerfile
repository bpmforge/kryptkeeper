# Autopilot fixture: the hub itself, in a container on the same podman
# network as the servers it manages. Running it there (not on the host) makes
# the hub's view of the world match production: it reaches nginx hosts and the
# agent by DNS name on a private network, with no loopback or privileged-port
# tricks. The binary is built for this arch by run.sh and copied in.
FROM docker.io/library/ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /data
COPY kryptkeeper /usr/local/bin/kryptkeeper
ENTRYPOINT ["/usr/local/bin/kryptkeeper"]
