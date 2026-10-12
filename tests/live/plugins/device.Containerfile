# Mock appliance for the plugins live harness: the mockdevice binary (built
# for this arch by run.sh) on the same podman network as the hub.
FROM docker.io/library/ubuntu:24.04
COPY mockdevice /usr/local/bin/mockdevice
ENTRYPOINT ["/usr/local/bin/mockdevice"]
