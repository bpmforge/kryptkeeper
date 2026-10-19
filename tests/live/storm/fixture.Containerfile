# W27-34 storm fixture: the stub CA / fake Kubernetes API / verify listeners
# binary, cross-compiled by run.sh and copied in.
FROM docker.io/library/ubuntu:24.04
RUN mkdir -p /out
COPY fixture /usr/local/bin/fixture
ENTRYPOINT ["/usr/local/bin/fixture"]
