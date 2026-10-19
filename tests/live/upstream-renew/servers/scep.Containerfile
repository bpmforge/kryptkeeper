# Independent SCEP server for the W27-10 live UAT: micromdm/scep scepserver
# (Go, RFC 8894), built from the pinned module tag so nothing of Kryptkeeper's
# own internal/scep is involved. Base images are pinned by index digest.
FROM docker.io/library/golang:1.24.13@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804 AS build
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN go install github.com/micromdm/scep/v2/cmd/scepserver@v2.3.0

FROM docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY --from=build /go/bin/scepserver /usr/local/bin/scepserver
RUN mkdir -p /depot
# The CA key is generated when the container starts, inside the container.
ENTRYPOINT ["/bin/sh", "-c", "cd /depot && scepserver ca -init -depot /depot -years 5 -keySize 2048 -key-password '' -common_name 'UAT SCEP Independent CA' >/dev/null 2>&1; exec scepserver -depot /depot -port 2016 -allowrenew 0"]
