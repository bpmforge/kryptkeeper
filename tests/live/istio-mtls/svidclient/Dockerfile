FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/svidclient .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/svidclient /svidclient
ENTRYPOINT ["/svidclient"]
