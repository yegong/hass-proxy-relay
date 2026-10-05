# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/hass-proxy-relay ./cmd/hass-proxy-relay
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -buildvcs=false \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/hass-proxy-relay \
    ./cmd/hass-proxy-relay

FROM scratch

COPY --from=build /out/hass-proxy-relay /hass-proxy-relay

USER 1000:1000
EXPOSE 443/tcp

ENTRYPOINT ["/hass-proxy-relay"]
CMD ["-c", "/data/config.yaml"]
