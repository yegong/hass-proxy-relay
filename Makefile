.PHONY: build test test-race vet smoke

build:
	go build -trimpath -o bin/hass-proxy-relay ./cmd/hass-proxy-relay

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

smoke:
	@test -n "$(CONFIG)" || (echo "usage: make smoke CONFIG=/path/to/config.yaml" >&2; exit 2)
	go run ./cmd/relay-smoke -c "$(CONFIG)"
