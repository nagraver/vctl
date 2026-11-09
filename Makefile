VERSION := $(shell cat VERSION)
LDFLAGS := -s -w -X github.com/nagraver/vctl/internal/whale.Version=$(VERSION)

.PHONY: build test integration clean
build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o dist/whale ./cmd/whale

test:
	go test -race ./...
	go vet ./...

integration: build
	WHALE_INTEGRATION=1 go test -race ./...

clean:
	rm -rf dist
