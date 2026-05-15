SHELL := /bin/bash

GO        ?= go
BIN       := bin/collab-server
PKG       := ./...
LDFLAGS   ?= -ldflags="-s -w -X github.com/spirefyio/collab/server/internal/config.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)"

.PHONY: all build test test-race fmt vet lint clean run tidy

all: fmt vet test build

build:
	@mkdir -p bin
	$(GO) build $(LDFLAGS) -o $(BIN) ./cmd/relay

run: build
	./$(BIN)

test:
	$(GO) test -count=1 $(PKG)

test-race:
	$(GO) test -race -count=1 $(PKG)

fmt:
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; skipping"; exit 0; }
	golangci-lint run $(PKG)

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin/
