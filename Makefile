# ckodex-oskal Makefile
# Pure ASCII build and test definitions

.PHONY: all build test lint fmt clean e2e help

SHELL := /bin/bash
BIN_DIR := bin
GO := go

all: fmt lint test build

help:
	@echo "Available targets:"
	@echo "  build        Compile oskal CLI and oskal-controller binaries"
	@echo "  test         Run all tests with race detector"
	@echo "  lint         Run golangci-lint across all packages"
	@echo "  fmt          Format all Go source files"
	@echo "  clean        Remove compiled binaries and test artifacts"
	@echo "  e2e          Run local Kind end-to-end testbed script"

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/oskal ./cmd/oskal
	$(GO) build -trimpath -o $(BIN_DIR)/oskal-controller ./cmd/oskal-controller

test:
	$(GO) test -count=1 -race ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

e2e: build
	./scripts/e2e-kind-testbed.sh
