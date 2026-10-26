# ckodex-oskal Makefile
# Pure ASCII build and test definitions

.PHONY: all build test schema-test check-ascii lint fmt clean e2e help

SHELL := /bin/bash
BIN_DIR := bin
GO := go

all: fmt check-ascii lint test build

help:
	@echo "Available targets:"
	@echo "  build        Compile oskal CLI and oskal-controller binaries"
	@echo "  test         Run all tests with race detector"
	@echo "  schema-test  Run strict NIST OSCAL v1.2.3 JSON schema validation suite"
	@echo "  check-ascii  Verify 100% pure ASCII across source and documentation"
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

schema-test:
	$(GO) test -v ./internal/projection/oscal -run TestStrictNISTOscalV123SchemaConformance

check-ascii:
	./scripts/check_ascii.py

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf $(BIN_DIR) dist coverage.out coverage.html site/public site/resources site/.hugo_build.lock .hugo_build.lock evidence .oskal.yaml

e2e: build
	./scripts/e2e-kind-testbed.sh
