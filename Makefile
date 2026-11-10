# ckodex-oskal Makefile
# Pure ASCII build and test definitions

.PHONY: all build test schema-test check-ascii lint fmt clean e2e help verify doctor cockpit validate-sample docs-build docs-serve

SHELL := /bin/bash
BIN_DIR := bin
GO := go

all: fmt check-ascii lint test build

help:
	@echo "Available targets:"
	@echo "  build            Compile oskal CLI and oskal-controller binaries"
	@echo "  test             Run all tests with race detector"
	@echo "  schema-test      Run strict NIST OSCAL v1.2.3 JSON schema validation suite"
	@echo "  check-ascii      Verify 100% pure ASCII across source and documentation"
	@echo "  lint             Run golangci-lint across all packages"
	@echo "  fmt              Format all Go source files"
	@echo "  verify           Execute complete verification gate (fmt, ascii, lint, test, build)"
	@echo "  doctor           Run deep system preflight diagnostics via CLI"
	@echo "  cockpit          Run live pure ASCII assurance cockpit in one-shot mode"
	@echo "  validate-sample  Validate included NIST OSCAL component definition example"
	@echo "  docs-build       Build the Hugo documentation site"
	@echo "  docs-serve       Serve the Hugo documentation site locally"
	@echo "  clean            Remove compiled binaries and test artifacts"
	@echo "  e2e              Run local Kind end-to-end testbed script"

VERSION ?= v1.0.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/oskal ./cmd/oskal
	$(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/oskal-controller ./cmd/oskal-controller

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

verify: fmt check-ascii lint schema-test test build

doctor: build
	./$(BIN_DIR)/oskal doctor

cockpit: build
	./$(BIN_DIR)/oskal cockpit --once

validate-sample: build
	./$(BIN_DIR)/oskal validate examples/oscal-component-definition.json

docs-build:
	cd site && hugo --minify

docs-serve:
	cd site && hugo server -D

