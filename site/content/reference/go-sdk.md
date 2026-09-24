---
title: "Go SDK Reference (pkg/oskal)"
description: "API reference for the public Go SDK provided by github.com/ckodex-labs/ckodex-oskal/pkg/oskal."
quadrant: "reference"
tier: "E5"
invariant: "Invisible excellence: pure domain abstractions with zero transport leakage"
---

## Package Overview

```go
import "github.com/ckodex-labs/ckodex-oskal/pkg/oskal"
```

The `oskal` package provides a high-assurance client interface for querying, ingesting, and verifying continuous assurance states.

---

## Client Constructors

### `NewClient`

Creates a gRPC-backed client connected to an OSKAL daemon or controller:

```go
func NewClient(ctx context.Context, target string, opts ...grpc.DialOption) (Client, error)
```

### `NewInProcessClient`

Creates a fully functional, zero-network in-memory engine:

```go
func NewInProcessClient(opts ...InProcessOption) Client
```

---

## The `Client` Interface

```go
type Client interface {
    GetAssuranceState(ctx context.Context, subject SubjectRef) (*AssuranceState, error)
    ExplainClaim(ctx context.Context, subject SubjectRef, control ControlRef) (*ExplainGraph, error)
    IngestEvidence(ctx context.Context, envelope *EvidenceEnvelope) error
    VerifyReceipt(ctx context.Context, receipt *ControlReceipt) (*ReceiptVerification, error)
    Close() error
}
```

---

## Fluent Builders

### `NewEvidenceEnvelope`

Constructs an `EvidenceEnvelope` with automatic SHA-256 integrity digest computation:

```go
func NewEvidenceEnvelope(
    schemaVersion string,
    id string,
    subject SubjectRef,
    observationType string,
) (*EvidenceEnvelope, error)
```

### `ComputeEvidenceRoot`

Calculates the canonical Merkle root over an arbitrary set of leaf digest strings:

```go
func ComputeEvidenceRoot(leafDigests []string) string
```

---

## Receipt Management

### `NewReceiptManager`

Instantiates an Ed25519 signer and verifier for non-repudiable receipts:

```go
func NewReceiptManager(signerSPIFFEID string) (*ReceiptManager, error)
```

Methods on `*ReceiptManager`:

- `SignReceipt(...) (*ControlReceipt, error)`
- `VerifyReceipt(receipt *ControlReceipt) error`

### `VerifyIndependentReceipt`

Verifies an Ed25519 `ControlReceipt` offline given an arbitrary public key hex string:

```go
func VerifyIndependentReceipt(receipt *ControlReceipt, pubKeyHex string) error
```

---

## OSCAL Projector

### `ProjectAssessmentResults`

Converts a collection of verified `ClaimEvaluation` records into NIST OSCAL 1.2.3 Assessment Results JSON:

```go
func ProjectAssessmentResults(
    evaluations []*ClaimEvaluation,
    title string,
) ([]byte, error)
```
