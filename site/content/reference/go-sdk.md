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

The `oskal` package provides a continuous assurance client interface for querying, evaluating, ingesting, projecting, and verifying assurance states. For UTCP v1.0.1 tooling and governed agentic calls, see [`pkg/utcp`](../utcp-mcp/).

---

## Client Constructors & Options

### `NewClient`

Connects to an OSKAL `AssuranceService` gRPC daemon:

```go
func NewClient(ctx context.Context, target string, opts ...ClientOption) (Client, error)
```

Available `ClientOption` helpers:
- `WithInsecure() ClientOption`
- `WithDialOptions(opts ...grpc.DialOption) ClientOption`
- `WithTimeout(d time.Duration) ClientOption`
- `WithRetry(maxAttempts int, baseBackoff time.Duration) ClientOption`

### `NewInProcessClient`

Creates a fully functional, zero-network in-memory client implementing `Client`:

```go
func NewInProcessClient(opts ...InProcessOption) *InProcessClient
```

Available `InProcessOption` helpers:
- `WithEvaluatorAuthority(auth AuthorityRef) InProcessOption`
- `WithReceiptManager(mgr *ReceiptManager) InProcessOption`

---

## The `Client` Interface

```go
type Client interface {
    GetAssuranceState(ctx context.Context, subject SubjectRef) (*StateResponse, error)
    EvaluateSubject(ctx context.Context, subject SubjectRef, controls []ControlRef) (*EvaluationResponse, error)
    ExplainClaim(ctx context.Context, subject SubjectRef, control ControlRef) (*ExplainResponse, error)
    SubmitObservation(ctx context.Context, obs *ProtoObservation) (string, error)
    SubmitReceipt(ctx context.Context, rcpt *ProtoReceipt) (bool, string, error)
    Close() error
}
```

---

## Fluent Builders & Digests

### `NewObservation`

Builds a wire `ProtoObservation` (`*evidencev1.Observation`) ready for `Client.SubmitObservation`:

```go
func NewObservation(id, obsType string, subject SubjectRef) *ObservationBuilder
```

Builder methods:
- `.WithProducer(auth AuthorityRef) *ObservationBuilder`
- `.WithEvidenceRef(uri, digest, mediaType string) *ObservationBuilder`
- `.WithObservedAt(t time.Time) *ObservationBuilder`
- `.Build() (*ProtoObservation, error)`

### `NewEvidenceEnvelope`

Initializes a fluent builder for canonical domain `EvidenceEnvelope` objects:

```go
func NewEvidenceEnvelope(schema, id string, subject SubjectRef, obsType string) *EvidenceEnvelopeBuilder
```

Builder methods:
- `.WithProducer(auth AuthorityRef) *EvidenceEnvelopeBuilder`
- `.WithArtifact(uri, digest, mediaType string) *EvidenceEnvelopeBuilder`
- `.WithEpoch(epoch AssuranceEpoch) *EvidenceEnvelopeBuilder`
- `.WithControlRefs(ctrls ...ControlRef) *EvidenceEnvelopeBuilder`
- `.WithCapturedAt(t time.Time) *EvidenceEnvelopeBuilder`
- `.WithIntegrityDigest(digest string) *EvidenceEnvelopeBuilder`
- `.Build() (EvidenceEnvelope, error)`

### `ComputeEvidenceRoot` & `ComputeStringDigest`

```go
func ComputeEvidenceRoot(digests []string) string
var ComputeStringDigest = assurance.ComputeStringDigest
```

---

## Receipt Management

### `NewReceiptManager`

Instantiates an Ed25519 signer and verifier scoped to an `AuthorityRef`:

```go
func NewReceiptManager(evaluator AuthorityRef) (*ReceiptManager, error)
```

Methods on `*ReceiptManager`:
- `IssueReceipt(subject SubjectRef, control ControlRef, state AssuranceState, epoch AssuranceEpoch, evidences []EvidenceRef, evaluatedAt time.Time) (assurance.ControlReceipt, error)`
- `VerifyReceipt(rcpt assurance.ControlReceipt) bool`
- `PublicKey() string`

### `VerifyIndependentReceipt`

Verifies an Ed25519 `ControlReceipt` offline given an explicit public key hex string:

```go
func VerifyIndependentReceipt(rcpt assurance.ControlReceipt, publicKeyHex string) (bool, error)
```

---

## OSCAL Projector

### `NewProjector`

Initializes a NIST OSCAL v1.2.3 JSON projector:

```go
func NewProjector() *Projector
```

Methods on `*Projector`:
- `ProjectAssessmentPlan(ctx context.Context, subject SubjectRef, contract EvidenceContract, controls []ControlRef) ([]byte, error)`
- `ProjectAssessmentResults(ctx context.Context, subject SubjectRef, evaluations []ClaimEvaluation, findings []Finding) ([]byte, error)`
- `ProjectComponentDefinition(ctx context.Context, componentName string, evaluations []ClaimEvaluation) ([]byte, error)`
- `ProjectSSP(ctx context.Context, systemName string, evaluations []ClaimEvaluation) ([]byte, error)`
- `ProjectPOAM(ctx context.Context, subject SubjectRef, findings []Finding) ([]byte, error)`
