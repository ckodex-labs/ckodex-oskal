---
title: "In-Process Assurance with the Go SDK"
description: "Embed the OSKAL continuous assurance engine directly into Go binaries, admission webhooks, or test runners without network dependencies."
quadrant: "tutorials"
tier: "E5"
invariant: "mode changes deployment, not governance semantics"
---

## Overview

In many environments, requiring a live network round-trip to a gRPC daemon is undesirable. Examples include:
- Kubernetes Admission Webhooks (where network latency budget is < 20ms).
- Local CI/CD pipeline test harnesses.
- Disconnected, high-security microservices.

The OSKAL Go SDK provides `oskal.NewInProcessClient()`, which instantiates a fully functional continuous assurance engine entirely in memory.

---

## Step 1: Add the OSKAL Dependency

Add `github.com/ckodex-labs/ckodex-oskal` to your `go.mod`:

```bash
go get github.com/ckodex-labs/ckodex-oskal@main
```

---

## Step 2: Implement the In-Process Continuous Assurance Check

Create a file named `main.go`:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/pkg/oskal"
)

func main() {
	ctx := context.Background()

	// 1. Initialize an in-process, zero-network assurance client
	client := oskal.NewInProcessClient()
	defer client.Close()

	// 2. Define the workload subject under test
	subject := oskal.SubjectRef{
		Kind:       "Deployment",
		Namespace:  "default",
		Name:       "auth-gateway",
		Generation: 1,
	}

	// 3. Build an authentic evidence envelope
	envelope, err := oskal.NewEvidenceEnvelope(
		"v1alpha1",
		"env-test-001",
		subject,
		"kubernetes.admission",
	)
	if err != nil {
		log.Fatalf("failed to construct envelope: %v", err)
	}

	envelope.ProducerSPIFFEID = "spiffe://ckodex.internal/ns/system/sa/test-runner"
	envelope.Observation.Attributes = map[string]string{
		"admission.k8s.io/allowed": "true",
		"security.k8s.io/seccomp":  "RuntimeDefault",
	}

	// 4. Ingest the observation envelope into the in-process store
	if err := client.IngestEvidence(ctx, envelope); err != nil {
		log.Fatalf("evidence ingestion failed: %v", err)
	}

	// 5. Query the vector state
	state, err := client.GetAssuranceState(ctx, subject)
	if err != nil {
		log.Fatalf("failed to query assurance state: %v", err)
	}

	fmt.Printf("[ASSURANCE STATE] %s\n", state.State)
	fmt.Printf("Evidence Envelopes: %d\n", len(state.EvidenceEnvelopes))
	fmt.Printf("Merkle Evidence Root: %s\n", state.EvidenceRoot)

	// 6. Generate an Ed25519-signed ControlReceipt
	receiptMgr, err := oskal.NewReceiptManager("spiffe://ckodex.internal/ns/system/sa/test-runner")
	if err != nil {
		log.Fatalf("failed to create receipt manager: %v", err)
	}

	receipt, err := receiptMgr.SignReceipt(
		"rcpt-local-001",
		oskal.ControlRef{Framework: "NIST-SP-800-53", ControlID: "AC-6"},
		subject,
		oskal.AssuranceStateVerified,
		state.EvidenceRoot,
		10*time.Minute,
	)
	if err != nil {
		log.Fatalf("failed to sign receipt: %v", err)
	}

	// 7. Verify the receipt independently offline
	if err := receiptMgr.VerifyReceipt(receipt); err != nil {
		log.Fatalf("receipt verification failed: %v", err)
	}

	fmt.Printf("[RECEIPT VERIFIED] Non-repudiable receipt %s signed with Ed25519.\n", receipt.ReceiptID)
}
```

---

## Step 3: Run and Observe

Execute your standalone Go program:

```bash
go run main.go
```

Output:

```text
[ASSURANCE STATE] ASSURANCE_STATE_VERIFIED
Evidence Envelopes: 1
Merkle Evidence Root: sha256:d82e01a89c091...
[RECEIPT VERIFIED] Non-repudiable receipt rcpt-local-001 signed with Ed25519.
```

The in-process client guarantees identical state transition semantics and cryptographic guarantees as the clustered controller, proving the principle: *mode changes deployment, not governance semantics*.
