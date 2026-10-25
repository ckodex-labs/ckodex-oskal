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

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/pkg/oskal"
)

func main() {
	ctx := context.Background()

	// 1. Configure the evaluator authority and receipt manager
	evaluatorAuth := oskal.AuthorityRef{
		Scheme:  "spiffe",
		Subject: "ckodex.internal/ns/system/sa/test-runner",
	}
	receiptMgr, err := oskal.NewReceiptManager(evaluatorAuth)
	if err != nil {
		log.Fatalf("failed to create receipt manager: %v", err)
	}

	// 2. Initialize an in-process, zero-network assurance client
	client := oskal.NewInProcessClient(oskal.WithReceiptManager(receiptMgr))
	defer func() { _ = client.Close() }()

	// 3. Define the workload subject under test
	subject := oskal.SubjectRef{
		Scheme: "k8s",
		ID:     "production/Deployment/auth-gateway",
	}

	// 4. Ingest an authentic observation
	obs, err := oskal.NewObservation("obs-001", "kubernetes.admission", subject).
		WithProducer(evaluatorAuth).
		WithEvidenceRef("k8s://admission/review", oskal.ComputeStringDigest("admission-payload-001"), "application/json").
		Build()
	if err != nil {
		log.Fatalf("failed to build observation: %v", err)
	}

	if _, err := client.SubmitObservation(ctx, obs); err != nil {
		log.Fatalf("evidence ingestion failed: %v", err)
	}

	// 5. Query the vector state
	state, err := client.GetAssuranceState(ctx, subject)
	if err != nil {
		log.Fatalf("failed to query assurance state: %v", err)
	}

	fmt.Printf("[ASSURANCE STATE] %s\n", state.State)
	fmt.Printf("Evidence Root:   %s\n", state.EvidenceRoot)

	// 6. Generate an Ed25519-signed ControlReceipt
	epoch := oskal.AssuranceEpoch{
		SubjectDigest:        oskal.ComputeStringDigest(subject.URI()),
		ImplementationDigest: oskal.ComputeStringDigest("kubernetes:workload-specification"),
		PolicyDigest:         oskal.ComputeStringDigest("policy:nist-ac6"),
		AuthorityDigest:      oskal.ComputeStringDigest("spiffe://assurance.ckodex.io/server"),
		EnvironmentDigest:    oskal.ComputeStringDigest("cluster:local"),
	}

	ctrl := oskal.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}
	receipt, err := receiptMgr.IssueReceipt(
		subject,
		ctrl,
		oskal.StateAssured,
		epoch,
		[]assurance.EvidenceRef{
			{URI: "k8s://admission/review", Digest: oskal.ComputeStringDigest("admission-payload-001"), MediaType: "application/json"},
		},
		time.Now().UTC(),
	)
	if err != nil {
		log.Fatalf("failed to issue receipt: %v", err)
	}

	// 7. Verify the receipt independently offline
	if !receiptMgr.VerifyReceipt(receipt) {
		log.Fatalf("receipt verification failed")
	}

	fmt.Printf("[RECEIPT VERIFIED] Non-repudiable receipt for %s signed with Ed25519.\n", receipt.Control.Canonical())
	fmt.Printf("Signer Public Key: %s\n", receiptMgr.PublicKey())
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
[ASSURANCE STATE] ASSURED
Evidence Root:   sha256:d82e01a89c091...
[RECEIPT VERIFIED] Non-repudiable receipt for nist-sp-800-53:AC-6 signed with Ed25519.
Signer Public Key: 3a7f80...
```

The in-process client guarantees identical state transition semantics and cryptographic guarantees as the clustered controller, proving the principle: *mode changes deployment, not governance semantics*.
