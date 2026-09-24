---
title: "Workload & AI Developer Persona Guide"
description: "How Application Developers and AI Engineers fulfill EvidenceContracts, sign container images, and embed pkg/oskal in tests."
quadrant: "personas"
tier: "E5"
invariant: "mode changes deployment, not governance semantics"
---

## Executive Summary

As an application or AI engineer, compliance often feels like an obstacle thrown over the fence by security teams just before release.

OSKAL gives you the tools to **shift compliance into your development loop**:
- Declare what evidence your service provides upfront.
- Test compliance contracts locally in unit tests using the Go SDK (`pkg/oskal`).
- Sign images and AI foundation model weights with Cosign and SHIELD.

---

## 1. Fulfilling an `EvidenceContract`

Your platform team will provide an `EvidenceContract` defining the evidence requirements for your namespace.

For instance, to satisfy `contract-production-services`:
1. Ensure your container image is signed with Cosign and carries an SLSA provenance attestation.
2. In your deployment manifest, declare `securityContext.runAsNonRoot: true` and `securityContext.allowPrivilegeEscalation: false`.
3. If deploying an AI model, provide an AI-BOM manifest matching the model weights file digest.

---

## 2. Testing Governance Locally with `pkg/oskal`

You do not need a live Kubernetes cluster to verify that your service fulfills assurance rules. Use the in-process SDK client in your Go tests:

```go
func TestServiceAssuranceContract(t *testing.T) {
    client := oskal.NewInProcessClient()
    defer client.Close()

    subject := oskal.SubjectRef{
        Kind: "Deployment",
        Name: "my-service",
    }

    // Ingest simulated CI evidence
    env, _ := oskal.NewEvidenceEnvelope("v1alpha1", "env-test", subject, "kubernetes.admission")
    env.Observation.Attributes = map[string]string{
        "admission.k8s.io/allowed": "true",
    }
    _ = client.IngestEvidence(context.Background(), env)

    state, err := client.GetAssuranceState(context.Background(), subject)
    if err != nil || state.State != oskal.AssuranceStateVerified {
        t.Fatalf("expected VERIFIED, got %v", state.State)
    }
}
```

---

## 3. Signing AI Foundation Models (SHIELD)

When deploying large language models or agentic pipelines:
1. Export model weights to Safetensors format.
2. Generate an AI-BOM documenting training datasets, licenses, and architecture.
3. Sign the Safetensors digest with Cosign:

```bash
cosign sign-blob --key cosign.key --bundle model-weights.bundle mistral-7b.safetensors
```

The OSKAL SHIELD adapter automatically verifies the signature upon deployment, emitting `ai.model.weights.attestation` evidence without manual auditor review.
