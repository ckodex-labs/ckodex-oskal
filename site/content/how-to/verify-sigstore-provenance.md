---
title: "How to Validate Sigstore Provenance and AI-BOMs"
description: "Verify SLSA Level 3 build provenance, Cosign signatures, and AI foundation model weights with the Sigstore and SHIELD adapters."
quadrant: "how-to"
tier: "E5"
invariant: "Evidence is contextual: subject + epoch + policy + time (I-03)"
---

## Context

Supply-chain assurance requires non-repudiable proof that deployed container images and AI model weights originate from trusted pipelines. OSKAL integrates two dedicated supply chain adapters:
1. **Sigstore Adapter**: Verifies container image signatures and in-toto SLSA Level 3 attestations.
2. **SHIELD Adapter**: Verifies AI model weights, dataset provenance hashes, and AI-BOM (Artificial Intelligence Bill of Materials) declarations.

---

## 1. Sign Workload Artifacts with Cosign

In your CI/CD pipeline, sign the container image and attach an in-toto SLSA provenance predicate:

```bash
cosign sign --key k8s://production/cosign-key registry.internal/banking/payment-service:v1.4.2
cosign attest --key k8s://production/cosign-key --type slsaprovenance --predicate provenance.json registry.internal/banking/payment-service:v1.4.2
```

---

## 2. Declare Supply-Chain Requirements in EvidenceContract

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: EvidenceContract
metadata:
  name: contract-supply-chain-strict
  namespace: production
spec:
  requiredEvidence:
    - observationType: "supply-chain.signature"
      maxAge: 720h # 30 days
      allowedProducers:
        - "spiffe://ckodex.internal/ns/system/sa/oskal-sigstore-adapter"
    - observationType: "ai.model.weights.attestation"
      maxAge: 168h # 7 days
      allowedProducers:
        - "spiffe://ckodex.internal/ns/system/sa/oskal-shield-adapter"
```

---

## 3. Verify AI Model Weights & AI-BOMs (SHIELD)

When deploying agentic AI models or inference services, the OSKAL SHIELD adapter verifies:
- Content-addressed SHA-256 digest of Safetensors / GGUF model files.
- Hugging Face / OCI artifact signing metadata.
- Permitted foundation model licenses in the AI-BOM.

Check the resulting verification state:

```bash
oskal assurance explain --subject-name fraud-detection-agent --control SI-7
```

```text
================================================================================
SECTION 51 EXPLAIN GRAPH: SI-7 (Software, Firmware, and Information Integrity)
SUBJECT: Deployment/fraud-detection-agent (ns: production, gen: 1)
EVALUATION: [PASS]
--------------------------------------------------------------------------------
ATOMIC REQUIREMENTS:
  [PASS] supply-chain.signature
         Image: registry.internal/ai/agent-runtime@sha256:7198...
         Attestation: SLSA Level 3 Provenance Verified
  [PASS] ai.model.weights.attestation
         Model: mistral-7b-instruct-v0.3.safetensors
         Digest: sha256:a18c9910482b...
         AI-BOM: CycloneDX 1.5 AI-BOM Verified
================================================================================
```
