---
title: "How to Export and Validate OSCAL 1.2.3 Artifacts"
description: "Project runtime assurance states into NIST OSCAL 1.2.3 JSON documents and validate them with ckodex-oscal-cli and ckodex-xoscal."
quadrant: "how-to"
tier: "E5"
invariant: "OSCAL export is derived from the evidence graph (I-06)"
---

## Context

OSKAL does not treat OSCAL as an internal runtime data model. Instead, **Invariant I-06** specifies that NIST OSCAL artifacts are projected outward from the underlying runtime evidence graph. 

The projected models conform strictly to NIST OSCAL 1.2.3 metaschema definitions, verified against `ckodex-oscal-cli` (Rust validator) and `ckodex-xoscal` (governance vector state verifier).

---

## 1. Export Live Assurance State to OSCAL Assessment Results

Export the active cluster assurance state into an OSCAL Assessment Results JSON file:

```bash
oskal export oscal \
  --model assessment-results \
  --subject-namespace production \
  --output /tmp/assessment-results.json
```

The resulting document contains:
- `assessment-results` root element with UUID and metadata timestamp.
- Concrete `findings` linked to specific control identifiers (e.g. `AC-6`).
- Source `observations` containing the exact `integrity_digest` and Merkle evidence root references.

---

## 2. Validate with `ckodex-oscal-cli`

Run the official NIST OSCAL 1.2.3 metaschema validator:

```bash
oscal-cli validate --input /tmp/assessment-results.json
```

Output:

```text
[PASS] Document successfully validated against NIST OSCAL 1.2.3 Metaschema.
Schema valid:      true
Constraints valid: true
Warnings:          0
Errors:            0
```

---

## 3. Verify Multi-Dimensional Governance Vector with `ckodex-xoscal`

Verify that the generated assessment results maintain strict semantic vector invariants:

```bash
xoscal-ctl verify --input /tmp/assessment-results.json
```

Output:

```text
[PASS] S(e,t) Product State Verified:
Vector:            <P=PRESENT, V=POSITIVE, A=0, C=COHERENT, E=VERIFIED, L=NORMAL>
Operational State: NORMAL (No degraded controls or anti-conflicts)
Attestation:       Ed25519 receipt verified against cluster root key.
```
