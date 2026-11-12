---
title: "How to Export and Validate OSCAL 1.2.3 Artifacts"
description: "Project runtime assurance states into NIST OSCAL 1.2.3 JSON documents and validate them with oskal validate."
quadrant: "how-to"
tier: "E5"
invariant: "OSCAL export is derived from the evidence graph (I-06)"
---

## Context

OSKAL does not treat OSCAL as an internal runtime data model. Instead, **Invariant I-06** specifies that NIST OSCAL artifacts are projected outward from the underlying runtime evidence graph.

Every projected document conforms strictly to embedded NIST OSCAL v1.2.3 schemas and is offline-validatable with `oskal validate`.

---

## 1. Export Live Assurance State to OSCAL Assessment Results

Export the active assurance state for a workload into an OSCAL Assessment Results JSON file:

```bash
oskal export assessment-results \
  --subject k8s://ckodex-assurance-test/Deployment/payments-api \
  --evidence-dir ./evidence > /tmp/assessment-results.json
```

OSKAL supports projecting all five operational NIST OSCAL v1.2.3 models:
- `oskal export assessment-results --subject <uri>`
- `oskal export component-definition --component <name>`
- `oskal export assessment-plan --subject <uri>`
- `oskal export ssp --subject <uri>`
- `oskal export poam --subject <uri>`

The resulting Assessment Results document contains:
- `assessment-results` root element with UUID and metadata timestamp (`oscal-version: "1.2.3"`).
- Concrete `findings` linked to specific control identifiers (e.g. `AC-6`).
- Source `observations` carrying integrity digests and Merkle evidence root references.

---

## 2. Validate with Embedded NIST OSCAL v1.2.3 Schemas (`oskal validate`)

Run the embedded sub-millisecond NIST OSCAL v1.2.3 validator (100% air-gap compatible):

```bash
oskal validate /tmp/assessment-results.json
```

Or override schema auto-detection explicitly with `--schema`:

```bash
oskal validate /tmp/assessment-results.json --schema assessment-results --output json
```

Output:

```text
[PASS] Document valid against NIST OSCAL v1.2.3 schema (assessment-results).
```
