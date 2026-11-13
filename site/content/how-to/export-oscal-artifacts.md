---
title: "How to Export and Validate OSCAL 1.2.3 Artifacts"
description: "Project runtime assurance states into NIST OSCAL 1.2.3 JSON documents and validate them with oskal validate."
quadrant: "how-to"
tier: "E5"
invariant: "OSCAL export is derived from the evidence graph (I-06)"
---

## Context

OSKAL does not treat OSCAL as an internal runtime data model. Instead, **Invariant I-06** specifies that NIST OSCAL artifacts are projected outward from the underlying runtime evidence graph.

Successful projections are structurally validated against embedded NIST OSCAL
v1.2.3 JSON schemas. This does not prove semantic completeness, authentic evidence,
resolved imports, Metaschema constraint conformance, or compliance. Projection
requires caller-supplied context for actual document references and system facts;
missing mandatory inputs return an actionable error instead of invented defaults.
See `docs/oscal-projection-inputs.md` for the SDK context contract.

---

## 1. Export Live Assurance State to OSCAL Assessment Results

After configuring actual projection context, export the active assurance state for a workload into an OSCAL Assessment Results JSON file:

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
- Supplied `findings` linked to explicitly mapped objective or statement identifiers and source evaluation evidence, when those inputs exist.
- Source `observations` carrying integrity digests and Merkle evidence root references.

---

## 2. Validate with Embedded NIST OSCAL v1.2.3 Schemas (`oskal validate`)

Run the embedded NIST OSCAL v1.2.3 JSON schema validator (no network required):

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

Missing evaluations cannot produce an assessment result or SSP control list. Empty
POA&M findings return an error because the pinned schema requires at least one
item; an empty finding set does not establish that controls are satisfied.
