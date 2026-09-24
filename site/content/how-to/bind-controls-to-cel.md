---
title: "How to Bind Canonical Controls to ValidatingAdmissionPolicy"
description: "Declare Kubernetes-native ValidatingAdmissionPolicy CEL expressions and map them into OSKAL ControlBindings."
quadrant: "how-to"
tier: "E5"
invariant: "Enforcement and assessment are separate operations (I-08)"
---

## Context

Kubernetes 1.30+ provides in-tree `ValidatingAdmissionPolicy` evaluated via the Common Expression Language (CEL). OSKAL does not wrap or replace CEL; instead, it observes CEL admission evaluations as structured evidence and maps them to canonical NIST SP 800-53 controls.

---

## 1. Author the Native ValidatingAdmissionPolicy

Create a native policy enforcing non-root container execution (`disallow-root-user.yaml`):

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: disallow-root-user
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  validations:
    - expression: "object.spec.template.spec.securityContext.runAsNonRoot == true"
      message: "Pods in production must set securityContext.runAsNonRoot to true."
```

Bind this policy to the target namespace:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: disallow-root-user-binding
spec:
  policyName: disallow-root-user
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchLabels:
        environment: production
```

---

## 2. Define the OSKAL ControlBinding

Now, map this Kubernetes-native admission enforcement to the canonical control `AC-6` (Least Privilege) using an OSKAL `ControlBinding`:

```yaml
apiVersion: assurance.ckodex.io/v1alpha1
kind: ControlBinding
metadata:
  name: bind-least-privilege-admission
  namespace: production
spec:
  canonicalControl: "ckodex:container.least-privilege"
  frameworkMappings:
    - framework: "NIST-SP-800-53"
      controlId: "AC-6"
    - framework: "CIS-Kubernetes-Benchmark"
      controlId: "5.2.6"
  workloadSelector:
    matchLabels:
      app.kubernetes.io/part-of: core-banking
  implementation:
    provider: "kubernetes.admission.cel"
    componentRef: "validatingadmissionpolicy/disallow-root-user"
    policyDigest: "sha256:d8912e84...0192"
  evidenceContractRef:
    name: contract-least-privilege
```

---

## 3. Verify CEL Admission Evidence

When a Deployment is submitted to Kubernetes, the OSKAL CEL adapter captures the admission decision:
- Extracts the admission evaluation result (`Allowed: true`).
- Computes the SHA-256 digest of the active `ValidatingAdmissionPolicy` definition.
- Signs and packages an `EvidenceEnvelope` of type `kubernetes.admission`.

Check that the evidence is recognized:

```bash
oskal assurance evidence --subject-name payment-service --subject-namespace production
```

Output:

```text
EVIDENCE ENVELOPES FOR Deployment/payment-service:
1. ID: env-adm-91823901
   Type:       kubernetes.admission
   Producer:   spiffe://ckodex.internal/ns/system/sa/oskal-cel-adapter
   Collected:  2026-09-24T11:21:00Z
   Attributes:
     admission.k8s.io/allowed: true
     policy.k8s.io/name: disallow-root-user
   Integrity:  sha256:88192a0149bb8812c30981
```
