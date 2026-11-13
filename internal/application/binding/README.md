# Authoritative binding context

`NewResolver(uncachedReader)` supplies one source of subject identity, selected
controls, evidence contracts, policies, and epoch configuration for both capture
and evaluation. Use a direct Kubernetes client or `manager.GetAPIReader()`.
Controller caches must not be used for this authority boundary.

- `ContextForBinding(ctx, namespace, bindingName)` resolves a real binding to
  exactly one real Pod or Deployment. Object and namespace label selectors and
  API groups are checked against the API objects. Without an object label
  selector, the binding must be named `<workload>-binding`.
- `ContextForSubject(ctx, subject)` accepts canonical
  `k8s://namespace/{Pod,Deployment}/name`, checks an expected UID when supplied,
  and requires exactly one applicable binding and one selected workload.
- `ResolveCapture(ctx, event)` requires a real Pod and checks UID, creation time,
  and the complete Pod -> ReplicaSet -> Deployment controller UID chain. Direct
  Pods are supported. Unsupported controller kinds, stale templates, changed
  ownership, and ambiguous attribution return errors with no epoch.
- `WithAuthorityDigest(actualSnapshotSHA256)` returns a separate resolver with a
  validated, caller-supplied canonical SHA-256 authority snapshot digest. Use the
  same configured resolver for evaluation and capture. The caller owns the
  authority proof; a syntactically valid digest does not establish that proof.

Missing API objects, missing referenced contracts, empty contracts, conflicting
requirement IDs, unsupported kinds, wildcard kinds, or API failures return errors.
There are no URI digests, default controls, default producer identities, invented
inline admission requirements, or silent freshness substitutes. Optional-only
contracts retain their actual Required flags; the evaluator must decide whether
those obligations can support an assurance claim.

Epoch dimensions bind the actual subject UID/full spec/labels; binding UID/spec;
referenced contract UID/spec and sorted namespace policy UID/spec; and namespace
UID/labels. Status-only changes do not invalidate the epoch. Namespace recreation
and non-image spec changes do. Authority remains empty until explicitly supplied.
Implementation-reference configuration is hashed; this does not prove the
referenced mechanism exists or enforces anything.

Hubble has no Pod UID in its supported flow identity. Such events must be at least
one second after the live Pod's API creation timestamp. The extra precision window
is required because the pinned Kubernetes `metav1.Time` JSON representation keeps
whole seconds. Facts in that interval are rejected rather than attributed across
same-second Pod name reuse. This is a conservative visibility limit, not proof of
a UID that the source did not provide.

Each operation has a ten-second deadline (or the caller's shorter deadline), no
internal retries, and a limit of 256 objects/requirements per collection. Every
lookup failure is returned. Governing objects and membership are checked again
before returning the context; detected concurrent changes invalidate the attempt.
Kubernetes does not supply an atomic transaction across these object reads. The
caller must reconcile/retry using a new bounded query after an error.

Capture epochs describe configuration observed at ingestion. They are not a
retrospective attestation that an event executed under that configuration. Producer
authentication, evidence verification, claim evaluation, persistence, execution
receipts, and controller recovery belong to their respective existing boundaries.

Run the real API attribution test only against an explicitly authorized cluster:

```sh
OSKAL_BINDING_KUBECONFIG=/path/to/authorized/kubeconfig \
OSKAL_BINDING_EVIDENCE_DIR=/path/to/retained/evidence \
go test -race ./internal/application/binding -run TestLiveBindingContext -v -count=1
```

The test creates uniquely named `oskal-binding-*` namespaces and actual API
resources. It requires the real Deployment/ReplicaSet controllers to create the
observed Pod ownership graph using server-assigned UIDs. It retains those resources
and an optional JSON evidence record. This verifies API attribution; it does not
prove that a telemetry source observed process or network execution. Earlier
manual API attribution records retained during controller-manager degradation
are separately labelled and are not controller-driven creation evidence.

Primary semantics: Kubernetes [object UID identity](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/),
[owner references](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/),
and [label selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/).
