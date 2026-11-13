# Service and embedded SDK evaluation authority

The default `service.NewServer` and `oskal.NewInProcessClient` have no live
assessment authority. They return UNKNOWN, with no invented epoch, timestamps,
contract, applicability, implementation providers or evidence root. Optional
archive arguments remain source-compatible but cannot establish current standing.

`SubmitObservation` accepts only bounded metadata into process memory. Its response
explicitly says unverified and non-durable. References are never converted into
payloads or envelopes, re-timestamped, signed by the service, or made eligible for
live evaluation. Claimed observer identities remain unverified. Invalid timestamps
and oversized messages are rejected. Full buffers return ResourceExhausted;
restarting clears these temporary observations. Historical receipt signature
verification likewise does not admit evidence or change assurance standing.

Configured controller integration uses:

```go
configured, err := service.NewServerWithEvaluation(receiptManager,
    service.EvaluationConfig{
        Resolver: sourceGroup.resolver,
        Evaluator: evaluator,
        Sources: sourceGroup.candidates,
    })
```

The host must use the same live candidate repository for `Evaluator` and `Sources`,
and the authoritative resolver must carry its actual authority snapshot digest.
`internal/application/assessment` resolves the live subject and bound controls,
uses the strict signature/artifact/producer/epoch evaluator, applies the shared
pure `evaluation.ApplyPolicies` helper, and checks governing epochs and source
revision again before returning. Missing dependencies fail construction. Resolution
failures return an actionable FailedPrecondition rather than an invented result.
All calls resolve fresh context, including requests without `force_fresh`.

Without an explicit policy requiring Assured, verified evidence remains VERIFIED.
The same shared policy helper is used by controller publication. Confirmed adverse
or incomplete evidence cannot become ASSURED through policy application. An empty
requested-control list evaluates all actually bound controls; unbound controls
are rejected.

The embedded SDK's `NewInProcessClientWithEvaluation(config, options...)` uses this
same service/application path. External callers can construct its configuration
with `oskal.NewEvaluationConfig(reader, authorityDigest, liveSource, verifier)`;
this binds evaluation and revision checks to the same supplied source. SDK serialization preserves subject attributes
(including UID), control versions, all five epochs, evidence references, trace,
and actual evaluation/expiry timestamps. `ExplainResponse.Evidence` preserves
reference URIs separately from producer identity. A reference alone has no producer,
capture timestamp or per-item verification status, so those graph fields remain
absent. Contract-level completeness is preserved rather than inferred from counts.

The network SDK requires explicit transport options. Production callers provide
TLS through `WithDialOptions`; plaintext is available only through an explicit
`WithInsecure` choice. The host remains responsible for authenticating TLS peers and
authorizing access to resolved Kubernetes scope. A local signing key labelled with
a SPIFFE URI is not workload-identity authentication. No signer is created when
none is supplied.

These read-time checks do not make multiple Kubernetes resources transactional.
Consumers must respect validity deadlines and resolve fresh authority for any
consequential action. A returned assessment is not an execution lease.

## Verification

On 2026-11-13, the real API regression passed with race detection:

```text
OSKAL_SERVICE_KUBECONFIG=<owned kubeconfig> go test -race ./internal/service \
  -run TestLiveBindingAssessmentOverTLSAndSDK -v -count=1
```

Retained namespace: `oskal-service-1794563209514162000`, UID
`522a1ca0-5465-402e-9d0e-d3214a284cef`. The test uses actual Kubernetes objects,
immutable filesystem CAS, Ed25519 signatures, source sessions, and a real TCP/TLS
1.3 gRPC server requiring client certificates. It checks wrong-producer rejection,
policy-free VERIFIED, explicit-policy ASSURED, policy-epoch invalidation, source
shutdown, unbound controls, UID preservation, and both SDK transports. An unsigned
opaque observation cannot become evidence or assurance in the default service.

This proves the configured application and transport path for real Pod API facts;
it does not claim runtime sensor enforcement, workload SVID authentication, or
hardware attestation. Phase 2 attestation remains gated.

The full `go test -race ./...` suite and `golangci-lint run` passed for this change.
