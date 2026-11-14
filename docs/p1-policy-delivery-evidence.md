# Phase 1 policy-source delivery backends

Verified locally on 2026-11-13 with actual retained Kubernetes engine reports and
OPA 1.22.4. The decoders and initial engine evidence are documented separately in
[policy ingestion evidence](p1-policy-ingestion-evidence.md).

## Batch ownership

`internal/application/policycollection` accepts:

```go
type BeginBatch func(context.Context) (
    ports.CapturedEventWriter,
    func(error), // End, required; runs exactly once for a returned batch
    error,
)
```

The parent application's factory must invalidate/rotate previous eligibility
before returning a writer, then publish only the completed current session. The
backend preserves CAS history but never reuses an RV/name cache to retain an old
batch. Empty lists contain no result evidence. Failed Lists, decoding, bounds,
deadlines or writes complete through `End(error)`; successful durable writes
finish through `End(nil)`. Fact storage is separate from assurance promotion.

## Kubernetes polling

`NewReportsRunner(ReportsConfig)` requires an explicit `dynamic.Interface`, GVR,
namespace matching its scope, producer, batch factory, poll interval, request
deadline, object cap and batch byte cap. Known standard report GVRs determine the
exact kind. Custom Gatekeeper constraint GVRs additionally require their kind.
The implementation has no ambient Kubernetes client or context selection.

`Poll(ctx)` begins a fresh batch before the actual List. A bounded List requests
at most `MaxObjects+1`; continuation or excess objects return `ErrSafeHold` rather
than accepting a partial snapshot. Raw and decoded bytes and capture count are
bounded before writes. A missing CRD is a source error, not an empty success.
Concurrent polls on the same runner receive `ErrBatchActive` without a queue.

`Run(ctx)` polls immediately, then waits the configured interval after each
success. The first fault terminates that run after completing its batch with the
error. The parent owns restart budget/backoff; there is no second retry owner.
Cancellation stops the timer and propagates its context error.

## Authenticated OPA HTTP receiver

`NewOPAReceiver(OPAConfig)` returns an `http.Handler`, not a listener. The parent
owns TLS listener credentials, HTTP header/server timeouts and shutdown. Required
configuration: actual OPA decoder, fresh `PrincipalResolver`, exact expected
publisher, batch factory and request deadline. Its local structural resolver
interface is compatible with `ports.PrincipalResolver`:

```go
AuthenticatedPrincipal(context.Context) (string, error)
```

`PeerTLSState(ctx)` exposes the handler's TLS connection state under a private
context key for that verifier. The handler requires a completed TLS 1.3 handshake
and peer certificate, then delegates fresh chain/identity verification to the
resolver. It does not equate a claimed URI, request header or TLS state alone with
authority. `VerifiedChains` is not required by the handler because a SPIFFE TLS
custom verifier may leave it nil; the supplied resolver must establish trust.

Authentication precedes body reads, decompression and `BeginBatch`. A single
capacity slot bounds authentication and batch work; concurrent requests receive
429 with a retry hint. Only POST with gzip `application/json` is accepted. The
request context and an enforced transport read deadline bound work. Existing OPA
compressed/expanded/event/schema/privacy bounds apply before persistence.

The verified upstream publisher is persisted as `authenticatedPublisher`.
`observer` and the envelope producer remain the observing collector. These may
legitimately differ: a collector signature is not an OPA publisher signature.
The original source JSON bytes remain unchanged in `sourceBytes`.

HTTP 204 follows actual durable writes and completion of `End(nil)`. Other
outcomes include 401 for missing/unverifiable TLS identity, 403 for a different
principal, 405 for method, 415 for media/encoding, 413 for payload bounds, 400 for
invalid batch, 429 for capacity, and 503 for batch/persistence/deadline failure.
No raw decision input or verifier error is echoed in HTTP errors.

## Actual backend verification

`TestLivePolicyCollectionRunners` used the explicit owned Kind kubeconfig and real
`reports.openreports.io` and Gatekeeper constraint APIs, followed by the real
live UID/creation-time resolver and filesystem CAS. It verified:

- Successful report and constraint Lists and verifiable persisted payloads.
- Real API cap -> SAFE_HOLD and exactly one batch before `Run` returned the fault.
- Unconfigured actual CRD -> failed source completion, not empty PASS.
- Actual empty namespace List -> distinct empty batch with no invented result.
- Two successful periodic polls followed by context cancellation.

```text
actual Lists and CAS writes; batches=5 completed=5;
capped/missing sources invalidated; empty source emitted no evidence
--- PASS: TestLivePolicyCollectionRunners (1.71s)
```

`TestLiveOPADecisionCapture` now routes the actual OPA gzip exporter into the
production `OPAReceiver`, with real mutual TLS and a resolver performing current
X.509 verification against the explicit test CA and exact URI. Its producer is
`local-test://opa-policy-collector`, while the authenticated publisher is
`spiffe://oskal-policy-test/opa`. The persisted record verifies that separation.

```text
allow artifact=sha256:933f94b26c910df112a7b3fb1e449d2a0c24264f83d28cbbe11877681e7f7be9
deny  artifact=sha256:1ee702637556c6d7105ee4ebb6d7338b33c0617a7a78aac12d13d1e70f1b5d52
production receiver authenticated publisher before batch;
malformed authenticated batch returned 400 after End(error)
actual filesystem persistence failure returned 503 and End(error);
retained CAS history was not deleted
--- PASS: TestLiveOPADecisionCapture (1.19s)
```

The test also verifies a wrong exact publisher receives 403 without beginning a
batch. Its write-failure check uses the real filesystem repository with an
obstructed temporary path; it receives the actual ENOTDIR error, not a simulated
writer response. No existing evidence is deleted. The coverage contract remains
UNKNOWN, and an input field selected for source masking remains absent from CAS.

Reproduce with the same explicit environment described in the ingestion record:

```sh
go test -race -count=1 -run '^TestLivePolicyCollectionRunners$' -v ./tests/integration
go test -race -count=1 -run '^TestLiveOPADecisionCapture$' -v ./tests/integration
```

Logs: `/private/tmp/oskal-p1-policy-evidence/live-policy-runners-final.log` and
`live-opa-production-receiver-final.log`. The evidence directory contains private
test keys and must not be committed or published. No new engine installation or
VM/global configuration change was needed.

Manager registration, source-session signing/current-root publication, production
SPIRE peer verification and binding-specific policy/epoch mapping remain parent
application assembly responsibilities. The test factory uses actual CAS and live
UID resolution; it does not claim signed-session integration or production trust.
The base branch's existing controller harness Ready=True versus UNKNOWN failure
remains outside this backend scope.

`go build ./...`, focused race checks and scoped golangci-lint 2.15.0 passed.
The final full `go test -race -count=1 ./...` run again passed all other packages
and failed only that existing controller harness expectation. Its actual output
is retained as `policy-delivery-full-race.log`; the whole-repository gate is not
reported as passing.
