# Durable capability lease execution

`workcell.NewKubernetesBroker(config, principalResolver)` creates an uncached
Kubernetes client. `Execute` authenticates every operation, checks the live
CapabilityLease, reserves a turn with a status resource-version compare-and-swap,
invokes one callback, then persists the observed result digest and completion.
The semantic evaluator performs no I/O. A request cannot claim its own principal.

A local CLI can use `NewKubernetesPrincipal(config)`, which executes a real
SelfSubjectReview for each operation. A multi-user transport must instead inject
a resolver that derives the verified peer from its authenticated transport. It
must never substitute the server's identity or accept identity headers. The
public Go package exposes `NewKubernetesClient` and `NewKubernetesPrincipal`.

The broker requires a positive TTL, 1–128 turns, exact namespace/name/UID,
matching admitted generation, and an active, non-deleting, non-revoked lease.
Grants are immutable in the CRD. Changed authority requires a new lease. A failed
or unavailable authoritative read denies execution. Payloads are limited to 1 MiB.

## Transport contract

The existing `lease_id` field carries `namespace/name/UID`. It identifies an
object; it is not a bearer credential. The compatibility field
`prev_receipt_hash` carries the previous **admission** hash, empty for the first
turn. Each request receives a unique ID. Completed IDs and stale chain tips
cannot be reused. A maximum of one effect is in flight per lease.

| Operation | Exact resource | Adapter-owned capability |
| --- | --- | --- |
| Register manual | `utcp://registry/manual/<escaped-name>` | `utcp:register-manual` |
| Register provider | `utcp://registry/provider/<escaped-name>` | `utcp:register-provider` |
| Deregister manual/provider | `utcp://registry/manual/<escaped-name>` | `utcp:deregister-manual` |
| Execute external tool | `utcp://registry/tool/<escaped-owner.tool>` | `utcp:execute-tool` |
| Run doctor probes | `utcp://registry/tool/oskal.run_doctor` | `utcp:run-doctor` |

Names resolve before admission. Aliases bind the same canonical owner/tool.
`RequiredCapability` metadata cannot select authority. Manual/provider
registration binds the full supplied definition, and tool execution binds the
full resolved tool definition plus arguments in the payload digest. Caller-owned
maps are copied before execution. Provider completion additionally digests the
actually loaded manual alongside its provider definition. A registry resource identifies the registered
operation; it does not assert attenuation over the downstream HTTP service's
resources. The downstream service retains its own authentication and authorization.

Nil brokers deny every registry mutation and effect. Fixed built-in local
analysis is the only ungated execution path. External tool calls do not retry,
follow redirects, or reuse connections that could trigger a transport retry.
Manual GET discovery has a separate bounded read retry policy.

## Evidence and failure semantics

`LastAdmissionHash` and `PendingExecution` describe permission reserved before
execution. They never prove completion. A successful effect produces an
`ExecutionReceipt` containing its admission, result digest, completion time and
previous execution hash. `ExecutionHistory` preserves every completed turn;
`LastExecutionHash` points to its tip. Each new admission verifies retained hash
linkage. The broker never reads or overwrites legacy `LastReceiptHash`.

Operational metrics use fixed source/type/status labels, avoiding lease-ID
cardinality. OpenTelemetry execution spans mark persisted admission, callback
return and persisted completion with their hash correlation identifiers. They
record no payloads or private reasoning. Export requires the application's
telemetry configuration.

These are **unsigned hash chains**, not signatures, independently authenticated
receipts, or proof against a Kubernetes administrator who can rewrite status.
Protect lease creation/spec and lease status writes with appropriately separated
RBAC. The broker requires get on leases and update on leases/status; local
SelfSubjectReview identity additionally requires create on selfsubjectreviews.

A callback error, panic or process crash after admission leaves the consumed turn
pending. The broker does not refund or replay it. If persisting completion fails,
inspect the live status: completion may have committed even when its response was
lost. No automatic retry may re-invoke the effect. Inspect the pending request ID,
payload digest, admission hash, downstream state and available execution evidence.
Revoke/contain the lease and reconcile the actual downstream outcome before
issuing a new lease; do not clear pending state to retry an uncertain operation.
Registry state is process-local: a completion proves the mutation occurred, not
that a registration survives process restart. Re-registration needs new authority.

Revocation and cancellation constrain **new admissions**. A successful status CAS
is the admission linearization point. A concurrent revocation does not retract an
already-granted external effect; the admitted callback receives cancellation and
the lease expiry deadline, but a downstream service must implement its own fencing
to guarantee cessation. Completion preserves any revocation recorded meanwhile.
Deleting a lease can remove its evidence; retain/export it under an operator
retention policy rather than treating deletion as recovery.

## Verification

Apply only the lease CRD to a dedicated test cluster, then run:

```sh
kubectl --kubeconfig "$OSKAL_LEASE_KUBECONFIG" apply -f config/crd/bases/assurance.ckodex.io_capabilityleases.yaml
OSKAL_LEASE_KUBECONFIG=/path/to/dedicated/kubeconfig go test -race -count=1 -v ./internal/adapters/workcell ./internal/adapters/utcp
```

The integration suites retain `oskal-lease-*` namespaces for inspection. They
exercise actual SelfSubjectReview identity, immutable grants, expiry, exact scope,
UID, capability and chain denial, concurrent admission, revocation, real file
writes, restart after an uncertain effect, unavailable API denial, and governed
UTCP registration/external HTTP execution/deregistration. These checks prove local
Kind behavior; they do not establish deployed-controller, multi-user TLS wiring,
production RBAC, or downstream fencing.
