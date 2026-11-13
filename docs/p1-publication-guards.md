# Live publication and source scope

A verified evidence evaluation remains VERIFIED until an explicitly resolved
AssurancePolicy requires Assured and its freshness criteria hold. Only ASSURED
sets the binding Ready condition true. Confirmed adverse evidence remains FAILED;
policy cannot promote an adverse or incomplete evaluation.

The controller re-resolves all five governing epochs and checks the live source
revision before and after publication. A stale binding condition guard cannot
prevent retraction of AssuranceStates owned by the original binding UID. Retargeting
first clears standing, evidence, receipt references and validity through the status
subresource, then changes the subject reference, then publishes new standing.
Receipt artifacts remain immutable even when their summary is retracted.

These are bounded detection and retraction checks, not a cross-object Kubernetes
transaction. A governing object can change between the final read and a write, and
an unavailable API can prevent retraction. Consumers must resolve fresh context,
compare the complete epoch and subject UID, verify receipt authority and expiry,
and deny on unavailable context. A status snapshot by itself is not an admission
lease or a continuing guarantee.

Namespace-wide captures first try direct Pod binding, then supported Deployment
attribution. Only an authoritative zero-binding result is ErrNotApplicable and
ignored without storage. API, authentication, UID, selector, ambiguity and configured
unsupported-owner errors remain failures. Unbound DaemonSet or StatefulSet Pods do
not terminate unrelated streams; a configured unsupported owner does.

Liveness measures the process. Readiness fails while any configured source is
STARTING, UNAVAILABLE or SAFE_HOLD. Explicit zero-source, webhook-disabled operation
is read-only UNKNOWN: readiness does not grant admission authority.

The enforcing webhook requires a pre-existing resolvable target and live evidence.
Bootstrap requires an explicit operator-managed sequence to create that target
before enforcement; the controller does not silently relax the webhook.

Public authority snapshots are retained under
`configuration/authority-snapshot.json.d/<sha256hex>.json` before the atomic latest
alias `configuration/authority-snapshot.json` is updated. Private keys and bearer
credentials are excluded. Historical proof files are never replaced by this writer.

## Verification

`OSKAL_PUBLICATION_KUBECONFIG=<explicit owned kubeconfig> go test -race
./internal/application/reconcile -run TestLivePublicationGuards -v -count=1`
passed against the owned Kind API on 2026-11-13. Retained namespace:
`oskal-publication-1794562331798242000`, UID
`8c874165-0566-4267-bb3f-b292cf67773f`. The test uses real API watches,
controller-created DaemonSet ownership, immutable CAS and Ed25519 signatures.
It checks policy-gated promotion, retarget ordering, stale-condition retraction,
source invalidation and direct/unbound/unsupported capture scope.

Scoped race tests and full `golangci-lint run` pass. The full race suite remains
blocked by existing CLI export metadata expectations and an integration test that
builds only `cmd/oskal/main.go`, omitting its package helpers. Those CLI paths are
outside this change. This test does not establish atomic multi-resource updates,
hardware attestation, or end-to-end live sensor enforcement.
