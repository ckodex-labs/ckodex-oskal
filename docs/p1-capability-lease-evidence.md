# Phase 1 capability lease evidence

Observed against the dedicated local Kind API `https://127.0.0.1:56169` on
2026-11-13 UTC. The API authenticated the test credential as `kubernetes-admin`
through SelfSubjectReview; this is local integration evidence, not production RBAC
or a remotely authenticated SPIFFE caller demonstration.

Commands and results:

```text
OSKAL_LEASE_KUBECONFIG=/private/tmp/oskal-p1-runtime-evidence/kubeconfig \
  go test -race -count=1 -v ./internal/adapters/workcell ./internal/adapters/utcp
exit 0
ok  github.com/ckodex-labs/ckodex-oskal/internal/adapters/workcell  17.950s
ok  github.com/ckodex-labs/ckodex-oskal/internal/adapters/utcp       4.497s

go test -race -count=1 ./...
exit 0

go build ./...
exit 0

golangci-lint run ./...
0 issues.
exit 0
```

The broker suite retained namespace `oskal-lease-1794546561170826000`.
Observed checks include two actual filesystem effects with two persisted
completions followed by turn-budget denial; wrong identity/UID/scope/capability/
chain/expiry denial; immutable-spec update rejection; twenty contenders rejected
while one callback was pending; and revocation preserved when that callback
completed. Eight simultaneous API admissions produced exactly one callback and
completion. A separate process wrote a file then exited with code 73; a fresh
broker denied replay of the durable pending turn. Callback failure after a write
also remained pending. Cancellation and API unavailability produced zero effects.

The UTCP suite retained namespace `oskal-lease-utcp-1794546561534596000`.
Governed manual registration, external HTTP execution, provider discovery and
registration, and deregistration ran against the real API. A caller-selected
`RequiredCapability` could not grant either execution or provider registration.
The successful tool made exactly one HTTP/file-write effect; its returned
completion matched persisted status:

```text
sha256:cf80fb1a7b2ab5cca8762638c400866f4d1c89cd4fd167fa35a3cc94f3d576e5
```

Separate local HTTP checks observed exactly one request on HTTP 503 and HTTP 307,
with neither automatic replay nor redirect following.

Local artifacts retained for review:

- `/private/tmp/oskal-lease-integration-final.log`
- `/private/tmp/oskal-lease-all-tests.log`
- `/private/tmp/oskal-lease-broker-state.json`
- `/private/tmp/oskal-lease-utcp-state.json`

The broker reserves authority before effects and hashes observed completion
afterward. These receipts are unsigned. The remaining integration work belongs to
the parent change: controller admission/chain preservation, CLI and authenticated
transport resolver wiring, and replacing read-path CAS constructors with a
non-creating opener. Deployed-controller behavior, multi-user TLS wiring,
production authorization, telemetry export and downstream revocation fencing are
not established by these tests. No Phase 2 attestation capability is claimed.
