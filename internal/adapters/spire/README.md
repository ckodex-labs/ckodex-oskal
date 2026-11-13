# SPIRE adapter

`NewWorkloadClient` uses go-spiffe v2.9.0 and a required local Unix socket URI,
exact own SPIFFE ID, and positive timeout no greater than one minute. Each
`Identity` or TLS callback opens a Workload API stream, receives one complete
SVID/bundle response, and closes that stream. No identity cache masks an agent
outage. The reconciler owns polling/retry cadence. A new response supplies current
trust roots; this adapter has no independent root refresh loop.

`Identity` verifies the actual caller process. It must never be used as proof
that an arbitrary Kubernetes subject has that identity. SPIRE's socket ownership,
workload attestation and registration policy establish which process receives the
SVID. `TLSClientConfig` and `TLSServerConfig` enforce TLS 1.3 mutual authentication
and exact peer SPIFFE IDs. Their context must remain live for the transport
lifetime. Close the client after transports have drained. Existing authenticated
connections do not reauthenticate when registration policy changes; callers must
bound connection lifetime and drain on policy changes.

`SVIDValidator` is a separate offline certificate validator for explicitly supplied
roots. It uses go-spiffe's URI-SAN and leaf/chain rules, accepts no default roots,
and applies zero clock skew tolerance unless explicitly configured. It does not
fetch SPIRE trust roots or authenticate the caller presenting a certificate.

## Real integration evidence

The adapter was tested against official SPIRE 1.16.0 server and agent images on
Linux arm64 using isolated Docker resources. Primary version references:

- https://github.com/spiffe/go-spiffe/releases/tag/v2.9.0
- https://github.com/spiffe/spire/releases/tag/v1.16.0
- https://github.com/spiffe/go-spiffe/blob/v2.9.0/workloadapi/client.go
- https://github.com/spiffe/go-spiffe/blob/v2.9.0/spiffetls/tlsconfig/config.go

Images resolved on 2026-11-12:

- `ghcr.io/spiffe/spire-server@sha256:ff546f4c62dafc479a0cd79eae9a7b6df2975754d75efd31706098e0d7548837`
- `ghcr.io/spiffe/spire-agent@sha256:ab3a8ce70435374cc5d84c81eabf0278dc046ddbc0a736d59694ba9e5975b1b6`

The live tests validated issued SVIDs, own-identity mismatch denial, successful
mTLS, both peer allowlist denials, closed-client denial and stopped-agent denial.
They used join-token node attestation and Unix UID workload attestation. These
results do not prove Kubernetes selectors, TPM/TEE attestation, production root
custody, root rotation, revocation propagation, or cross-platform Workload API
support.

To run against a real registered agent from the workload's execution environment:

```sh
OSKAL_SPIRE_TEST_SOCKET=unix:///run/spire/agent.sock \
OSKAL_SPIRE_TEST_ID=spiffe://example.org/workload \
go test -v ./internal/adapters/spire -run '^TestRealWorkloadAPI$'
```

Without those variables, the integration test explicitly skips. It never starts a
fake SPIRE server. The stopped-agent test separately requires
`OSKAL_SPIRE_UNAVAILABLE_SOCKET` and must run only after the real agent is stopped.
