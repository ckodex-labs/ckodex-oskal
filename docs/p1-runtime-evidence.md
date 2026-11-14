# Phase 1 runtime capture evidence

Observed and verified locally on 2026-11-12 and 2026-11-13. This record covers real runtime
subscriptions and storage, not a deployed OSKAL controller or production trust.

## Execution path

```text
Tetragon FineGuidanceSensors.GetEvents (mTLS)
  or Hubble Observer.GetFlows (mTLS through a Kubernetes-authorized port-forward)
-> official generated protobuf messages
-> namespace, identity, verdict/UID and timestamp validation
-> synchronous CapturedEventWriter (4 MiB bound)
-> live Kubernetes Pod GET + UID/creation-time check
-> authoritative subject and epoch resolver
-> exact protobuf JSON payload + envelope in filesystem CAS
-> SHA-256 verification
```

The collectors run one session. They return upstream, validation, persistence or
cancellation errors; callers own bounded reconnect and source availability state.
There is no hidden queue, synthetic event, timestamp replacement or automatic
assurance promotion. The epoch resolver is an application port: production wiring
must supply the same epoch authority as reconciliation, rather than constructing
an epoch from the subject URI. The live test uses the current API Pod digest.

Tetragon's official `Process.uid` field is the effective user ID used for
permission checks (mapped to `ProcessCredentials.euid` in the generated SDK).
Individual observations are `workload.runtime.process.euid.nonroot` or
`workload.runtime.process.euid.root`, under the narrow `runtime.process-uid`
control reference. Root execution is a fact; policy determines whether it is
prohibited. A nonroot effective UID does not prove capabilities are restricted,
least privilege, or that all executions were observed. Hubble forwarded and dropped packets remain
`network.flow.observed`; neither establishes default-deny isolation. An isolation
contract evaluated against these observations remained UNKNOWN in the live test.
No events produce no evidence. An explicit Hubble `LostEvents` stream message
terminates collection with an error so the source owner can downgrade availability.
It cannot silently establish complete visibility. Continuous coverage, loss-window
accounting and loss metrics remain outside this capture claim.

Unused legacy `TetragonObserver`/`CiliumObserver` APIs were retired after a
repository-wide caller inventory found only tests. Those APIs constructed
digest-only envelopes from caller-supplied booleans and process structs without
retaining their payload. Their former composition test's fabricated VERIFIED and
ASSURED claim was replaced with a missing-runtime/isolation UNKNOWN assertion.
The real SDK mapping and live storage tests remain.

## Versions and dependency consequence

The official [Tetragon 1.8.0 release](https://github.com/cilium/tetragon/releases/tag/v1.8.0)
and [Cilium 1.20.4 release](https://github.com/cilium/cilium/releases/tag/v1.20.4)
were checked against their primary release pages on 2026-11-12. Both pages marked
these versions latest at that observation time.

The code imports `github.com/cilium/tetragon/api/v1/tetragon` from the split API
module v1.8.0 and Cilium's `api/v1/{flow,observer}` packages from v1.20.4.
Tetragon's published API module requires the root module at the zero pseudo
version and uses an upstream local replacement. A version-scoped replacement
maps that exact zero pseudo version to the corresponding root release v1.8.0.
It does not replace any other root-module version.

`go mod graph` showed Cilium v1.20.4 requires Kubernetes v0.36.5 and
controller-runtime v0.24.1; Tetragon API v1.8.0 requires gRPC v1.85.0. The resolved
project graph uses Kubernetes v0.37.2, controller-runtime v0.25.2 and gRPC v1.85.0.
The resulting whole repository built and passed the uncached race suite. This
does not establish cross-version or cross-platform deployment compatibility.

## Real runtime observation

Only the isolated Kind cluster `oskal-p1-runtime-20261112` was used, through its
explicit kubeconfig. A real nonroot BusyBox Pod generated process executions and
outbound traffic. Cilium/Hubble 1.20.4 and Tetragon 1.8.0 were running; observed
runtime image IDs were:

| Component | Runtime image digest |
| --- | --- |
| Cilium | `sha256:20fe92e4c86641233a450098c158d2d29085f3419931ab6bf681d2485dedf16e` |
| Hubble relay | `sha256:cb23408209697ed30d2bc462e1f01eb622ea4423a891458f78bc88d7255bbfc1` |
| Tetragon | `sha256:5ed9088a1582131d71b06c98e0d549a37a71ae63ab13aabefc7a47553c822a9d` |

The initial 2026-11-12 run used plaintext Hubble gRPC through a Kubernetes-authorized
loopback port-forward, with `disable-server-tls: true` in the relay configuration.
That historical output remains in `live-test-final.log`; it did not prove Hubble
mTLS. The isolated cluster was then upgraded with the exact official Cilium
1.20.4 chart settings:

```yaml
hubble:
  tls:
    enabled: true
  relay:
    tls:
      server:
        enabled: true
        mtls: true
```

The chart's `_extensions.tpl` configures `tls-relay-client-ca-files` using the
relay's mounted `hubble-server-ca.crt`. The generated server certificate has SAN
`*.hubble-relay.cilium.io`. A dedicated client certificate was signed by this
isolated cluster's CA and provided with explicit roots and server name
`oskal.hubble-relay.cilium.io`. The service changed from port 80 to port 443;
the explicit loopback port-forward now targets 443. These options are defined in
the [versioned official chart values](https://github.com/cilium/cilium/blob/v1.20.4/install/kubernetes/cilium/values.yaml).

The final 2026-11-13 live test returned exit 0, including stream cancellation, real API
identity resolution, persisted payload verification and the isolation UNKNOWN
check. Both actual source APIs rejected a missing client certificate with
`tls: certificate required` and rejected an incorrect server name with an x509
SAN validation error before successful authenticated capture:

```text
captured real workload.runtime.process.euid.nonroot
  subject=k8s://oskal-runtime-test/Pod/capture-workload
  artifact=sha256:5fc3d70e7b1b1998de064aed9a6a2803452a1d1f04c8bc752842f37869361116
captured real network.flow.observed
  subject=k8s://oskal-runtime-test/Pod/capture-workload
  artifact=sha256:a92ac9712d61dfc3e82916acc95053c671a5d96619cb8000ef1f6efbead8175f
--- PASS: TestLiveRuntimeCapture (2.51s)
PASS
```

The first strict timestamp run rejected a real Tetragon timestamp approximately
200 ms ahead of the host clock. `MaxClockAhead` therefore explicitly permits a
bounded, cancellation-aware wait; its default zero rejects future timestamps.
The live test selected one second, waits until the original source timestamp is
no longer future, and rechecks it before storage. Virtual-time tests verify the
wait, cancellation, zero/default rejection, excessive skew, and invalid settings.
No source timestamp was rewritten and no clock setting was changed.

## Reproduction and retained evidence

`TestLiveRuntimeCapture` skips unless `OSKAL_LIVE_KUBECONFIG` is explicitly set.
It also requires `OSKAL_LIVE_NAMESPACE`, `OSKAL_LIVE_POD`,
`OSKAL_LIVE_TETRAGON_ENDPOINT`, `OSKAL_LIVE_HUBBLE_ENDPOINT`, and explicit
CA/certificate/key file paths and server names for both sources:
`OSKAL_LIVE_TETRAGON_{CA,CERT,KEY,SERVER_NAME}` and
`OSKAL_LIVE_HUBBLE_{CA,CERT,KEY,SERVER_NAME}`. Partial TLS configuration fails;
there is no plaintext or insecure verification fallback.
`OSKAL_LIVE_EVIDENCE_DIR` selects retained CAS output. Run:

```sh
go test -race -count=1 -run TestLiveRuntimeCapture -v ./internal/application/ingestion
```

The test uses server names `test.tetragon-grpc.cilium.io` and
`oskal.hubble-relay.cilium.io`, verified against the respective certificate SANs.
Its loopback Hubble endpoint additionally uses Kubernetes port-forward
authorization. This setup does not verify production SPIFFE peer
authorization or production source availability enforcement.

Local logs, manifests, image identities and CAS payloads are retained under
`/private/tmp/oskal-p1-runtime-evidence`. That directory also contains local test
private keys: it must not be committed or published. No private key is included
in this repository record.

Other gates, all exit 0 with Go 1.27.3 on Darwin ARM64:

```text
go build ./...
go test -race -count=1 ./...
golangci-lint 2.15.0 run ./internal/adapters/tetragon/... ./internal/adapters/cilium/... ./internal/application/ingestion/... ./internal/ports/...
  0 issues.
go mod tidy -diff
git diff --check
```

The full-repository lint has an existing controller-runtime `scheme.Builder`
deprecation in the API package after the dependency upgrade; parent integration
owns its replacement. The scoped runtime lint passes. No hosted, signed,
multi-node, accelerator, or production deployment claim is made here.
