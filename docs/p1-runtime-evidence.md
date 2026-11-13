# Phase 1 runtime capture evidence

Observed and verified locally on 2026-11-12. This record covers real runtime
subscriptions and storage, not a deployed OSKAL controller or production trust.

## Execution path

```text
Tetragon FineGuidanceSensors.GetEvents (mTLS)
  or Hubble Observer.GetFlows (Kubernetes-authorized loopback port-forward)
→ official generated protobuf messages
→ namespace, identity, verdict/UID and timestamp validation
→ synchronous CapturedEventWriter (4 MiB bound)
→ live Kubernetes Pod GET + UID/creation-time check
→ authoritative subject and epoch resolver
→ exact protobuf JSON payload + envelope in filesystem CAS
→ SHA-256 verification
```

The collectors run one session. They return upstream, validation, persistence or
cancellation errors; callers own bounded reconnect and source availability state.
There is no hidden queue, synthetic event, timestamp replacement or automatic
assurance promotion. The epoch resolver is an application port: production wiring
must supply the same epoch authority as reconciliation, rather than constructing
an epoch from the subject URI. The live test uses the current API Pod digest.

Tetragon nonroot executions are individual `workload.runtime.process.nonroot`
facts. Root executions are `workload.runtime.process.violation` facts. Neither
proves all executions were observed. Hubble forwarded and dropped packets remain
`network.flow.observed`; neither establishes default-deny isolation. An isolation
contract evaluated against these observations remained UNKNOWN in the live test.
No events produce no evidence. Continuous coverage/loss guarantees are outside
this capture claim.

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

The final live test returned exit 0, including stream cancellation, real API
identity resolution, persisted payload verification and the isolation UNKNOWN
check:

```text
captured real workload.runtime.process.nonroot
  subject=k8s://oskal-runtime-test/Pod/capture-workload
  artifact=sha256:ec75cd514fc695255238e2686f855ef6d6904ed85c39a981010b1978c69e667c
captured real network.flow.observed
  subject=k8s://oskal-runtime-test/Pod/capture-workload
  artifact=sha256:9f6a9cd69aca6a6ba0ed32bba806146c77b9863a57c6e2c99e58c21373b2a25c
--- PASS: TestLiveRuntimeCapture (3.15s)
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
`OSKAL_LIVE_TETRAGON_ENDPOINT`, `OSKAL_LIVE_HUBBLE_ENDPOINT`, and the explicit
Tetragon CA/certificate/key file paths in `OSKAL_LIVE_TETRAGON_{CA,CERT,KEY}`.
`OSKAL_LIVE_EVIDENCE_DIR` selects retained CAS output. Run:

```sh
go test -race -count=1 -run TestLiveRuntimeCapture -v ./internal/application/ingestion
```

The test's Tetragon certificate requires the SAN
`test.tetragon-grpc.cilium.io`; its loopback Hubble endpoint uses Kubernetes
port-forward authorization. This setup does not verify production SPIFFE peer
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
