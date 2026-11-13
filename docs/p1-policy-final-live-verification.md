# Final native policy and SPIFFE verification

These checks used the owned retained Kind API, actual OPA 1.22.4, actual SPIRE
1.16.0, real TLS connections, actual source metadata, real signing keys, and
filesystem CAS. They do not establish production deployment, compliance,
hardware attestation, or primary-CA rotation.

## Native OPA into the actual manager

`TestRealManagerOPACapture` passed in **22.462 seconds**. Before launch the test
required an explicit kubeconfig and owned mutation namespace. It built the
actual controller package and started it with `--namespace=oskal-policy-test`,
`--enable-webhook=false`, and an explicit CAPTURE-only OPA source. The existing
`has-team` and `missing-team` ConfigMap UIDs came from PartialObjectMetadata.
No target ConfigMap data was read by this path.

OPA built and loaded the real `manager-policy-v1` bundle. Its Rego policy
returned allow for `has-team` and deny for `missing-team`; its own decision-log
plugin masked the input sentinel and delivered revisioned gzip decisions over
mTLS to the manager's configured listener. The manager persisted and signed
both capture records. Returned native decision IDs, results, bundle revision,
and masking were checked against the stored source bytes.

Full SHA-256 identities from the successful run:

| Native result | Masked native decision bytes | Stored capture payload |
| --- | --- | --- |
| deny | `8f3780620b8628e0eaaeffa1163efe8272dd99e23c152aca5c0493d4cd7f910f` | `36d38062c2912b8d3048e88f6e9cf6605db129ae23995fd409d9ef92a883cc60` |
| allow | `557dde99bc5346e04777035525668e5a1aa26440bfaee42f6bf03c3c735e8701` | `aa2c5087ced99b5e88d1af1cfe71f6e1660038a708079685f7760283139534ab` |

Signatures verified with the manager's actual persisted public key. The envelope
producer and record observer were `local://oskal-controller`; the separately
authenticated publisher was `spiffe://oskal-policy-test/opa`. The observer's
signature is not an OPA message signature. Both envelopes retained only the
actual subject digest, with the other epoch dimensions unset and no ControlRefs.
Engine allow/deny did not become a control evaluation or admission grant.
The actual operational snapshots contained only CAPTURE sources; the separate
runtime-registry isolation test covers unchanged existing runtime eligibility
and revision during policy Begin/End. Process readiness is a separate contract.

The same actual manager listener was then exercised with:

- A valid certificate from the test CA carrying another URI: HTTP 401, despite a
  spoofed publisher header.
- Authenticated malformed gzip: HTTP 400.
- A real reversible filesystem obstruction at this test's private CAS path:
  HTTP 503. The original directory and history were restored and integrity
  verified; the obstruction file was retained separately.
- An oversized authenticated source: HTTP 413 and visible SAFE_HOLD. The first
  reason remained stable across 11 seconds of idle expiry, and subsequent valid
  deliveries remained denied with HTTP 503. The runtime source view stayed empty.

Both child processes completed graceful shutdown. The artifact-serving endpoint
provided the actual built OPA bundle; it did not synthesize policy decisions.

The executed command was:

```sh
OSKAL_POLICY_CONTROLLER_KUBECONFIG=/private/tmp/oskal-p1-runtime-evidence/kubeconfig \
OSKAL_POLICY_CONTROLLER_NAMESPACE=oskal-policy-test \
OSKAL_POLICY_OPA_BINARY=/private/tmp/oskal-p1-policy-evidence/opa \
OSKAL_POLICY_TLS_CA=/private/tmp/oskal-p1-policy-evidence/opa-ca.crt \
OSKAL_POLICY_TLS_CA_KEY=/private/tmp/oskal-p1-policy-evidence/opa-ca.key \
OSKAL_POLICY_TLS_SERVER_CERT=/private/tmp/oskal-p1-policy-evidence/opa-server.crt \
OSKAL_POLICY_TLS_SERVER_KEY=/private/tmp/oskal-p1-policy-evidence/opa-server.key \
OSKAL_POLICY_TLS_CLIENT_CERT=/private/tmp/oskal-p1-policy-evidence/opa-client.crt \
OSKAL_POLICY_TLS_CLIENT_KEY=/private/tmp/oskal-p1-policy-evidence/opa-client.key \
OSKAL_POLICY_CONTROLLER_EVIDENCE=/private/tmp/oskal-p1-policy-controller-evidence/opa-manager-complete \
go test -count=1 -run '^TestRealManagerOPACapture$' -v ./cmd/oskal-controller
```

Those paths identify the explicitly owned local test fixtures. Private keys and
captured evidence remain outside Git with restrictive directory permissions.
The successful output is retained at
`/private/tmp/oskal-p1-policy-controller-opa-manager-live-complete.log`.

Two earlier test failures remain preserved:

1. All measured route and fault checks succeeded, but cleanup failed because a
   child process inherited `t.Context`, canceled before `t.Cleanup`. The test now
   owns a separately bounded process context and stops children before canceling
   it. Output: `...-opa-manager-first-shutdown-failure.log`.
2. A concurrent disk observer saw an envelope before its payload publication
   completed. The test now waits for a complete physical snapshot and still
   requires the actual artifact hash and signature before accepting either
   decision. Permanent absence reaches the bounded timeout. Output:
   `...-opa-manager-observer-window-failure.log`.

The earlier report-manager namespace omission and its 22-object AS/CB inspection
remain documented in [the controller capture evidence](p1-policy-controller.md).

## Live SPIFFE trust-bundle change

`TestRealPolicySPIFFEBundleChange` passed in **20.20 seconds** against two owned
SPIRE 1.16.0 containers on their isolated network. The agent actually issued
`spiffe://phase1.oskal.test/pin-test`. Before changing trust, the fresh own SVID
permitted signing and the pinned receiver admitted the real peer to its method
check, returning HTTP 405 for GET.

The actual SPIRE management API then installed a second real public CA as the
federated trust domain `pin-change.oskal.test`, and the actual workload entry
was updated to receive that bundle. The fresh Workload API bundle changed:

```text
before sha256:01533108d4ddbf14cb874b9349178776e30b72072db5316d7831caa631290257
after  sha256:3a94ad94bac833084b36fdb4ebfc36c0ff49cf4e3f045e33f06a6e4e6be523e8
```

The same-snapshot peer API still verified the actual peer cryptographically
against the changed bundle and returned that changed digest. The old admitted
pin nevertheless rejected the request with HTTP 401 and rejected signing with
no signature returned. This distinguishes a changed authority snapshot from a
broken endpoint or invalid peer. It proves bundle-membership-change handling;
replacement or rotation of the primary SPIRE CA remains **NOT VERIFIED**.

`AuthenticatedPeerWithTrustBundleDigest` derives the principal and public-root
digest from the single fresh context used for both own-SVID and peer verification.
A second fetch is not used as proof of the first snapshot's roots. Canonical
SPIFFE IDs are parsed during source preflight, before archive/key initialization.

The following command was executed inside the owned real agent container; the
caller changed its own server's federation after the `PIN_READY` measurement:

```sh
docker exec \
  -e OSKAL_SPIRE_TEST_SOCKET=unix:///test/data/pin-agent.sock \
  -e OSKAL_SPIRE_TEST_ID=spiffe://phase1.oskal.test/pin-test \
  -e OSKAL_SPIRE_PIN_CHANGE=1 \
  oskal-p1-pin-spire-agent /test/pin.test \
  -test.run '^TestRealPolicySPIFFEBundleChange$' -test.v
```

Setup errors were investigated from actual configuration and logs. The server
image runs as UID 1000, so copied private files required matching ownership;
the agent's actual Unix client attested as UID 0, requiring that exact selector.
SPIRE rejected an attempted reserved agent-namespace token alias, so the actual
attested join-token node identity was used for the workload registration.
These failures and the successful evidence remain in the private evidence tree.

Successful output:
`/private/tmp/oskal-p1-pin-spire-evidence/pin-live.log`.
After stopping the two owned containers, their logs and runtime data were
preserved in `/private/tmp/oskal-p1-pin-spire-evidence/final`, including a protected
`stopped-runtime.tar.gz`. Only these containers and their network were removed. Re-running the recorded
container command requires re-creating that explicitly owned isolated environment.
No VM setting, global trust store, unrelated container, release, or remote branch
was changed.

## Bounded archive and service readiness integration

The native manager test was extended after archive bounds and capture service
readiness were integrated. It now requires `/readyz` HTTP 200 before OPA starts,
while no native decision exists, and HTTP 500 after the oversized authenticated
batch enters SAFE_HOLD. HTTP 500 is controller-runtime 0.25.2's actual health
checker failure response; subsequent ingestion remains HTTP 503.

The test also now fails immediately if a visible envelope's raw artifact cannot
be read. Immutable storage publishes payloads before envelopes; the test no
longer tolerates the earlier incomplete disk-observer window.

On 2026-11-13 the actual explicit fixture command below exited 0:

```sh
OSKAL_POLICY_CONTROLLER_KUBECONFIG=/private/tmp/oskal-p1-runtime-evidence/kubeconfig OSKAL_POLICY_CONTROLLER_NAMESPACE=oskal-policy-test OSKAL_POLICY_OPA_BINARY=/private/tmp/oskal-p1-policy-evidence/opa OSKAL_POLICY_TLS_CA=/private/tmp/oskal-p1-policy-evidence/opa-ca.crt OSKAL_POLICY_TLS_CA_KEY=/private/tmp/oskal-p1-policy-evidence/opa-ca.key OSKAL_POLICY_TLS_SERVER_CERT=/private/tmp/oskal-p1-policy-evidence/opa-server.crt OSKAL_POLICY_TLS_SERVER_KEY=/private/tmp/oskal-p1-policy-evidence/opa-server.key OSKAL_POLICY_TLS_CLIENT_CERT=/private/tmp/oskal-p1-policy-evidence/opa-client.crt OSKAL_POLICY_TLS_CLIENT_KEY=/private/tmp/oskal-p1-policy-evidence/opa-client.key OSKAL_POLICY_CONTROLLER_EVIDENCE=/private/tmp/oskal-p1-policy-controller-evidence/readiness-bounded go test -count=1 -race -run '^TestRealManagerOPACapture$' -v ./cmd/oskal-controller
```

Output excerpt:

```text
actual manager service readiness HTTP200
actual manager handler HTTP401
actual manager handler HTTP400
actual manager handler HTTP503
actual manager handler HTTP413
actual manager service readiness HTTP500
actual manager handler HTTP503
actual manager handler HTTP503
VERIFIED oversized actual source exposed SAFE_HOLD, stable reason across expiry, next deliveries denied; mode=SAFE_HOLD reason=policy source bound exceeded; operator review and restart required
--- PASS: TestRealManagerOPACapture (18.65s)
PASS
ok github.com/ckodex-labs/ckodex-oskal/cmd/oskal-controller 20.276s
```

Both native allow/deny payloads and their masked raw source bytes were verified
under the actual observer key. The full output is retained at
`/private/tmp/oskal-final-native-readiness-bounded.log`. This is a real host
manager/API/OPA integration check, not a deployed Helm or Service-network proof.
