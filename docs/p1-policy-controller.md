# Controller policy capture sources

The controller's single `--sources` JSON file accepts the existing `tetragon`
and `hubble` runtime entries and the new `policy-report`, `gatekeeper`, and `opa`
entries. All source IDs share a unique DNS-label namespace and the combined
source count is at most 16. See
[p1-policy-controller-sources.example.json](p1-policy-controller-sources.example.json)
for the exact shape. Paths, GVRs, policy paths, publisher identities, and result
mappings in that example require operator selection; they are not defaults or
claims about an installed engine.

Every policy entry requires `policy_mode: "CAPTURE"`. No other policy mode is
implemented. The controller records native engine facts as signed historical
capture material. It supplies only an actual public-metadata subject digest;
policy, implementation, authority, and environment epoch dimensions remain
unset, and all ControlRefs are empty. Runtime binding/control attribution is
not applied to policy capture. Therefore reports, including engine `pass` and
OPA `allow`, cannot make the strict evaluator return PASS or grant admission.
Policy and bound runtime candidates use separate bounded in-memory registries
sharing only the durable archive and signer. Policy Begin/End, polling, outage,
or saturation cannot change the runtime registry revision, eligibility, or
control health gate. Runtime readiness and the evaluator/gRPC live view use
only bound runtime sources. The controller emits operational snapshots for
both registries with explicit BOUND_RUNTIME / CAPTURE modes; policy faults
remain visible without silently changing runtime standing.

A configuration with policy sources and no bound runtime source must explicitly
set `--enable-webhook=false`. Capture-only mode has no admission standing.
Its Kubernetes service readiness becomes available when each OPA listener is
actually serving TLS or each report source has completed a successful poll.
This includes valid empty polls and listeners awaiting their first request;
neither creates an observation or control standing. This separation permits
Kubernetes Services to route the first OPA delivery. A failed/stopped report
poller or listener clears service readiness. SAFE_HOLD blocks readiness until
operator review and restart. Native batch failures and expiry remain visible
in capture lifecycle even when the listener can accept a recovery batch.
UNKNOWN policy revisions and Gatekeeper truncation remain explicit in payloads.
An observer's signature identifies the controller, not the policy publisher.

Readiness verification on 2026-11-13 ran against actual mTLS sockets and an
explicit isolated Kind kubeconfig. The real empty-report namespace was retained
as `oskal-capture-empty-22xbh` (UID
`4af67a8f-3c80-40f1-a15c-d24e5a40eca7`). Actual command and output:

```text
OSKAL_POLICY_CONTROLLER_KUBECONFIG=/private/tmp/oskal-p1-runtime-evidence/kubeconfig go test -count=1 -race ./cmd/oskal-controller -run 'TestCaptureListener|TestPolicyBatchesCannot|TestCaptureOnly|TestRealEmptyReportPoll|TestPolicyBatchSafeHold' -v
actual empty report poll: service ready, eligible=0, capture=STARTING, bound runtime sources=0
--- PASS: TestRealEmptyReportPollReadinessWithoutEvidence (0.08s)
--- PASS: TestCaptureListenerReadyBeforeFirstDeliveryWithoutControlStanding (0.59s)
--- PASS: TestPolicyBatchesCannotInvalidateBoundRuntimeEvidence (0.02s)
--- PASS: TestCaptureOnlySourcesRequireExplicitReadOnlyMode (0.00s)
--- PASS: TestPolicyBatchSafeHoldCannotBeResetByAnotherDelivery (0.00s)
PASS
ok github.com/ckodex-labs/ckodex-oskal/cmd/oskal-controller 2.580s
exit 0
```

The listener test authenticated real TLS requests and observed HTTP 405 for
GET and HTTP 413 for oversized POST. The latter entered SAFE_HOLD and blocked
readiness while the listener was still serving, then transport became
unavailable after shutdown. Poll readiness was
observed after an actual successful empty API list, with zero eligible captures.
These tests do not prove a deployed Helm release or Kubernetes Service routing.

## Reports and metadata

Report configuration names the exact served GVR and kind. Supported APIs are
WG PolicyReport v1alpha2 and OpenReports v1alpha1, with explicit namespace for
namespaced reports and no namespace for cluster reports. Gatekeeper requires
an explicit ConstraintTemplate-defined v1beta1 constraint resource and kind.
A policy/report name prefix never establishes which engine authored a result.

The controller polls the real API with its manager configuration. HTTPS,
verified server certificates, and explicit public CA bytes are required;
ambient contexts and insecure TLS are not introduced by this source path.
Each poll starts a new fenced batch. A failed list, decode, metadata lookup,
signature, or durable write invalidates that batch's eligibility. A successful
empty list produces no eligible observation; successful delivery health is
reported separately and may make capture-only service readiness true.
Deletion or replacement cannot keep the previous batch eligible. At most three
consecutive failed runs are restarted, with one bounded restart owner.

Targets resolve through actual served discovery and a bounded 32-GVK REST
mapping cache. All API reads have a five-second bound and API response bodies
are capped at 16 MiB. Target GETs request PartialObjectMetadata, never target
spec/data. Allowed kinds are core Pods, Namespaces, ServiceAccounts, ConfigMaps;
apps Deployments, DaemonSets, StatefulSets, ReplicaSets; batch Jobs and CronJobs;
WG/OpenReports report objects; and actual served Gatekeeper constraint kinds.
Secrets and arbitrary APIs are rejected before target GET. A concrete UID must
match the current object and the observation must follow its creation. The
subject digest includes actual UID, creation time, and generation, without
claiming the report observed that generation's policy or workload spec.

`--namespace` limits controller reconciliation/mutations; cluster report capture
may observe subjects outside that namespace when explicitly configured and
permitted by the operator's separate read authority. These scopes are different.

## OPA publisher authentication

OPA requires an explicit decision path, bundle name, distinct boolean allow /
deny mappings, and exact publisher URI. There is no path, identity, mapping,
TLS-mode, or compliance fallback. The receiver accepts gzip JSON decision logs
only. Configure OPA's `system.log.mask` to retain only `input.subject`; the
existing decoder rejects unmasked input, unknown fields, duplicate keys,
missing bundle revision, unsupported result types, and oversized batches.
HTTP errors and controller logs never echo raw decision input.

`tls_mode: "pki"` requires mounted server certificate/key and explicit client CA.
TLS 1.3 mutual authentication is mandatory. Each request verifies the actual
TLS exporter, chain against that CA at current time, ClientAuth usage, and exact
single leaf URI. Headers and log fields do not establish publisher identity.
PKI files are loaded as one reviewed startup snapshot; changes require restart.

`tls_mode: "spiffe"` instead requires the controller's explicit main
`--workload-api` and `--spiffe-id` flags, plus the exact expected SPIFFE publisher.
PKI file settings are forbidden in this mode. Fresh peer verification uses the
handler's transport-owned TLS state and fresh Workload API trust. Startup pins
the canonical public SPIFFE bundle digest after verifying the own SVID against
that same snapshot. Peer admission and each evidence/receipt signature require
the fresh bundle digest to retain that pin. A bundle change fails closed and
requires an operator-reviewed new snapshot and restart; it is not an automatic
root rotation or hardware attestation claim.

Authenticated publisher URI and observer producer remain separate persisted
metadata. Each accepted delivery replaces the previous capture session. Batch
failure invalidates it; storage/session failures return HTTP 503. A single
expiry ticker per source invalidates idle capture eligibility after
`--source-session-window`. Sessions never regain eligibility from archive data.
Request deadlines must not exceed the session window. A decoder/capture bound
violation latches SAFE_HOLD until operator review and process restart; another
delivery cannot silently reset it. OPA has one active request per source, 16 pre-handshake connections, bounded
headers/body/deadlines, and a five-second shutdown drain. Listener startup
failure invalidates availability and uses the same three-run restart budget.

The public immutable authority snapshot records effective policy transport
settings, expected publisher, explicit decision mapping, API/public CA/certificate
digests, public signing key, and SPIFFE bundle digest when configured. Private
keys, bearer tokens, and raw decision inputs are excluded. Existing public
snapshot history remains content-addressed under `.d` variants.

## Explicit RBAC grants

Default policy capture Helm lists are empty and add no policy or ConfigMap read
grants. Configure only actual source resources:

```yaml
policyCapture:
  reportSources:
    - group: openreports.io
      resource: reports
      namespace: observed
  gatekeeperResources:
    - k8srequiredlabels
  configMapMetadataNamespaces: []
```

The chart renders report Roles/RoleBindings in the selected namespaces, separate
ClusterRoles only for selected cluster report resources and exact Gatekeeper
constraint resources, and optional ConfigMap `get` Roles in selected namespaces.
No wildcard Gatekeeper resource or Secret grant is generated. The existing apps
read role includes ReplicaSets for the actual Pod-to-ReplicaSet-to-Deployment
runtime resolver path.

Kubernetes RBAC cannot constrain ConfigMap `get` to metadata fields. Enabling a
ConfigMap metadata namespace grants that ServiceAccount the capability to read
ConfigMap contents there, even though this code requests and stores only
metadata. Leave the list empty where that broader capability is not authorized.

For a static installation add an exact scoped rule and bind the controller
ServiceAccount; do not add `constraints.gatekeeper.sh/*` for convenience:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: oskal-capture-selected-constraint
rules:
  - apiGroups: [constraints.gatekeeper.sh]
    resources: [k8srequiredlabels]
    verbs: [get, list]
```

Namespaced WG/OpenReports grants should likewise use a Role/RoleBinding with
only the configured `policyreports` or `reports` resource. Cluster report
resources require corresponding exact ClusterRole/ClusterRoleBinding rules.
Target metadata lookup may require a separate narrow read grant for an allowed
kind; absence of that grant causes capture failure, never invented identity.

## Verification boundary

Local verification exercised actual generated X.509 certificates and a TLS 1.3
HTTP connection: the exact publisher reached a real unconfigured-session error
and received HTTP 503; another valid certificate was rejected despite a spoofed
identity header. This proves authentication and failure propagation, not policy
capture success. Pure cryptographic tests verify that public bundle certificate
order does not alter its digest and changed root bytes do.

Actual Helm rendering verifies default-empty policy grants, explicit scoped
report / Gatekeeper / ConfigMap grants, and wildcard rejection. Full Go build,
race tests, and lint passed during implementation. Opt-in real SPIRE tests and
the actual manager integration test require explicitly configured live backends;
ordinary passing/skipped tests do not establish those paths.

Run the actual manager capture check only against an authorized existing API
with real engine-generated reports/constraints and surviving subject UIDs:

```sh
OSKAL_POLICY_CONTROLLER_KUBECONFIG=/explicit/owned/kubeconfig \
OSKAL_POLICY_CONTROLLER_SOURCES=/explicit/report-sources.json \
OSKAL_POLICY_CONTROLLER_NAMESPACE=owned-test-namespace \
OSKAL_POLICY_CONTROLLER_EVIDENCE=/explicit/private/evidence \
go test -count=1 -run '^TestRealManagerPolicyCapture$' -v ./cmd/oskal-controller
```

That test launches the actual manager package binary, reads actual policy
resources, resolves current PartialObjectMetadata, and verifies persisted signed
CAS artifacts with empty control references and incomplete capture epochs. It
does not deploy engines, synthesize successful reports, grant admission, or
assert production, hardware, root-rotation, or signed-promotion readiness.

Observed manager proof on 2026-11-13 used the explicitly owned Kind API and
`--namespace=oskal-policy-test`, with `--enable-webhook=false`. It passed in
5.262 seconds including package build. The actual manager read three native
OpenReports targeting existing ConfigMap UIDs and one served
`constraints.gatekeeper.sh/v1beta1` `OskalRequiredLabels` audit. All four stored
artifact digests matched the earlier native-engine delivery proof; signatures
verified using this manager's persisted public key. Envelopes had only a subject
digest and no ControlRefs. Engines remained scaled down: this proves fresh API
capture of retained native output, not continuing engine health or compliance.
The manager used an explicit local signing key; live SPIFFE bundle pin / root
change behavior and native OPA delivery into this new manager listener were not
re-run as part of this particular manager proof. Prior native OPA receiver
proof and the new actual PKI authentication/failure tests remain separate.

The first proof launch mistakenly omitted the manager namespace restriction.
It exited normally and its log/CAS were retained. The test now requires
`OSKAL_POLICY_CONTROLLER_NAMESPACE` before launching and passes it as
`--namespace`. Inspection of all 22 owned AssuranceState/ControlBinding objects
with managed fields showed a latest managed-field time of
2026-11-13T09:47:52Z, before the first launch at 2026-11-13T10:48:37Z; all condition
transition times also preceded launch. No AS/CB updates from that launch were
observed, and its CAS contained no control receipt directory. This inspection
is reported at that strength, without claiming a collected API audit trail.

Private reproducible evidence was retained outside Git:

- `/private/tmp/oskal-p1-policy-controller-manager-live-final.log`
- `/private/tmp/oskal-p1-policy-controller-evidence/final-namespaced/TestRealManagerPolicyCapture`
- `/private/tmp/oskal-p1-policy-controller-manager-live.log` (first launch)
- `/private/tmp/oskal-p1-policy-controller-evidence/first-launch-side-effect-inspection.json`
- `/private/tmp/oskal-p1-policy-controller-race-final.log`
- `/private/tmp/oskal-p1-policy-controller-lint-final.log`

No engine resources, VM settings, release artifacts, remote branches, or
production services were modified by this manager proof. The test manager
processes drained and exited; the owned API and evidence remain available.


Subsequent native OPA-to-manager and live SPIFFE bundle-membership-change checks
are recorded in [the final live verification](p1-policy-final-live-verification.md).
They supersede the corresponding unverified integration boundaries of the earlier
report-manager proof while retaining its original measured scope and failures.
Primary SPIRE CA rotation remains unverified.
