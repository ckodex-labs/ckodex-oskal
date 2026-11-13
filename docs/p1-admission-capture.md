# Admission capture records and durability

The webhook performs its existing built-in Go checks on declared core/v1 Pod
CREATE/UPDATE requests. It no longer hashes a sample CEL policy, invents a Pod
name/UID, assigns a production SPIFFE observer, or emits complete assurance epochs.
The retired `AdmissionObserver`/`GenerateAdmissionEvidence` APIs had no real
policy-observation backend and are removed. `cel.ComputePolicyDigest` now hashes
only a supplied policy's identity, generation and complete spec; that digest does
not establish installation, evaluation or enforcement.

## Recorded facts

A configured sink receives:

```go
type EvidenceSink func(context.Context, assurance.EvidenceEnvelope, []byte) error
```

The payload is a bounded `AdmissionCapture` JSON record containing the exact
received AdmissionReview bytes, request UID, observation time, effective mode,
actual check results and violations, the local policy decision, and separately
labelled declared object metadata. Raw bytes use JSON base64 encoding so their
original representation is preserved.

The envelope identifies an `admission-request`, not a Kubernetes workload.
`requestUID` is correlation metadata and is never used as a Pod UID. Object names,
UIDs and namespaces remain declarations from the request. A generateName request
without a supplied name stays UNRESOLVED; no suffix or object identity is invented.

The artifact URI and digest identify the actual capture payload bytes. The sole
epoch field is the digest of the actual request bytes; policy, implementation,
authority and environment epochs are unset. Control references are absent.
Signing, when configured by the sink, authenticates the observer's capture record.
It does not authenticate the Kubernetes API client or establish a live workload.

Limitations travel inside every record: declared identity, unverified API-client
identity, no workload-creation proof, no runtime privilege observation, no installed
CEL-policy proof, UNKNOWN control standing, and no proof of response delivery.
The policy decision is computed before persistence and response delivery. A capture
may survive a later persistence acknowledgement/deadline failure; it must not be
interpreted as evidence that the final admission response allowed the request.

## Enforcement and failure behavior

The non-root check evaluates declared runAsNonRoot defaults/overrides and explicit
runAsUser=0. The privilege check rejects explicit privileged=true,
allowPrivilegeEscalation=true, and additions of SYS_ADMIN, NET_ADMIN, SYS_PTRACE,
SYS_MODULE, DAC_OVERRIDE or NET_RAW. These checks cover regular, init and ephemeral
containers. Duplicate spellings of the same prohibited capability yield one
violation. Omitted escalation settings and capability drop lists are not validated
by this check, and the result does not establish runtime privileges.

Enforcing mode denies check violations. Audit and warn modes retain the adverse
check result while permitting the policy decision; warn also returns warnings.
A configured sink must persist the unchanged envelope and payload or return an
error. Any sink failure, panic, quota exhaustion or request deadline failure denies
the AdmissionReview in **every** mode. Response annotations report capture FAILED
and a bounded failure class, with no invented stored-artifact reference.

A nil sink selects policy-only operation: capture status is NOT_RECORDED and no
capture URI, digest or envelope ID is returned. Non-Pod and valid DELETE/CONNECT
requests remain outside the built-in check scope and are not archived, avoiding
collection of unrelated object content. Their annotations say NOT_APPLICABLE and
NOT_RECORDED. A configured sink requires an explicit bounded observer identity;
no identity fallback is generated.

## Bounds and hosting

Request bodies are capped at 4 MiB, capture payloads at 8 MiB, in-flight validations
at 16, JSON depth at 32, arrays at 256 elements and JSON items at 65,536. Duplicate
keys and excessive structure are rejected before typed Pod allocation. Total Pod
containers are capped at 256, declared identity/container names at 256 bytes and
capability names at 128 bytes, preventing violation-message amplification.

Each request passes a derived deadline to the sink (default five seconds, maximum
ten). Custom HTTP hosts must support response-controller read deadlines. Payload
storage adapters must honor that context; generic callbacks cannot be forcibly
interrupted if they ignore it. The server leaves bounded response time after the
work deadline. TLS credentials are explicit; startup validates them before starting
the shutdown waiter, and configured TLS uses a minimum of TLS 1.3.

The response annotation `capture-digest` is the payload digest, and `capture-uri`
is its CAS URI. The old misleading `admission-envelope-digest` and synthetic
`assurance-epoch` annotations are no longer emitted. `admission-envelope-id` is
issued only after a successful configured sink call.

## Verified component evidence

Actual TCP/TLS tests use real filesystem CAS, real Ed25519 signatures and exact
payload reads. They verify preserved input bytes/signature, request/object UID
separation, generated-name uncertainty, built-in checks for all container classes,
adverse audit/warn facts, and configured durability failures. An actual one-byte
archive budget denies in all modes; a real filesystem obstruction also denies.
An expired sink context produces no successful capture. Nil sinks produce no
artifact references, and a missing configured observer never acquires a default.

The dependent air-gap test now exercises actual local file/CAS bytes, receipt
cryptography and projection with UNKNOWN local-material standing. Its checksum and
tamper coverage remains; it no longer claims fabricated Kubernetes admission or
workload identity.

Focused race tests and lint cover webhook, CEL and air-gap packages. CLI/controller
sink wiring is a coordinated integration change owned separately; a full repository
build requires those callers to adopt the new signature. These component checks do
not establish Kubernetes API-server client authentication, actual workload creation,
live CEL enforcement, hardware attestation or Phase 2 capability.
