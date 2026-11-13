# Phase 1 policy-engine ingestion

Observed on 2026-11-13. These adapters ingest engine observations; they do not
turn an engine's `pass`, `allow`, or zero violations into a global compliance
claim. Controller watchers, authenticated HTTP admission and claim mapping are
separate application integration boundaries.

## Published source contracts

Primary releases were checked before installing:

| Engine/API | Version | Contract |
| --- | --- | --- |
| Kyverno | [1.20.0](https://github.com/kyverno/kyverno/releases/tag/v1.20.0), chart 3.10.0 | [PolicyReport results](https://kyverno.io/docs/guides/reports/) |
| OpenReports reports-api | [0.2.1](https://github.com/openreports/reports-api/releases/tag/v0.2.1) | [Report API fields](https://github.com/openreports/reports-api/blob/v0.2.1/apis/openreports.io/v1alpha1/report_types.go) |
| Gatekeeper | [3.23.1](https://github.com/open-policy-agent/gatekeeper/releases/tag/v3.23.1), chart 3.23.1 | [Constraint audit status](https://open-policy-agent.github.io/gatekeeper/website/docs/audit/) |
| OPA | [1.22.4](https://github.com/open-policy-agent/opa/releases/tag/v1.22.4) | [Decision-log service](https://www.openpolicyagent.org/docs/management-decision-logs) |

Kyverno's actual optional OpenReports output was tested with the OpenReports CRDs
bundled by its chart. The old local `OpenReport.spec.subject/spec.findings` model
was not an upstream API and has been removed along with its only test caller.

## Adapter contracts and limits

`policyreports.Decode(rawJSON, producer)` accepts only:

- `wgpolicyk8s.io/v1alpha2`: `PolicyReport`, `ClusterPolicyReport`.
- `openreports.io/v1alpha1`: `Report`, `ClusterReport`.

The decoder returns `[]Capture`, each containing an `Event` for
`ports.CapturedEventWriter` and a decoded `Record`. It preserves concrete subject
UID, report UID/resourceVersion, source/policy/rule/result, properties and the
upstream `{seconds,nanos}` timestamp. It uses the oldest result timestamp per
subject. Empty results, missing timestamps/UIDs, unsupported versions and
selector-only identities return errors. Snapshot size, result count and subject
fan-out are bounded. Summary counts do not synthesize result facts.

`gatekeeper.DecodeConstraint(rawJSON, producer)` accepts the actual
`constraints.gatekeeper.sh/v1beta1` object and its `status.auditTimestamp`,
`totalViolations` and capped `violations`. Its event is bound to the constraint
UID, not the names in violations: those entries have no workload UID. Metadata
preserves total/listed counts, truncation, and UNKNOWN workload identity and
audited policy revision. Zero violations remain an audit observation.

Both standard report APIs lack a universal authenticated policy revision field.
Their decoded facts and persisted metadata explicitly retain revision UNKNOWN;
the current policy name or generation is never substituted for the evaluated
revision. Arbitrary properties survive without being interpreted as authority.

`opa.NewDecoder(Config)` requires an exact decision path, named bundle, explicit
distinct JSON boolean allow/deny mappings, and producer identity supplied by the
authenticated caller. `DecodeBatch(io.Reader)` accepts the actual gzip-compressed
JSON array; `Ingest(ctx, reader, writer)` also writes validated events. Limits:
1 MiB compressed, 4 MiB expanded, 128 decisions, and 32 JSON nesting levels.
Duplicate object keys are rejected so masked input cannot be hidden behind a
later duplicate field. The whole batch is validated before any write.

Only `input.subject.{apiVersion,kind,namespace,name,uid}` is retained. Additional
input fields, query data, request headers and nondeterministic caches are rejected
before persistence. OPA must mask input at its source; actual source masking was
verified. Standard typed client-address metadata (`requested_by`) is retained:
OPA's masking API supports only `/input`, `/result` and `/nd_builtin_cache`, and
rejects `/requested_by` masking. Labels are limited to `app`, `id`, `version`.
The configured bundle revision must be present, but its presence is not signature
or policy-admission proof. A non-boolean result is rejected rather than coerced.

All events are observations: `policy.report.snapshot`,
`policy.gatekeeper.audit.observed`, or `policy.opa.decision.{allow,deny}.observed`.
The CAS payload is explicitly an OSKAL capture record, not a replacement upstream
API. Its `sourceBytes` field preserves the original source JSON bytes using JSON
base64 encoding, alongside normalized metadata and result facts. This makes
revision gaps and truncation durable without rewriting the source object.

## Actual execution evidence

Only the owned Kind cluster `oskal-p1-runtime-20261112` and explicit kubeconfig
were used. Kyverno and Gatekeeper had separate owned installation namespaces;
the test policy matched ConfigMaps only in `oskal-policy-test`. Real ConfigMaps
with and without a `team` label generated pass/fail reports. Gatekeeper audit used
`constraintViolationsLimit=1`, producing two total violations and one listed.

Actual engine → actual source API/log → decoder → live resource UID/creation-time
check → subject epoch → filesystem CAS → payload digest verification passed:

| Source | Sample persisted capture SHA-256 |
| --- | --- |
| Kyverno PolicyReport | `098814a7b4f615d6862f3ae9007192ff232738d70160e07aa713f0b75b38daf5` |
| Actual Kyverno OpenReports | `de5f50201064079d271e203b91620097b37570631b1e7102ddf8a9a76ab6b3b3` |
| Gatekeeper audit, truncated | `56ea16a385135657e69c59e27bcf91e87cac204f1ce2e31189948dfc1cd7a656` |
| OPA allow | `b6f5ad97bb0fd6ad39f3cbad67779bb6b9d81b3965d1b4bb20edb817cc7b567c` |
| OPA deny | `46e4844550f9ef07eb70767a701508b20de7cff13d2edb0c0e294c4525e667d8` |

An independent filesystem SHA-256 pass verified all fourteen retained payloads:
three standard reports, six OpenReports, one Gatekeeper audit, and four OPA
decisions from two actual runs. The ingestion writer's CAS verification also ran
for each test capture. The separate coverage contract remained UNKNOWN.

The OPA test launched the official Darwin ARM64 binary 1.22.4, verified against
the release asset digest
`e6dfa065844e3a1553d665ccc4a2c0a25d1ca3925f6ed8fbaf0fa1ec2060d2a5`.
OPA itself loaded a built bundle named `oskal` with revision `oskal-policy-v1`,
answered real allow/deny queries, and uploaded its gzip batch over TLS 1.3 with a
client certificate. The receiver validated the exact client URI
`spiffe://oskal-policy-test/opa`. Input selected for masking was absent from the
stored source bytes. Controlled mutations of real captured decisions were
rejected for unmasked input, missing revision, wrong path and wrong result type.
Real report mutations were rejected for missing UID/timestamp, wrong API and
empty results; the live resolver rejected a stale UID.

## Reproduction and acceptance boundary

Live tests require `OSKAL_POLICY_KUBECONFIG` and the caller-managed engine
resources from the retained manifests. `OSKAL_POLICY_EVIDENCE_DIR` retains CAS.

```sh
go test -race -count=1 -run '^TestLivePolicyReportCapture$' -v ./tests/integration
# Add OSKAL_POLICY_OPENREPORTS=1 for real reports.openreports.io output.
go test -race -count=1 -run '^TestLiveGatekeeperAuditCapture$' -v ./tests/integration
go test -race -count=1 -run '^TestLiveOPADecisionCapture$' -v ./tests/integration
```

OPA additionally requires `OSKAL_POLICY_OPA_BINARY`, `OSKAL_POLICY_TLS_CA`,
`OSKAL_POLICY_TLS_{SERVER_CERT,SERVER_KEY,CLIENT_CERT,CLIENT_KEY}`. The OPA test uses
only a loopback evaluation API; the log/bundle service requires mutual TLS and
the exact test client identity. Production receiver transport belongs to the
application integration and is not proven by the test receiver alone.

Retained logs, manifests, original report snapshots and CAS reside under
`/private/tmp/oskal-p1-policy-evidence`. It also contains local test private keys;
do not publish or commit that directory. Installed engine identities and output
were real; no mocked engine or Kubernetes backend was used.

`go build ./...`, scoped policy-adapter/integration lint, focused uncached race
tests, the actual live tests above and `git diff --check` passed. A full uncached
race run passed all packages except the existing parent-owned
`TestControllerReconciliationHarness`, whose Ready=True expectation conflicts
with the controller's real-source UNKNOWN gate. This branch does not change that
harness or claim the whole-repository gate passed.

The optional Kyverno OpenReports Helm upgrade timed out with failed readiness
and client connection loss even though its new admission/reports pods emitted
the actual OpenReports captured above. The failed Helm result is retained in
`kyverno-openreports-upgrade.log`; successful report decoding is not successful
rollout proof. Saved last termination states were `Completed`/exit 0, not evidence
of OOM. API timeouts and heavy shared 8 GiB VM usage were observed. Only owned
test deployment scale-down followed, with initial request failures and partial
outcomes retained. Final API reads confirmed Gatekeeper audit and Kyverno
background/cleanup/reports desired replicas zero; each admission controller stays
at one to keep installed fail-closed webhooks available. No VM setting or
unrelated resource was changed.

This establishes functioning decoder/storage paths for the tested engines and
formats. It does not establish continuous report coverage, production receiver
authorization, current policy admission, signed decisions, or a deployed OSKAL
watcher/claim integration.
