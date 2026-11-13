# Deploying configured evidence sources

The chart mounts an operator's source configuration and credentials without
inventing a policy, publisher identity, or successful assessment.

`sources.configMapName` selects an existing ConfigMap in the release namespace.
Its `sources.configMapKey` (default `sources.json`) is mounted read-only at
`/etc/oskal/sources/sources.json` and passed to the controller's `--sources` flag.
The controller still validates the entire JSON configuration before opening its
archive, creating signing keys, or starting collection.

`sources.tlsSecrets` names existing Secrets, each mounted read-only at
`/etc/oskal/source-tls/<secret-name>`. Files use mode 0440 and the default Pod
group 65532. `sources.publicCAConfigMaps` mounts public roots read-only at
`/etc/oskal/source-ca/<configmap-name>`. Source JSON must use the actual mounted
paths. These mounts do not grant Kubernetes Secret API reads. Operators remain
responsible for credential issuance, rotation, and exact publisher/peer pins.

Admission stays enforcing by default. Rendering fails when admission is enabled
without a source ConfigMap. Capture-only or read-only deployments must explicitly
set `webhook.enabled=false`; this now passes `--enable-webhook=false` rather than
accidentally inheriting the binary's enabled default. A named ConfigMap alone
does not establish runtime authority: the controller separately rejects admission
with only CAPTURE sources. Policy capture never creates control standing.

`policyCapture.opaListeners` explicitly selects the OPA listener names and ports
exposed through a ClusterIP Service named `<release-fullname>-policy`. Each port
must match an actual `opa.listen` entry in source JSON. An empty list exposes
none. Schema/template validation rejects unsafe mount names, duplicate ports or
names, reserved controller ports, and ports outside 1..65535. Configure network
policy separately; the source listener always requires its explicit TLS/publisher
authentication. No external load balancer is created.

This chart does not provision a SPIRE Workload API socket or pass a controller
SPIFFE identity. Use the explicit controller Workload API flags with a deployment
that provides that socket for SPIFFE mode; selecting SPIFFE source JSON through
this chart alone fails closed. The chart path verified here uses PKI mode.

`reconcileNamespace` optionally bounds OSKAL resource reconciliation. The empty
default retains existing cluster-wide behavior. Source namespaces and opted-in
policy read grants remain separate, explicit configuration.

## Verification

Checked on 2026-11-13: latest Helm
[v4.3.2](https://github.com/helm/helm/releases/tag/v4.3.2) from the official GitHub
release API; the installed executable used below is v4.3.1+gc0d08d0. Latest Go
1.27.4 was checked at the [official download API](https://go.dev/dl/?mode=json);
the installed test toolchain is go1.27.3 darwin/arm64. No dependency upgrade was
needed for this chart change.

Actual commands:

```text
helm template capture deploy/helm/ckodex-oskal --namespace oskal-policy-test --set webhook.enabled=false --set sources.configMapName=capture-sources --set 'sources.tlsSecrets[0]=opa-ingress' --set 'sources.publicCAConfigMaps[0]=opa-roots' --set 'policyCapture.opaListeners[0].name=opa' --set 'policyCapture.opaListeners[0].port=9444'
exit 0

go test -count=1 -race ./cmd/oskal-controller -run 'TestChart|TestPolicyRBAC' -v
--- PASS: TestPolicyRBACRendersOnlyExplicitResourceGrants (0.22s)
--- PASS: TestChartMountsSourcesAndExplicitlyDisablesAdmission (0.52s)
PASS
ok github.com/ckodex-labs/ckodex-oskal/cmd/oskal-controller 2.595s
exit 0

helm lint deploy/helm/ckodex-oskal --set webhook.enabled=false --set sources.configMapName=capture-sources --set 'policyCapture.opaListeners[0].name=opa' --set 'policyCapture.opaListeners[0].port=9444'
==> Linting deploy/helm/ckodex-oskal
[INFO] Chart.yaml: icon is recommended
1 chart(s) linted, 0 chart(s) failed
exit 0
```

The Go tests decode actual Helm output as Kubernetes Deployments and Services,
check credential modes and mounts, exercise opt-in RBAC, and observe invalid
input rejection. This evidence proves chart rendering, not a deployed Helm
release, live Service delivery, credential rotation, or policy compliance.
