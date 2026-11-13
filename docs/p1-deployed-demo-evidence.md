# Phase 1 deployed demo evidence

Observed locally on 2026-11-13. The complete `make demo` command passed with a
fresh Kind cluster, a deployed OSKAL controller and real Tetragon 1.8.0 process
events. No reconciliation method was called manually.

## Successful execution

Controller and CLI source was a clean detached worktree at
`543b05dddc32c9eaf38c70e439fabb51729ce8ae`. The Go demo runner was the resulting
`cmd/demo` implementation in this change. The successful command was:

```sh
GOMAXPROCS=2 make demo \
  DEMO_SOURCE=/private/tmp/oskal-demo-source-543b05d \
  DEMO_TETRAGON_CHART=/private/tmp/oskal-p1-runtime-evidence/tetragon-1.8.0.tgz
```

The observed node was Linux ARM64, running Kubernetes v1.37.0. The runtime image
was built from host cross-compiled binaries and a minimal Docker context, using
the observed primary-registry distroless base digest. The actual exported OCI
index, platform manifest, configuration and every compressed layer were hashed
before importing that archive. The configuration digest matched the actual CRI
lookup under an explicitly registered immutable manifest alias. Kubernetes
reported the same verified graph's index digest as the running image ID.

The demo installed all six OSKAL CRDs, an explicit namespace AssurancePolicy,
one nonroot workload, a current-process evidence contract, and a ControlBinding.
The policy required fresh Assured standing, treated missing evidence as Unknown,
and explicitly disabled admission enforcement. The source configuration selected
Tetragon mTLS with explicit roots, client identity and server name.

The deployed execution path was:

```text
real Tetragon process event over mTLS
-> current Kubernetes workload UID/spec and binding/policy resolution
-> signed source-session evidence and filesystem CAS
-> strict evidence evaluation
-> deployed controller publishes ASSURED, verified 1/1 and nonempty root
-> signed immutable control receipt
-> owned Tetragon DaemonSet receives an unschedulable node selector
-> owned source Pods disappear
-> deployed controller publishes UNKNOWN, verified 0/1 and empty root
-> new signed immutable control receipt
```

The source-loss transition took exactly `3.014592917s`. The complete acceptance
execution took `1m26.568509s`, from `2026-11-13T10:03:19.284537Z` to
`2026-11-13T10:04:45.853223Z`. That duration excludes subsequent diagnostic
collection and the initial `go run` compilation. `make` returned exit 0.

Each receipt was verified with the actual CLI both inside the deployed
container and on the host. The trusted public key was generated and pinned on
the host before Pod creation. Only the individual receipt was copied from the
owned Kind node's inspected kubelet volume path. Private signing keys were never
copied from that volume. Receipt body SHA-256 equaled the published reference:

| Standing | Immutable receipt |
| --- | --- |
| ASSURED | `rcpt-9dad178f057f509fb28cfe26a30852bcab86f48657ed8dcb891f7a497978a6ea` |
| UNKNOWN | `rcpt-b1e82640a59083bc95dad1a9d0f8da5dcd5177c94b7a407f3d5692b0ba370d23` |

The demo checked the signed subject UID, current Pod specification digest,
control, evaluator, complete epoch, evaluation time, state and evidence root
against the actual AssuranceState. Altering either receipt's root was rejected
by the same actual CLI verification path. The controller retained its Pod UID
and restart count during the transition.

## Earlier failed attempts

All failures and their evidence remain retained. Each was followed by causal
inspection before changing the demo. Failed owned cluster containers were
stopped, not deleted. The controller source remained fixed throughout.

| Attempt | Execution duration | Exit | Observed cause and correction |
| --- | --- | --- | --- |
| 1 | `1m57.207143542s` | 2 | Docker's image ID identified an OCI manifest; CRI's image ID identified its configuration. The corrected path hashes the actual exported configuration and preserves the typed OCI graph. |
| 2 | `2m12.580892375s` | 2 | CRI's synthetic import repository digest did not resolve as the qualified name Kubernetes used. An explicit owned immutable manifest alias is now registered and verified through CRI before deployment. |
| 3 | `1m22.625127667s` | 2 | Kubernetes reported the verified OCI index digest at the final running-image check. That check now recognizes the cryptographically associated index, manifest and configuration instead of conflating their types. |

Attempt 1's outer console duration was `1m57.432236292s`, including its diagnostic
window; its failure record measured the execution window in the table. The final
implementation records and prints one canonical execution duration before
diagnostics. Attempt 3 independently reached ASSURED, but its failed command is
not counted as successful acceptance. Attempt 4 ran the full corrected command
without intervention or a resume path.

## Retained evidence and scope

Successful cluster: `oskal-deployed-1794564199285080000`. It remains running with
the Tetragon source stopped. The prior owned runtime cluster and failed demo
cluster containers remain stopped. Unrelated clusters and infrastructure were
not modified.

Successful artifacts and explicit kubeconfig:

```text
/private/var/folders/c2/hd1nq7p54lq4_3wys4p9ymp40000gn/T/oskal-deployed-demo-1257714432
```

Complete command outputs:

```text
/private/tmp/oskal-deployed-proof-20261113-543b05d-attempt1.log
/private/tmp/oskal-deployed-proof-20261113-543b05d-attempt2.log
/private/tmp/oskal-deployed-proof-20261113-543b05d-attempt3.log
/private/tmp/oskal-deployed-proof-20261113-543b05d-attempt4.log
```

The artifact directory is private and includes local test credentials; it is not
a public evidence bundle. Relevant records include `source.json`,
`built-image-identity.json`, `controller-running.json`, `before.json`, `after.json`,
the individual receipt files, host/container CLI output, tamper rejections and
`result.json`. Archived image bytes contain only the public runtime base and the
built binaries. They do not contain checkout files or test keys.

This demonstrates bounded local deployed behavior and local Ed25519 receipt
verification. It does not establish production trust, SPIFFE source authority,
hardware attestation, admission enforcement, complete process coverage, or
native support for architectures other than the observed Linux ARM64 node.
