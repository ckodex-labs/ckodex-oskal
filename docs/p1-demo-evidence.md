# Kubernetes API evidence demo

The demo reads a real Kind node condition and reports UNKNOWN after its API evidence transport stops.

## Scope

`make demo` creates a fresh, uniquely named Kind cluster with its own kubeconfig,
installs the six OSKAL CRDs, and runs the existing ControlBinding reconciler locally
against the real API. It does not deploy the controller container. Its only control
asserts that the API reports the observed node Ready=True. This is not a cluster
security audit, an eBPF sensor, attestation, or signed evidence demonstration.

The demo explicitly reconciles two current observations. A stopped transport makes
no current evidence eligible; the historical CAS archive is retained separately.
Production controller repository ingestion does not yet implement this availability
contract. Expired stored evidence can produce STALE rather than UNKNOWN.

Prerequisites: Go matching go.mod, make, Docker, Kind and kubectl on PATH; a working
Docker Linux VM with sufficient resources. No tools are installed automatically.
The cluster and artifacts remain available for inspection. Cleanup is printed, not
executed. The user's kubeconfig and existing clusters are not modified.

## Observed execution

Checked 2026-11-12, committed base aee6d58, macOS arm64 with Colima.

Command: `make demo`. Final run exit code: **0**. Demo elapsed: **32.236s**.

```text
Scope: local OSKAL reconciler and CRDs; API evidence only, unsigned and not hardware-attested.
before: demo:api-node-ready = PASS (OSKAL control state ASSURED); Verified 1/1 requirements
Evidence transport stopped: Get "http://127.0.0.1:57728/api/v1/nodes": dial tcp 127.0.0.1:57728: connect: connection refused
after: demo:api-node-ready = UNKNOWN; Verified 0/1 requirements
Elapsed: 32.236s
```

Cluster: `oskal-demo-1794543123295091000`. Artifacts: local temporary directory
`oskal-demo-2259046886`, including node-response.json, before.json, after.json and
the content-addressed evidence archive. The raw Node JSON carries UID,
resourceVersion and node condition timestamps.

Two earlier runs failed before OSKAL started. Kind reported:

```text
ERROR: failed to create cluster: could not find a log line that matches "Reached target .*Multi-User System.*|detected cgroup v1"
make: *** [demo] Error 1
```

Retained node logs established the cause:

```text
Failed to create control group inotify object: Too many open files
Failed to allocate manager object: Too many open files
Exiting PID 1...
```

The shared Colima VM had fs.inotify.max_user_instances=128. With explicit operator
approval it was temporarily raised to 1024 for the successful fresh-cluster run,
then restored to 128. This is not proof of an unprepared clean-machine run or of
the production controller's behavior after a runtime sensor stops.

## Tool versions checked

| Tool | Installed/used | Primary source checked |
| --- | --- | --- |
| Go | 1.27.3 | https://go.dev/dl/?mode=json (latest 1.27.4) |
| Kind | 0.33.0 | https://github.com/kubernetes-sigs/kind/releases/latest (0.33.0) |
| kubectl | 1.37.2 | https://kubernetes.io/releases/ (1.37 series) |
| Docker Engine | 29.2.1 | https://docs.docker.com/engine/release-notes/29/ (latest 29.9.3) |
| Colima | 0.10.3 | https://github.com/abiosoft/colima/releases/latest (0.10.3) |
| golangci-lint | 2.15.0 | https://github.com/golangci/golangci-lint/releases/latest (2.15.0) |

Kind troubleshooting recommends retaining failed nodes before exporting logs:
https://kind.sigs.k8s.io/docs/user/known-issues/ . Log export was attempted but
could not execute commands inside the exited node; docker logs supplied the cause.
