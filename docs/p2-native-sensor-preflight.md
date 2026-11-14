# Native sensor proof: retained preflight blocker

Status: **BLOCKED before Kubernetes and Tetragon startup**. No native BPF zero,
failed-map-read, minimum-capability, counter-reset, saturation, or signed sensor
receipt acceptance is claimed by this experiment.

The authorized scope was a fresh, owned Kind cluster on the current Colima
context. Shared VM sysctl changes and stopping unrelated infrastructure were not
authorized. No such changes were made.

## Inputs checked

- Docker context: `colima`, 4 CPUs, 8,309,010,432 bytes memory.
- Kind: installed v0.33.0. Its
  [official release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)
  identifies the default Kubernetes image as
  `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`.
  The registry's arm64 manifest is
  `sha256:6a3345f517a7df05185c648f83d18d464f2a94ea4a69eaee39b7e1de02611e59`.
- Local kubectl: v1.37.2, Helm: v3.22.1. Every Kubernetes operation was scoped to
  the private kubeconfig path; the ambient remote context was not used.
- Retained official Tetragon 1.8.0 chart SHA-256:
  `38a10bca4bffd3efac7cbcc7f99b24dbcd3ef76402aa7bbb72c0b2e2dc0c8111`.
  Its registry arm64 image manifest was verified as
  `sha256:616ca090f812513508eb1b91e7867a01642ea61ac8a0071536455c0b550ac3eb`.
  Tetragon was not installed because the node never started.

## Actual failure and causal experiment

The following command exited 1 with `--retain`:

```text
kind create cluster --name oskal-p2-native-20261113
  --kubeconfig /private/tmp/oskal-p2-native-proof/kubeconfig
  --config /private/tmp/oskal-p2-native-proof/kind.yaml
  --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
  --wait 90s --retain
```

The invocation used the scoped environment variable
`KIND_EXPERIMENTAL_DOCKER_NETWORK=oskal-p2-native-network`. The Kind source and
actual CLI warn that custom-network overriding is experimental. The retained
node received limits of 2 CPUs, 3 GiB memory with no additional swap, and 2,048
PIDs. It was not OOM-killed. Its systemd 257.13 process exited 255 after reporting:

```text
Failed to create control group inotify object: Too many open files
Failed to allocate manager object: Too many open files
```

`tests/runtime/nativepreflight` is a small Linux Go executable that reads only
its own process and public kernel limits, attempts one actual `inotify_init1`,
and immediately closes the descriptor if allocation succeeds. It does not
change limits, inspect other processes, mount filesystems, or create BPF objects.

Cross-compilation alone was followed by actual execution in a dedicated Linux
arm64 container, based on the same pinned Kind image, with a read-only root,
no network, all capabilities dropped, 0.25 CPU, 64 MiB, and 32 PIDs. At
`2026-11-14T00:11:52.042814636Z`, it observed:

| Measurement | Actual result |
| --- | --- |
| Kernel | `6.8.0-100-generic`, arm64 |
| Effective UID | 0 |
| Open descriptors | 7 |
| Process soft descriptor limit | 524,287 |
| `fs.inotify.max_user_instances` | 128 |
| `inotify_init1(IN_CLOEXEC|IN_NONBLOCK)` | `EMFILE`: too many open files |
| Executable exit | 1 |

This rules out the diagnostic process exhausting its ordinary descriptor limit.
Linux v6.8's
[inotify allocation path](https://github.com/torvalds/linux/blob/v6.8/fs/notify/inotify/inotify_user.c#L680)
returns `EMFILE` when the per-user/user-namespace instance count cannot increase.
Shared inotify-instance quota exhaustion is therefore the supported causal
inference. The exact number of distinct instances held by other processes was
not enumerated, and the failed systemd process's own live descriptor table was
not available after exit. No exact unrelated-process usage count is claimed.

## Retained state and next gate

The failed node is `oskal-p2-native-20261113-control-plane` on the dedicated
`oskal-p2-native-network`; it remains stopped. The planned private kubeconfig is
`/private/tmp/oskal-p2-native-proof/kubeconfig`. It is not a ready cluster.
There is no sensor Pod UID, sensor PID, BPF root enrollment, or native input file.

Private artifacts under `/private/tmp/oskal-p2-native-proof` include
`kind-create.log`, `node-boot.log`, `node-inspect.json`, `network-inspect.json`,
`preflight-limits.log`, and `inotify-proof-2.log`. The directory is mode 0700;
evidence files are mode 0600, and the diagnostic executable is mode 0700.
Failed diagnostic transport/build attempts were also retained: Colima did not
share the host's `/private/tmp` bind path, and its legacy Docker builder did not
support `COPY --chmod`. The final image copied the already-executable binary
before starting a read-only runtime; no global installation was performed.

Native sensor acceptance remains blocked until the owner authorizes a suitable
environment change or provides an independently available environment. The agent
must not raise the shared inotify limit or stop unrelated containers on its own.

## Prepared read-only native helper

`tests/runtime/nativehealth` provides three Linux-only modes for the next
authorized experiment. `credentials` measures the current locked OS thread.
`inventory` reads the actual kernel, sensor PID start ticks and cgroup, and the
IDs and ABI metadata of the seven pinned Tetragon health maps using read-only
descriptors. It emits a `candidateEnrollment`; the digest identifies those
observations with the digest field empty during hashing. It does not authenticate
the candidate or grant permission to use it.

`read` accepts a bounded private JSON file containing externally authorized
`enrollment` and `grant` values, rejects ambiguous JSON through the shared strict
decoder, and invokes the production `ReadWitness` with a five-second deadline.
The enclosing operator must authenticate and authorize that input before calling
the helper. No signature or external authority is invented by the local CLI.
Errors retain the returned UNKNOWN witness in machine-readable output and exit 1.
The helper creates no maps, programs, grants, mounts, or counters and does not
change process capabilities or namespaces.

The actual Linux arm64 build and Linux-target lint passed. Native BPF inventory
and witness execution remain unperformed because the retained node could not
start. Compilation is not native sensor proof. The prepared binary is
`/private/tmp/oskal-p2-native-proof/nativehealth`; it must not be used against an
unrelated or production node to bypass the pending environment authorization.
