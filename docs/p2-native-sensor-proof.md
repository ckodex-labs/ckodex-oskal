# Native Tetragon witness observations

These are actual Linux kernel measurements from an owned Kind cluster, not a
hardware attestation, complete telemetry claim, or production acceptance.

The user explicitly authorized temporarily changing Colima's shared
`fs.inotify.max_user_instances` from 128 to 1024 and restoring 128 after stopping
the owned test node. The value was checked as 128 before the change at
`2026-11-14T01:08:19.748008Z`; the write and confirming read succeeded. Restoration
is still pending while the node remains available for root-agent integration.
The original failed node and its causal preflight evidence remain retained.

## Running source identity

| Field | Observed value |
| --- | --- |
| Kind cluster | `oskal-p2-native-20261113-b` |
| Node | `oskal-p2-native-20261113-b-control-plane` |
| Kubernetes | v1.37.0 |
| Kernel | `6.8.0-100-generic`, arm64 |
| Pod | `oskal-p2-native/tetragon-hlmdm` |
| Pod UID | `f84db5fb-c624-49b8-addb-5f32f093e54f` |
| Sensor PID in node namespace | 3806 |
| Process start ticks | 24348171 |
| Boot ID | `ae117bbe-c7d8-4ba5-b62e-f220eba8fd49` |
| BPF pin root | `/sys/fs/bpf/tetragon` |
| Tetragon image | `quay.io/cilium/tetragon@sha256:616ca090f812513508eb1b91e7867a01642ea61ac8a0071536455c0b550ac3eb` |

The node is limited to 2 CPUs, 3 GiB memory, and 2,048 PIDs; Tetragon has a 1 CPU,
1 GiB limit. The externally selected `cgroup-rate=1000000000,1s` configuration was
confirmed through the actual options map. No throttle transition is treated as
proof of lost events. The source exposes its Unix socket at
`/var/run/tetragon/tetragon.sock`, mode 0660, root-owned, and metrics at the
node-local `http://127.0.0.1:2112/metrics`.

## Runtime-discovered iterator defect and fix

The first actual enabled-throttle witness panicked, exit 2. `throttleEntries`
passed a typed nil `*uint64` to `ebpf.Map.NextKey`'s interface parameter. The
library consequently tried to marshal a non-nil interface containing a nil
pointer. The upstream v0.22.0 contract requires a nil interface for the first
key. The focused correction uses an initially nil interface and subsequent
concrete uint64 keys. No map, counter, or throttle policy was changed.

The full panic remains in `witness-panic.log`. After rebuilding and executing the
corrected helper, `ReadWitness` returned `OBSERVED` from
`2026-11-14T01:14:26.00225945Z` through `.005727803Z`: four possible CPUs, all
1,792 kernel-loss cells read as zero, and zero update/delete errors for both
monitored maps. Throttle options were actually read as 1,000,000,000 events per
1,000,000,000 ns, with 15 entries and no active throttled cgroups.

The existing native `TestWitnessNativeTetragon` was cross-compiled and then
actually executed inside this Linux node with `OSKAL_TETRAGON_HEALTH_EXPECT_ZERO=1`.
It passed with exit 0. Portable host race tests passed in 1.154 seconds, and
Linux-target lint reported zero issues. The native test at this stage did not
use the race detector; host race testing is not native race proof.

## Actual privilege and denial observations

A second successful witness used effective/filesystem UID 0, **zero effective,
permitted, inheritable, bounding, and ambient capabilities**, `NoNewPrivs=1`, and
seccomp mode 0. It returned `OBSERVED` with 1,792 zero loss cells in approximately
2.981 ms. Thus CAP_BPF, CAP_PERFMON, and CAP_SYS_ADMIN were not necessary for this
read of existing root-owned pins on this observed kernel/profile. This is not a
universal minimum-privilege claim or proof of a restrictive seccomp profile.

An otherwise scope-matching grant for UID 65532 with zero capabilities reached
the real map open and returned `UNKNOWN`, exit 1, with
`open read-only tg_stats_map: permission denied`. No loss values were invented.
The pins were unchanged at root ownership and mode 0600. Input documents were
separately owned by their executing test UID and kept mode 0600, so this denial
was at the BPF pin rather than the grant-file read.

The actual Prometheus sample omitted `tetragon_bpf_missed_events_total`, while
the native witness read genuine zero values. The sample also explicitly exposed
zero observer-ring and userspace-queue loss counters. Missing metrics alone were
not used to establish zero.

## Evidence and limits

Private evidence is under `/private/tmp/oskal-p2-native-proof`: the explicit
`kubeconfig`, `sensor-pod.json`, `sensor-container.json`, `inventory-root.json`,
`native-input-root.json`, `native-input-no-caps.json`, `native-input-nonroot.json`,
`witness-root-fixed.json`, `witness-no-caps-owned-input.json`,
`witness-nonroot.json`, `security-no-caps.log`, `metrics-baseline.txt`, and
`native-test-zero.log`. Node-side inputs are `/oskal-native-input-root.json`,
`/oskal-native-input-no-caps.json`, and `/oskal-native-input-nonroot.json`.

The operator supplied these test grants under the explicit task authority. Their
digests identify inputs; they are not signed production delegations. The current
source and maps must be rechecked before later use. A signed end-to-end receipt,
source replacement, restrictive seccomp, and positive loss under bounded flood
remain separate acceptance gates. The shared Colima kernel is not an isolated
hardware trust boundary.
