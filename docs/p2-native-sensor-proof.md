# Native Tetragon witness observations

These are actual Linux kernel measurements from an owned Kind cluster, not a
hardware attestation, complete telemetry claim, or production acceptance.

The user explicitly authorized temporarily changing Colima's shared
`fs.inotify.max_user_instances` from 128 to 1024 and restoring 128 after stopping
the owned test node. The value was checked as 128 before the change at
`2026-11-14T01:08:19.748008Z`; the write and confirming read succeeded. Restoration
was completed after the final owned node stopped: the value was rechecked as
1024, restored to 128 with exit 0 at `2026-11-14T02:26:47.852518Z`, and independently
read back as 128. The original failed node and all later nodes remain retained.

## Profile b source identity (now stopped)

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
source and maps must be rechecked before later use. A signed end-to-end receipt
and initial healthy full-window acceptance remain separate gates. The later
experiments below extend this native evidence. The shared Colima kernel is not
an isolated hardware trust boundary.

## Process-local enforcement experiments

The Go `nativefilter` helper emits an arm64 classic-BPF filter for the installed
`setpriv` loader. The read profile permits only `BPF_OBJ_GET`,
`BPF_MAP_LOOKUP_ELEM`, `BPF_MAP_GET_NEXT_KEY`, and `BPF_OBJ_GET_INFO_BY_FD` among
BPF commands. Other system calls remain allowed; this is not a complete
production seccomp profile. The filter checks the architecture.

With UID 0, all capabilities zero, NoNewPrivs 1, and this actual seccomp mode-2
filter, the witness read all 1,792 loss cells as zero in 3.795 ms. A second
process with the same grant and credentials but a deny-BPF filter returned
UNKNOWN and `open read-only tg_stats_map: operation not permitted`, exit 1,
without loss values. The test did not attempt map writes.

The separate `credential-transition` mode first obtained an actual OBSERVED
witness using the original root grant, then changed only its disposable process
to UID/GID 65532. Its next request using the unchanged old grant returned UNKNOWN
with `operation-time credentials differ from read grant`, exit 1. The actual
after-transition credentials were UID/FSUID 65532 and effective capabilities zero.
This proves rechecking after a process-identity change, not prevention of an
arbitrary credential race inside a kernel syscall.

Evidence: `witness-seccomp-readonly.json`, `witness-seccomp-deny.json`,
`security-seccomp-readonly.log`, and `witness-credential-transition.json`.
UID 0 still has access to root-owned files and sockets without capabilities;
these results do not establish minimal overall authority or a production sandbox.

## Bounded workload results

The Go `nativeflood` workload executes only `/bin/true`, with 64 workers and a
30-second context deadline. Its owned Pod has a 2 CPU/128 MiB limit, no service
account token, no capabilities, a read-only root, and no privilege escalation.
The binary bounds duration and fan-out; the container runtime enforces CPU/RAM.
It never writes counters, disconnects collectors, or changes sensor buffers.

Profile b used the default queue. It completed 63,750 executions with zero
workload errors from `01:39:27.138379062Z` through `01:39:57.147612874Z`.
Kernel, observer-ring, observer-queue, and map-error loss deltas were zero.
Actual positive loss was **NOT_DEMONSTRATED** within that authorized budget.

The root agent then authorized a distinct, explicitly **loss-sensitive demo**
profile c. The previous node was stopped and retained. Profile c uses the
vendor's Kind `/proc` to `/procHost` mapping, with the mount read-only, and
Tetragon's documented `rb-queue-size=4`; kernel ring settings were unchanged.
This is not a production default or performance recommendation.

Profile c's source was `oskal-p2-native/tetragon-pdq56`, Pod UID
`8c52ec7e-ff4d-43cf-91d3-d07a3e1bb662`, PID 3681, start ticks 24604703, on
`oskal-p2-native-20261113-c-control-plane`. Map IDs were 18163 (kernel stats),
18157/18159 (exec/map stats), 18158/18160 (joined/map stats), and 18171/18170
(rate options/rates). These identities stayed unchanged across the workload.

Profile c completed 66,640 executions with zero errors from
`2026-11-14T02:04:38.875132435Z` through `02:05:08.876923216Z`.
Its live cgroup showed `cpu.max=200000 100000`, `memory.max=134217728`,
`memory.current=9883648`, and `pids.current=37` at `02:04:53.979534Z`.
This memory sample is not a peak-memory measurement.

`tetragon_observer_ringbuf_queue_events_lost_total` increased from 3 to 19,887:
**19,884 upstream observer-queue record drops**. The upstream implementation
increments it when its real channel is full and a received record is dropped.
Kernel-loss cells, perf/ring errors, and map errors remained zero, with no active
throttle. Families are not summed into a unique-event count; the metric does not
attribute every dropped record to this workload.

Full-window assurance was already UNKNOWN due to terminal pod metadata failures.
This does not demonstrate a PASS-to-UNKNOWN transition. Raw before/after metrics,
witnesses, workload output, runtime limits, and source identities remain under
`profile-c/`; `native-evidence-manifest.json` records artifact digests.

## Attribution blocker and final verdict

The proper host-proc mapping did not eliminate terminal `pod_info` failures.
No metric was stripped or relabeled to obtain a passing window. A read-only
preflight of the official CRI/cgidmap alternative found that the actual Kind CRI
cgroup path exists under the node's `/sys/fs/cgroup` and is absent under
`/procHost/1/root/sys/fs/cgroup`. The v1.8 resolver joins the CRI path with that
latter VM-host root. Failed mapping can leave container identity empty, so reduced
metadata-failure counts would not establish correct attribution.

The CRI/cgidmap Helm change was **not applied**. No custom remapping, upstream
fork, counter reset, scope relaxation, or additional flood was attempted. Native
primitives and actual upstream queue loss are demonstrated; initial healthy
complete-window acceptance remains **PARTIALLY VERIFIED / NOT MET**.

## Final cleanup

Only the owned profile-c node was stopped. The stop command exited 0; the node
exited 137 after the 30-second stop deadline at `02:26:47.209597496Z`, with PID 0,
Running false, and OOMKilled false. This is not a graceful-shutdown claim. Its
Kubernetes API was unavailable afterward, exit 1. The shared inotify setting was
then restored and read back as 128. Fourteen non-OSKAL container states matched
immediately before and after this cleanup.

`inotify-restoration.json` records values, timestamps, command results, node state,
API check, and the container-state comparison. Nodes, volumes, kubeconfigs, logs,
and proof files remain retained. The profile-c kubeconfig is
`/private/tmp/oskal-p2-native-proof/kubeconfig-c` and references the stopped cluster.
