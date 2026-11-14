# Tetragon visibility measurements

This adapter measures facts for the Tetragon **v1.8.0** contract. It does not sign
evidence, decide admission, calculate window deltas, assign control standing, or
declare complete kernel visibility. Those operations belong to the consuming
application. `OBSERVED` means a specific measurement succeeded; it does not mean
that an authority, configuration, source identity, or control was verified.

## Portable metrics reader

`MetricsReader.Read(ctx)` uses a new connection to an explicit numeric loopback
HTTP address at `/metrics`, with no proxy, redirect, compression, or connection
reuse. Both request and response are bounded by a deadline of at most five
seconds. Only Prometheus text version 0.0.4 is accepted. Deployment must bind that
network namespace to the enrolled sensor; loopback alone does not authenticate a
producer. The reader does not expose port 2112 or change sensor configuration.

`ParseMetrics(reader, limits)` hashes the original bounded body and preserves
each known family, its actual upstream TYPE, sorted labels, and exact integer
values. Unknown families consume the global byte, line, and sample budgets but
do not introduce new output labels. Limits may be reduced, never increased above
`DefaultLimits()`. Missing families remain `UNKNOWN`; no missing counter becomes
zero. Duplicate series or TYPE declarations, missing required labels, incorrect
TYPEs, timestamps, invalid label escapes, negative/fractional values, NaN,
infinities, uint64 overflow, unterminated input and exceeded limits invalidate
the sample. Exact integer scientific notation is supported with `math/big.Rat`.
Values above 2^53 retain their literal integer value but make their family
`UNKNOWN`: upstream float64 exposition cannot prove consecutive integer precision.

The fixed families include the observer's lost/read-error/queue/received counters,
listener overflow, BPF output misses, processed events, both monitored maps'
entries/capacities/errors, cgroup-rate transitions, missed program/link probes,
field-filter/handler/export failures, export rate limiting and missing process/cache information. Individual signals
are retained. They must not be summed into a unique lost-event total.
`tetragon_map_errors_{update,delete}_total` are upstream **gauges**.
Probe-family absence is `UNKNOWN`, including unsupported kernel/link collection.
Export metrics describe the JSON exporter and must not be represented as gRPC
delivery counts; their applicability requires the consuming path's configuration.

The upstream BPF missed-event collector emits only positive counters and silently
omits failed map opens/lookups. The HTTP endpoint's success therefore cannot
distinguish zero kernel output failures from a broken custom collector.

## Actual Linux kernel witness

`ReadWitness(ctx, enrollment, grant)` requires an authenticated, externally
authorized enrollment and role grant. A syntactically valid digest is not
authority. The caller must verify their issuer, signature, delegation, effective
policy, revocation and scope before supplying them. `grant.EnrollmentDigest`
binds that grant to the enrolled sensor generation. The adapter deliberately
does not label caller-supplied claims as cryptographically verified.

The role is exactly `tetragon.health.read`. Its current expiry, effective UID,
filesystem UID, effective capability set, user namespace and mount namespace are
checked on the locked OS thread immediately before and after BPF operations.
Credentials are read from `/proc/thread-self/status` and namespace links. An
expired grant or mismatch stops the measurement. No privilege escalation,
capability modification, namespace entry, map creation, mount, retry, or fallback
is performed. Native syscalls cannot be interrupted midway; the context is
checked around every operation and must expire within five seconds.

The adapter observes `/proc/sys/kernel/random/boot_id`, the enrolled sensor PID's
actual start ticks and cgroup, and the Pod UID component of its Kubernetes
cgroup. The identity is remeasured afterward. A bridge whose cgroup/proc view
hides these facts returns an error rather than trusting a supplied Pod UID.
The caller remains responsible for associating the enrolled map IDs with the
admitted sensor binary, loaded programs, pod image and configuration. Matching
an untrusted enrollment is not source authentication.

The explicit map root must be on bpffs and contain no symlink components. Maps
are opened with `BPF_F_RDONLY`, their actual IDs and ABI are compared against the
enrolled manifest, and all descriptors close at the end of the call. Pins are
reopened before completion to detect removal or replacement while an older
descriptor remained readable. A successful descriptor read does not silently
establish current pathname authority forever.

The v1.8.0 layouts are:

| Map | Layout |
| --- | --- |
| `tg_stats_map` | PERCPU_ARRAY, key uint32 zero, capacity 1, value `[256][7]uint64` = 14,336 bytes per possible CPU |
| `execve_map_stats`, `tg_execve_joined_info_map_stats` | PERCPU_ARRAY, key int32, capacity 3, int64 per CPU; keys 0=count, 1=update errors, 2=delete errors |
| `execve_map`, `tg_execve_joined_info_map` | Actual enrolled map ID/schema/capacity; statistics are measured separately |
| `cgroup_rate_options_map` | ARRAY, key uint32 zero, capacity 1, `{Events, Interval uint64}` = 16 bytes |
| `cgroup_rate_map` | PERCPU_HASH, key uint64 cgroup ID, capacity 32,768, `{Curr, Prev, Time, Rate, Throttled uint64}` = 40 bytes per CPU |

Loss-error indices are unknown, ENOENT, E2BIG, EBUSY, EINVAL, ENOSPC and EAGAIN.
All 256 by 7 values, including genuinely read zeros, are retained. Per-CPU
aggregation rejects overflow. Signed map-stat totals reject overflow and negative
totals. A map's absent `stats` field means those fields were not measured for
that map; it does not imply zero usage/errors.

The possible CPU layout is checked against both `ebpf.PossibleCPU()` and a fresh
bounded `/sys/devices/system/cpu/possible` read before and after the measurement.
The maximum accepted CPU count is 256. Sensor generations with a different map
ID, ABI, boot, process, credentials or CPU layout require explicit re-enrollment.

With enrolled throttling enabled, the reader requires actual active options,
reads the entire rate map twice within the admitted entry bound, rejects repeated
keys, disappearing entries, changed key sets and options, and preserves any
observed nonzero `Throttled` field. Enumeration is capped at 1,024 entries and
returns an error when a larger live map exceeds the bound. These observations
are not a history of throttling between polls; the application must also consume
the actual throttle transitions and loss counters.

With throttling declared disabled, this adapter returns throttle and overall
availability `UNKNOWN`. It has no implementation that verifies the complete
effective sensor configuration and loaded-program manifest. Missing rate maps,
zero metrics, or a boolean enrollment flag cannot close that gap. Successful
loss/map reads remain individual measured facts, not a healthy source verdict.

Non-Linux systems have no kernel backend: `ReadWitness` returns
`ErrUnavailable`, `UNKNOWN`, and no loss values. It does not run a substitute
sensor or produce hard-coded zero measurements.

## Sources and dependency identity

Primary source was read on 2026-11-13. Source bytes under the pinned tag were
hashed directly over HTTPS. These hashes identify the researched contract; they
do not attest the sensor actually running on a node.

| v1.8.0 source | SHA-256 |
| --- | --- |
| [bpf/lib/process.h](https://github.com/cilium/tetragon/blob/v1.8.0/bpf/lib/process.h) | `e6776d310d96e6bc50963b00c70112bf69404aba449c277f691c414e2562bfb2` |
| [pkg/api/processapi/processapi.go](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/api/processapi/processapi.go) | `5a73e2c36b0d07ace41fe8f144131f50f273623e9132cdfe43aedeeffe520db2` |
| [bpf/process/bpf_rate.h](https://github.com/cilium/tetragon/blob/v1.8.0/bpf/process/bpf_rate.h) | `8874bbdbb15dba6931d4d22f512a94cfc407b9c5a77eb6055f27a11202ff4a23` |
| [pkg/observer/observer_stats.go](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/observer/observer_stats.go) | `0822e3bbec19a989b17492c86801cdff702ca649ab1339f364009347c88dca60` |
| [pkg/metrics/eventmetrics/bpfcollector.go](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/metrics/eventmetrics/bpfcollector.go) | `965d1e73ad02789289c5470ed044ffd0f0637de34e03e2ff972097cdf00b69d3` |
| [pkg/observer/metrics.go](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/observer/metrics.go) | `1186008c464e21f2411f81146b92e497285216e10101d673d6062ae1977571ef` |
| [pkg/metrics/mapmetrics/mapmetrics.go](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/metrics/mapmetrics/mapmetrics.go) | `ef44476ddb8eaf2bbee5e9520301fcffc106e32dd7d3e77a5af75e3b95906b3d` |
| [pkg/metrics/cgroupratemetrics/cgroupratemetrics.go](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/metrics/cgroupratemetrics/cgroupratemetrics.go) | `c82674fb18e88deae166ce172febda406df151d33a5e5efe8c59f7c6339e0531` |

The existing dependency graph selected `github.com/cilium/ebpf v0.22.0`; adding a
direct import required its explicit root requirement and two checksum lines.
No selected version changed. `go mod download -json` identified tag origin
`e55144e17360b60cc4583229c35c2dbf0935b308`, module sum
`h1:v2ktp0roffpMOj2MMf3idtCQZOsAoC4BJbAJN+ke2bY=` and go.mod sum
`h1:CDzZbe2hC5JjlDC+CY3KFCzlYwN4gbxppYM+Z10bQt4=`.
[The upstream API](https://github.com/cilium/ebpf/tree/v0.22.0) provides read-only
pin options, map info/ID, exact per-CPU lookup and possible-CPU discovery.

Linux access requirements depend on the actual kernel, pin permissions, seccomp
and LSM. Reading existing pins differs from creating/loading programs; the
adapter does not assume CAP_SYS_ADMIN, CAP_BPF or CAP_PERFMON is necessary or
sufficient. Native minimum privilege and successful sensor-map reads remain
unverified until the real node preflight. See the kernel
[pinned-object permission path](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/inode.c)
and [BPF syscall implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c).

## Verification boundary

`go test -race ./internal/adapters/tetragonhealth` exercises real Prometheus
instrumentation exposed over a real local TCP server, exact parser boundaries,
and transport rejection/cancellation. These are exposition/parser checks. They
are not kernel loss measurements or evidence of a live Tetragon deployment.

Compile the actual Linux implementation without claiming runtime proof:

```sh
GOOS=linux GOARCH=arm64 go test -mod=readonly -c \
  -o /private/tmp/oskal-p2-health-linux-arm64.test ./internal/adapters/tetragonhealth
```

On the actual authorized Linux node, the native test requires an input file
containing `{"enrollment": ..., "grant": ...}` with externally authenticated
enrollment and current grant. The dedicated test reads the actual sensor maps;
it creates no fake map backend. Omitting `OSKAL_TETRAGON_HEALTH_NATIVE_INPUT`
explicitly skips that gate. A native run, successful zero reads, minimum
privileges, saturation and signed control receipt integration are still required
before claiming the Phase 2 runtime behavior.
Set `OSKAL_TETRAGON_HEALTH_EXPECT_ZERO=1` only for an actual fresh baseline whose
kernel output counters must all be zero; a nonzero real counter fails that gate.
