# Tetragon guest sampler

`New(Config)` validates the shared native enrollment, metrics endpoint and bounds,
explicit Unix gRPC target, outside grant key/path, source identity and namespace.
`Start(ctx)` authenticates the grant, checks actual credentials and socket DAC,
queries the real API version (exact v1.8.0), and starts one event receiver.
`Sample(ctx)` serializes reads and reauthenticates the file before actual HTTP
metrics and read-only BPF operations. `Close(ctx)` cancels and drains the receiver.
The caller owns the gRPC connection and must construct it for the actual enrolled
Unix socket without a custom remote dialer or hidden retry. No reconnect occurs.

The fixed DSSE type is `application/vnd.oskal.tetragon-read-grant.v1+json` and the
payload is `ReadGrant{RoleGrant: ...}`. Its inner digest must be empty. The outside
operator signs the exact enrollment digest, role, expiry and measured credential
scope. The sampler verifies the pinned Ed25519 key and strict JSON before setting
the native grant digest to the exact envelope hash. Files are regular, at most
64 KiB, not group/other writable, and opened without following a final symlink or
blocking on a FIFO. Each read checks identity/size again. Expiry is half-open and
at most five minutes away. The stream also expires at its initial grant deadline;
rotating the file does not silently extend that stream. The sampler never issues
a grant, changes capabilities or creates a trust root.

The event request uses two OR alternatives: the configured namespace, or node-wide
`PROCESS_THROTTLE`. This matches upstream v1.8 `filters.MatchOne`; filters inside
one alternative are ANDed. Aggregation and field filtering are absent. The outbox
holds at most 64 original protobuf-JSON events / 256 KiB, each at most 32 KiB.
Actual overflow, unsupported messages and RPC failures fence the stream; nothing
is silently dropped. Node throttle notifications remain original observations
and also increment a separate locally observed stream-notification counter.

Every sample includes one `application/vnd.oskal.tetragon-health.v1+json` payload,
at most 512 KiB, with the full parsed metrics, native witness, native enrollment,
exact signed grant and explicit scope caveats. Upstream families retain their
TYPE, labels, totals, map occupancy and throttle configuration. No metric total
is presented as a unique count of lost events. The health JSON uses the existing
native witness JSON shape, including flattened map enrollment fields; consumers
must use a compatible schema rather than the strict typed decoder's unsupported
anonymous-embedding profile. Grant and signed heartbeat decoding remain strict.

`RequiredSignals()` returns a sorted conservative profile of 1,817 IDs:

| IDs | Source semantics |
| --- | --- |
| `native.bpf.NNN.ERROR` | All 256 opcodes x 7 actual native output-failure cells |
| `native.map.NAME.update/delete` | Native cumulative per-map errors |
| `native.map.NAME.capacity` | Availability guard: actual full/unknown occupancy becomes UNKNOWN; never a cumulative occupancy counter |
| `native.throttle.active` | Availability guard: actual active/unknown throttle becomes UNKNOWN |
| `stream.throttle.events` | Count of notifications actually received by this stream |
| `metrics.FAMILY` | Each named failure family's sum across its labels, retained separately; raw labels remain in health evidence |
| `metrics.tetragon_cgroup_rate_total.type=TYPE` | Separate delete/lookup/update failure and throttle start/stop counters; normal checks, processing and deletes are only raw health facts |

Only a complete successful native witness establishes zero for sparse BPF/map
signals. Missing families, including probes, remain UNKNOWN. Cumulative counters retain their actual values and OBSERVED status, including
nonzero history. The first domain heartbeat establishes only an UNKNOWN baseline;
adjacent complete windows compare deltas. A positive delta makes that window
UNKNOWN, while unchanged history is not new loss. Active/full gauges remain
UNKNOWN independently. Each raw labeled series behind an aggregate is tracked
by a canonical name/label digest with bounded cardinality. Any decrease,
disappearance or manifest replacement fences the sampler even if its family's
sum increased. Label ordering does not change identity. Narrower applicability requires an
outside policy and evidence; this adapter does not infer it from missing data.

## Verified scope

Host race tests use actual Ed25519 signatures and actual files for wrong key,
role, enrollment, expiry, self-digest, cancellation, symlink, FIFO and byte bounds.
Normalization vectors are pure semantic tests, not synthetic runtime evidence.
Linux arm64 native tests use the real Tetragon API, metrics and enrolled BPF maps.
Linux amd64 and Windows builds also compile; non-Linux native use fails explicitly.

On the owned native node, the authorized host-only test issuer minted a three-minute
read grant for UID/FSUID 0, all capabilities dropped, under no-new-privileges. Its
private key remained on the protected host. Actual native sampling returned API
v1.8.0, 1,792 native cells, 1,817 counters, about 197 KiB of metrics and 184,251 bytes
of complete health evidence in the initial read. The corrected cumulative-window
run retained all 1,817 counters as OBSERVED. Its first window was baseline UNKNOWN;
the next was UNKNOWN from an actual increase of 25 terminal event-cache fetch
failures. Four original events were retained during one authorized Pod execution,
including `/bin/true` exec/exit. Health evidence was 186,783 bytes and the formatted
complete sample was 435,854 bytes. Native zero cells were read, not inferred from
the absent Prometheus BPF family. Both optional probe families were observed.

The native window check supplies an explicitly UNATTESTED domain test context;
it tests actual counter/time normalization into the pure window function, not
quote admission or control standing. Pure transition tests separately prove that
8,649 -> 8,649 is eligible while 8,649 -> 8,650 is UNKNOWN. A raw-series test
rejects 5+5 -> 4+9 even though the aggregate increased.

In upstream v1.8.0 [`eventcache.handleEvents`](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/eventcache/eventcache.go),
`fetch_failures_total` increments only after the configured retry budget is
exhausted. The event may still be notified with incomplete enrichment afterward.
Thus this is terminal process/parent/ancestor/Pod enrichment failure, not proof
that the whole event was dropped. The conservative profile retains it as a
required completeness signal and does not confuse it with recoverable retry
attempts or a unique count of lost events. Positive control standing and
hardware/co-residence assurance are not claimed.

Private runtime evidence is retained at
`/private/tmp/oskal-p2-sampler-window-operator/{actual-sample.json,native-sample.log}`.
The tagged host issuer requires explicit operator input/output environment values;
it is a separately invoked test harness, not a production self-authorization mode.
