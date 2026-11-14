# Attested guest stream transport

This adapter hosts a real TLS 1.3 bidirectional gRPC stream around `guest.Session`.
It does not replace quote verification, source sampling, control evaluation or
persistent publication with transport status. One server owns one configured
source and one publisher lifetime. Each stream has a new application session and
fresh TLS-bound nonce; session generations increase monotonically on the server.

The server requires an actual attestation verifier and durable `guest.Publisher`.
It publishes through the application-owned port and validates the returned v2
DSSE receipt against an outside-pinned controller key and assessment scope before
acknowledgement. Session/record/quote/standing/root/caveats and integrity facts must
match. Evaluation time may follow observation time but cannot precede it or be in
the future. Conservative UNKNOWN downgrades are allowed; expired positive receipts
are not current acknowledgements. Control validity may be stricter than telemetry
validity and is checked by the v2 verifier.

`Server.Serve(ctx, rawTCPListener)` caps connections before TLS, uses one RPC per
connection, limits global streams and draining I/O workers, and applies whole-frame
size/time bounds. Send and receive queues are fixed-size. A separate watchdog uses
actual verifier time and does not require incoming traffic or successful network
sends. It fences the application session and attempts a durable UNKNOWN publication
before bounded closing. Publishers must honor deadlines and fence stale generations;
a publication failure is visible as SAFE_HOLD and never becomes an acknowledgement.
Server restart requires a new publisher with no restored live eligibility.

Rejected quote bytes are retained separately from the last admitted quote/proof
and standing. The transport does not relabel rejected assertions as attestation.
All references, times and integrity decisions originate in the session/application
or actual received bytes, not a producer-selected trust root or echoed channel value.

## Current verification boundary

The server/protocol component compiles and focused race/lint checks pass. Existing
real gRPC/TLS tests independently derive matching exporters at both endpoints and
reject reuse across connections and TLS 1.2. Additional actual TCP socket tests
exercise pre-handshake connection capacity. Real signed v2 receipt tests reject
wrong session, record, quote, time and subject bindings.

Those receipt tests intentionally use UNKNOWN signed fixtures without a quote;
they do not fake an attestation verifier or claim backend publication success.
End-to-end quote admission, healthy streaming, durable watchdog outcomes and the
producer loop require the actual TPM/provider/publisher integration gates. No
physical guest co-residence or hardware-backed TPM proof is claimed here.

## Producer lifecycle

`NewClient(ClientConfig)` requires an explicit TLS identity/trust configuration,
export signing key, outside enrollment, pinned receipt scope, real attester and
real sampler. `Run(ctx)` creates a fresh connection and exporter observer without
reconnect or RPC retry. One bounded quote worker operates independently of one
bounded sample worker. The sender and receiver each have a fixed-size queue;
unacknowledged heartbeat capacity is 16 and retained record metadata capacity is
32. Raw observation batches are not retained in the receipt index. Ports must
honor their deadlines; a worker that fails to drain fences that client instance.

The producer signs the exact supplied sample time and UNKNOWN counter facts. Slot
numbers derive from elapsed time since the admitted schedule, so missed ticks do
not become a fabricated contiguous stream. Receipt validation checks the pinned
controller, assessment scope, actual client exporter/export key, quote digest,
source/root/caveats, submitted record digest, sample window and evaluation time.
Admission starts sampling only after its signed receipt arrives. Receipt expiry
clears local positive status; disconnect requires a fresh session. Endpoint clocks
must satisfy the enrolled time bounds; there is no silent clock-skew allowance.

Client tests verify real Ed25519 DSSE heartbeat bytes across a missed slot and
original UNKNOWN sample facts, allocation bounds, and expiry of local status.
These component checks do not establish a successful attested producer/backend
stream; that still requires the actual integration gate described above.
