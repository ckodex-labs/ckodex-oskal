# Phase 2 acceptance remains incomplete

A healthy, complete telemetry window has not been demonstrated, so Phase 2 is not accepted.

The implementation preserves UNKNOWN instead of excluding an inconvenient signal
or substituting a narrower claim for the requested complete-window assessment.

| Requirement | Observed evidence | Acceptance boundary |
| --- | --- | --- |
| Attested producer | Real swtpm quotes, registered-key broker, actual mTLS/exporter binding, nonce/key/PCR/channel rejection | Software root only; protected key, running guest code, memory and hardware co-residence are not proven |
| Complete healthy window | Actual native BPF zero reads and signed source sampling | Full window remains UNKNOWN from increasing exhausted Pod-enrichment failures |
| Flooded sensor | Queue loss counter 3 -> 19887, delta 19884 upstream queue records, during 66640 real execs in 30s | Explicit demo queue size 4; not unique events, a performance result, or a PASS -> UNKNOWN transition |
| Silence | Actual TPM + TLS + filesystem evidence pipeline independently persisted a fenced UNKNOWN receipt when no heartbeat arrived | Initial-silence proof, not a previously healthy complete production sensor |
| Replay | Real quote/session tests reject old challenges, wrong nonce/key/channel and consumed proofs | The complete one-command demo replay sequence is not demonstrated |
| Receipts | Full-body v2 signatures, assessment expiry, retained gaps/caveats; actual standalone verification returned UNKNOWN with exit 2 | Signature verification does not independently reverify all underlying quote, policy and observation artifacts |

## Why the current window stays UNKNOWN

Tetragon v1.8.0 can exhaust Pod-enrichment retries and still notify listeners.
Its namespace filter rejects an event whose Process.Pod is absent for a nonempty
namespace. Thus events can disappear from OSKAL's namespace subscription even
when raw ring-buffer and BPF-loss counters are zero. The failure counter's labels
do not prove those events belonged outside the selected workload. An existing
correctly attributed non-root event proves an existential observation, not
complete capture or attribution. The current policy does not authorize treating
those propositions as equivalent.

The official Kind proc mount was applied read-only in the second profile. The
proposed CRI/cgroup-ID alternative was inspected before mutation: Tetragon joins
the node-relative CRI cgroup path to the VM host's proc-root cgroup filesystem.
An actual owned Pod's path existed in the node but returned ENOENT through the
host path. Enabling this unresolved mapping could suppress Pod failures without
proving attribution; the Helm change was not applied. No counter was reset or
removed to manufacture an initial PASS.

## Verification and cleanup

The integrated branch builds and passes ordinary race tests, vet, focused native
tests and lint. Real broker tests use swtpm, actual TLS and measured ELF files.
Native witnesses were exercised with no capabilities, a process-local BPF command
allowlist, an actual seccomp denial, a non-root DAC denial and a later UID change
under the old grant. These are bounded experiments, not production or scale claims.

Both owned Kind profiles, failed attempts, volumes and private evidence were
retained. The final running node was stopped; its exit 137 followed the stop
deadline, with OOMKilled false. The authorized inotify limit was restored from
1024 to 128 and independently read back. Fourteen unrelated container states were
unchanged. The software TPM test process was also stopped.

Retained local evidence includes `/private/tmp/oskal-p2-native-proof/`, its
`inotify-restoration.json`, the `profile-c` before/after flood files, and
`/private/tmp/oskal-p2-user-receipt-proof/`. Public CI proof is attached to the
software-TPM workflow runs. No hardware TEE, production promotion, release or tag
publication is implied by this work.
