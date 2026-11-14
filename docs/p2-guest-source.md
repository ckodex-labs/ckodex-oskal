# Send evidence from inside the runtime

`oskal-sensor` connects a real local Tetragon source to the outside verifier. It
obtains quotes through the constrained outside broker; it never receives the
TPM authorization or raw TPM socket. Its configuration, export key, TLS identity,
read grant and trust anchors must come from the outside supervisor.

The configured sampler reads actual loopback metrics and enrolled BPF maps,
checks operation-time credentials, and batches real gRPC events. Measurements
and original signed grants travel inside the signed record. Failure ends the
stream; there is no reconnect, fabricated heartbeat, or unmeasured fallback.

Use an explicitly supplied private configuration:

```sh
oskal-sensor --config /absolute/source.json --json
```

This command requires the static Linux build. It drops effective, permitted,
inheritable, bounding and ambient capabilities across all Go runtime threads and
sets no-new-privileges before collecting evidence. A thread-local capset would
leave other sampling threads with startup authority. The native read profile
still requires filesystem access and an explicitly authorized seccomp policy;
capability removal is not a complete sandbox or a hardware guarantee.

The actual credential diagnostic is:

```sh
oskal-sensor credentials
```

On the owned Linux arm64 Kind node this returned effective UID/FSUID 0 and
effective capabilities 0, with exit status 0. That is an observed credential
state, not proof of hardware isolation or production deployment.

The configuration schema is `guestproducer.Config`: explicit verifier and broker
addresses, separately pinned TLS server names and CAs, client certificate/key
paths, export key path, receipt key/scope, complete native enrollment, read-grant
path and outside key, local socket owner, metrics endpoint, namespace and resource
limits. Configuration is strict JSON at most 256 KiB. Private configuration and
key files require mode 0600. All file inputs are bounded regular files; endpoint
and enrollment validation precede network connections.

Results go to stdout, status/errors to stderr. `--json` returns the final source
status and verified receipt bytes. Exit 0 means a current verified positive
receipt, 2 means a received UNKNOWN/incomplete assessment, 3 means FAILED, and 1
means the source could not run or obtain a verified receipt. A successful TLS
connection or TPM quote alone is never exit-0 assurance.

This source builds and its real Linux capability-drop diagnostic ran. Its full
collector/client loop with a positive bound assessment is not verified. Current
Kind experiments preserve increasing Pod-enrichment failures as UNKNOWN, and the
five-step Phase 2 acceptance demo is incomplete. Software-root evidence must
carry the exact human label software TPM root &mdash; not hardware-backed and its
runtime-memory, key-extraction and co-residence limitations.
