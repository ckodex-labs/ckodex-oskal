# Native admission connection bounds

Native `AdmissionWebhookServer.Start` now bounds accepted connections at **64**
before TLS handshakes, HTTP header parsing, or per-request handler goroutines can
be created. The existing **16** in-flight validation limit remains separate.
`Close` unblocks an Accept waiting for capacity; each accepted connection releases
its slot exactly once on close. The implementation reuses the repository's
existing token-listener pattern without adding a dependency or framework.

The prior native host called `ListenAndServeTLS` directly. Go 1.27.4's HTTP server
starts a connection goroutine after each successful underlying Accept, while the
webhook's validation semaphore runs only after TLS and headers. Stalled handshake
or header clients could therefore bypass the validation concurrency limit.
Timeouts limited their duration, but not their count.

Startup still validates the explicit certificate/key before opening the listener,
uses TLS 1.3 or newer, and preserves request/body/JSON limits. Native hosting now
opens an explicit TCP listener, wraps it before `ServeTLS`, and owns the bounded
context-triggered shutdown drain. If the five-second drain expires, active
connections are closed. `Start` waits for that work instead of leaving its
shutdown goroutine behind when the manager returns. Shutdown through the existing
external `Shutdown` method remains caller-owned.

Custom hosts using only `Handler()` must supply their own listener/connection
limits. The handler's 16-request limit does not bound connections accepted by a
separate host. Protocol stream settings were not redesigned: the inspected locked
Go 1.27.4 HTTP/2 implementation has a finite default maximum of 250 concurrent
streams per connection, and admission validation is still guarded independently.
This is not a process RSS, rate, workload-capacity, or production-load claim.

## Actual verification

The tests run the real native Start path over TCP/TLS. They observe acceptance
at HTTP StateNew and physical TCP closure through a forwarding connection wrapper,
before the listener releases its token. The observer is installed synchronously
before net/http starts the connection goroutine. They do not infer live TCP count
from later StateClosed notifications or goroutine counts, and use no fake
listener/backend.

- 64 real sockets stalled before TLS and filled native capacity. An additional
  real TLS handshake reached its I/O deadline without a 65th acceptance.
- Releasing a slot permitted a real TLS 1.3 health request with verified server
  certificate chains. Maximum simultaneous accepted connections stayed at 64.
- A real TLS request stalled mid-body while the remaining slots stalled before
  TLS; another TCP connection waited in the kernel backlog. Context shutdown
  unblocked saturated Accept and all those clients within the bounded drain
  (observed approximately five seconds).

The regression probe was also executed against the exact previous native
`server.go` from commit `84b7bdba47461cd663afca6271292d6d73cb66b6` through a Go
overlay. It failed as expected: the extra TLS handshake succeeded before any slot
was released. Baseline output is retained at
`/private/tmp/oskal-p1-listener-baseline/repro.log`.

The first combined test run had a test-startup race: its second test attempted
TLS before asynchronous native binding. It now waits for an actual successful TCP
connection before starting that handshake. The initial output remains at
`/private/tmp/oskal-p1-listener-startup-race-failure.log`.

Focused real tests and race verification use Go 1.27.4 darwin/arm64. Output is
retained in `/private/tmp/oskal-p1-listener-{live,race,lint,build}.log`. No cluster,
VM configuration, unrelated process, trust store, remote branch, or release was
modified.


## Hosted callback-ordering failure and measurement correction

The [hosted Go job](https://github.com/ckodex-labs/ckodex-oskal/actions/runs/43443914456/job/131948286970)
failed the earlier post-release counter assertion at 2026-11-13T14:39:17Z:
`accepted concurrency exceeded bound after release: 65`, after 0.37 seconds.
Its full output is preserved at
`/private/tmp/oskal-p1-listener-hosted-failure/job-131948286970.log`.

Go 1.27.4's `net/http/server.go` closes the connection at line 1975 and only then
invokes StateClosed at line 1976. Its close path calls the underlying connection's
Close at line 1816. The bounded listener closes the real TCP connection and
releases its token before returning from that call. A newly accepted connection
can therefore reach StateNew while the old StateClosed callback is still pending.
The old counter measured outstanding callback notifications, which can reach 65;
that value does not establish 65 live TCP connections.

A controlled real-network reproduction delays the first StateClosed notification
until another verified TLS request completes. It reproduces the old callback
counter at 65 while the corrected live TCP counter stays at 64. The corrected
observer forwards every real connection operation unchanged and decrements only
after actual TCP Close returns, before token release. The full-capacity blocked
extra handshake, accepted count, slot-release verified TLS request, maximum live
TCP bound, and bounded shutdown assertions remain in place. Production listener
and server code are unchanged by this correction.

Controlled pre-correction output is retained at
`/private/tmp/oskal-p1-listener-hosted-failure/controlled-ordering-before-fix.log`;
the corrected comparison is at `.../accurate-counter.log`. Repeated focused race
verification and shutdown output are at `.../repeated-race.log` and
`.../shutdown-race.log`, with scoped lint at `.../lint.log`. This correction is
local Go 1.27.4 darwin/arm64 evidence; the final hosted rerun remains separate.
