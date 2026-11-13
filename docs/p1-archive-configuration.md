# Operator archive budgets

CLI and controller operators can select bounded archive byte and entry budgets.
Defaults are 67,108,864 bytes (64 MiB) and 8,192 objects. The shared storage
validator accepts 1..1,099,511,627,776 bytes and 1..1,000,000 entries. These budgets
apply to accounted disk and canonical resident objects separately; they are not
exact process RSS, PVC capacity, or evidence-validity claims. Per-object/schema
bounds and cryptographic checks remain independent.

| Operator flag | Default | Meaning |
| --- | --- | --- |
| `--archive-max-bytes` | `67108864` | Maximum accounted bytes in each archive accounting space |
| `--archive-max-entries` | `8192` | Maximum accounted objects in each archive accounting space |

Both `oskal` global flags and `oskal-controller` flags validate before archive
creation, signing-key setup, listener creation, or backend operations. The raw
`utcp call` argument path parses these flags and validates them before broker or
network setup. Invalid budgets produce an error and create no archive.

All actual CLI filesystem archive constructors receive the selected budget:
material recording, local analysis/inspect/explain, binding evaluation and
projections, receipt lookup, pruning, and the local TLS gRPC service's archive
open. MCP and UTCP constructors copy the same explicit budget into their native
archive readers and UTCP bridge. Doctor and cockpit also receive it. Remote gRPC
servers retain their own operator budgets; a client flag does not change remote
server authority or its independently bounded observation buffers.

Legacy SDK entrypoints retain conservative defaults:

- `mcp.NewServer` / `NewServerWithBroker` use the default limits;
  `NewServerWithLimits` accepts an explicit validated budget.
- `utcp.NewRegistry` uses defaults; `NewRegistryWithLimits` accepts an explicit
  validated budget for local reads and diagnostics.
- `diagnostics.RunDoctor` uses defaults; `RunDoctorWithLimits` validates first and
  reports invalid configuration before running other probes.
- A zero `cockpit.CockpitConfig.ArchiveLimits` selects defaults for compatibility.
  A nonzero custom budget is validated before the display loop or archive read.
  CLI callers validate their selected budget before constructing the cockpit.

An archive above its selected bounds is refused, including read-only restore.
History is not silently pruned, rewritten, moved, or partially loaded. After
reviewing resource availability and the retained evidence, an operator can
reopen with an explicitly higher supported budget. Raising a resource budget
neither verifies the observations nor makes archived history live-eligible.

Runtime source capacity faults are terminal for that configured process. The
collector owner records generation-fenced SAFE_HOLD before ordinary session end,
retains the actual refusal reason, invalidates eligibility, closes the source
connection, and stops retrying. Shutdown cannot rewrite the first hold reason.
Policy capture already follows the same typed `ports.ErrEvidenceCapacity`
containment contract. Recovery requires operator review and restart under a
reviewed configuration; no automatic pruning or capacity-bypass fallback exists.

## Helm configuration

The chart renders explicit decimal arguments from:

```yaml
archiveLimits:
  maxBytes: 67108864
  maxEntries: 8192
```

The values schema enforces the same positive ranges as the Go validator. The
actual chart test rendered these defaults and the selected values 1,048,576 /
128, and rejected zero, out-of-range, and fractional budgets. Logical archive
limits remain separate from `evidenceStorage.sizeLimit`, persistent volume size,
and pod resource requests/limits.

## Observed local verification

Actual subprocess/file tests demonstrated:

- Invalid CLI and controller budgets created no archive. The raw UTCP path
  rejected them before attempting a deliberately absent lease kubeconfig.
- Low byte budgets refused an actual retained material archive through direct
  CLI analysis, UTCP, MCP, cockpit, and TLS gRPC startup; the UTCP path also
  refused a low entry budget. MCP returned an explicit tool error. Doctor
  reported the archive failure with exit 3.
- Reopening with the reviewed higher test budget returned the same material as
  UNKNOWN. Every historical filename and byte remained unchanged.
- A real signed file observation was persisted under a 4 KiB archive budget.
  A subsequent actual larger file observation exhausted capacity; runtime
  containment stayed SAFE_HOLD in the same generation without retry. The first
  signed observation reopened with intact hashes under reviewed higher limits.

These checks used real files, signatures, package binaries, and actual Helm
rendering. The quota-state check does not stand in for collector networking or a
production load measurement. Existing native source and OPA proofs remain
separate. No cluster, VM setting, release, remote branch, or unrelated file was
modified by this operator configuration unit.

Executed focused checks:

```sh
go test -count=1 -run '^TestActualCLIArchiveBudgets' -v ./cmd/oskal
go test -count=1 -run 'TestControllerInvalidArchiveLimits|TestActualQuotaFault' -v ./cmd/oskal-controller
go test -count=1 -run '^TestArchiveBudgetsRender' -v ./cmd/oskal-controller
```

## Receipt and admission boundaries

Archive receipt-ID lookup now opens the selected bounded archive and uses its
confined `GetReceipt` API. Full immutable SHA-256 IDs and safe legacy aliases
(including a `.json` suffix) remain supported. IDs require `--evidence-dir`;
standalone paths use `--receipt-file`, bounded to the 64 KiB metadata limit before
JSON parsing. The explicit standalone file operation does not restore the whole
archive. Actual CLI tests rejected low-budget ID lookup, traversal IDs, a real
archive symlink to an outside receipt, and an otherwise-valid oversized receipt,
while valid signatures and every historical byte remained intact.

Runtime supervision also stops automatic generations for every existing
SAFE_HOLD, including concurrent writer and observation-identity conflicts. A
real conflicting signed file observation demonstrated the guard without a fake
collector: both immutable content references remained retrievable, the source
stayed in the same held generation, and stream end preserved its first reason.

The CLI webhook uses the global `--evidence-dir` normally; the former local flag
no longer shadows it. Optional `--webhook-evidence-dir` selects the webhook
archive explicitly. If both options are nonempty, their cleaned absolute paths
must agree; a conflict is rejected before archive creation. Every configured
sink uses the selected quota-backed CAS and propagates failures.

Admission capture records received requests, declared Pod-setting check results,
mode, and the server decision. Request UID is an `admission-request` correlation
identity, never a Pod UID or workload-creation proof. CLI captures identify the
local observer and remain unsigned; controller captures use the actual configured
producer and sign the envelope before persisting its exact payload. Neither path
adds runtime candidate eligibility, control mappings, or complete authority /
implementation / environment epochs. With no sink, the adapter explicitly reports
NOT_RECORDED and supplies no durable artifact standing. Configured sink failure
denies the AdmissionReview in enforcing, warn, and audit modes.

Actual CLI TLS subprocess checks demonstrated quota refusal in all three modes,
a healthy global archive containing the digest-bound request/check payload, and
conflicting archive flags causing no filesystem creation. These checks exercise
received AdmissionReview handling; they do not assert that a Kubernetes API
server invoked the webhook or created a Pod. The adapter's separate real TLS,
CAS, signature, I/O, quota, and deadline tests are documented in
[p1-admission-capture.md](p1-admission-capture.md).

The MCP server and default OSKAL UTCP manual identify application version v1.0.1.
Their transport protocol/schema versions remain independent.
