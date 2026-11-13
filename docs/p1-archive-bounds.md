# Bounded evidence archive admission

The filesystem and memory evidence repositories now enforce explicit byte and
entry budgets. Existing constructors use `storage.DefaultArchiveLimits()`:
64 MiB and 8,192 entries. The limits apply separately to accounted persistent
objects and canonical resident objects; they are not an exact Go heap or RSS limit.

Operator-controlled construction uses:

```go
limits := storage.ArchiveLimits{MaxBytes: 64 << 20, MaxEntries: 8192}
if err := limits.Validate(); err != nil {
    return err
}
repo, err := storage.OpenFilesystemEvidenceRepositoryWithLimits(path, limits)
```

`NewFilesystemEvidenceRepositoryWithLimits` and
`NewMemoryEvidenceRepositoryWithLimits` expose the same budget contract. Validate
limits before creating storage or other persistent state. Increasing a budget is
an explicit operator decision that must account for the process/container memory
limit and retained evidence volume.

## Admission and recovery

Every envelope/payload pair and every receipt/compatibility-alias set is admitted
as one quota calculation before persistent writes. Envelope and receipt writers
share a mutex, preventing concurrent admission or serialization from oversubscribing
these budgets. Repeated identical objects consume no additional quota. Existing
objects remain readable after refusal. Failed writes may conservatively retain
reservations, and replaced smaller aliases retain their previous high-water size;
reopening rebuilds accounting from actual files. `Usage()` reports these conservative
reservations, rather than claiming measured filesystem or heap usage.

Capacity failures are `*storage.CapacityError` and wrap
`ports.ErrEvidenceCapacity`. Source supervision must detect them with `errors.Is`,
clear affected live eligibility and enter SAFE_HOLD. Reopen with sufficient reviewed
limits, or roll over to a separately managed archive while preserving prior history.
No automatic pruning, deletion or quota-driven eviction is performed. The existing
explicit operator `Prune` API remains separate; reopen after authorized retention
changes to recalculate available capacity.

Artifacts are now synced and published before referring envelopes. CAS publication
uses create-only links; retrying an object never silently replaces corrupt bytes.
A failed envelope publication may retain an orphan artifact for investigation,
but does not publish an envelope pointing at an artifact not yet written. Immutable
receipt IDs and historical bytes retain their existing format.

## Allocation and enumeration bounds

- Raw payload reads are limited to the smaller of 32 MiB and the configured byte
  budget. At most one writer performs ingestion/serialization at a time. Reading
  bytes to identify a duplicate is bounded even when the archive is full.
- Envelope and receipt JSON is limited to 64 KiB. Subject attributes and envelope
  control references are each capped at 256 entries, and aggregate string bytes
  are checked before serialization. Serialized JSON size is checked again.
- Restore preflights object sizes and aggregate file budgets before loading the
  archive. Directory enumeration reads chunks and stops at `MaxEntries + 16`
  entries per managed directory, including unrelated entries in that scan.
- Legacy documents are capped at 32 MiB. Arrays are streamed with at most
  `MaxEntries` elements, rather than unmarshaled into an unbounded object slice.
  Each recognized envelope must meet the 64 KiB metadata bound before structured
  decoding/indexing. Oversized raw JSON can consume only the bounded document and
  decoder buffers; it is not decoded into a giant map or object slice.
- Resident canonical blobs/receipts have independent byte/entry checks. Subject
  indexes are bounded by admitted envelopes, and receipt aliases are bounded
  multiples of admitted receipts. Returned and supplied metadata maps are copied,
  preventing subsequent caller mutations from expanding or changing stored indexes.

Go representation overhead, decoder/copy buffers, bounded temporary publication
files and already-admitted caller buffers are additional to the configured byte
budget. These bounds prevent unlimited archive growth in the process; they do not
constitute a measured memory benchmark or guarantee a particular RSS on every
runtime/platform. Payload readers supplied by adapters must themselves be bounded
and deadline-aware; a generic `io.Reader` cannot be forcibly interrupted by storage.

## Scope

The disk budget covers CAS envelope/payload files, receipt files and compatibility
aliases, plus managed top-level legacy JSON files. Signing-key files, configuration
and public-snapshot directories, unrelated nested directories, filesystem metadata
and temporary publication overhead are outside this quota. This is not a quota for
the entire volume. Separate filesystem/container limits still apply.

The archive has one writer owner. Calls through that repository instance are
serialized; multiple independent processes or external file writers are not covered
by a distributed quota transaction. Controller leadership and archive ownership must
prevent competing writers. Read-only reopening is supported and never changes files.

## Verified evidence

`go test -race ./internal/adapters/storage -count=1 -v` passed all existing storage
integrity, immutable receipt, path-confinement and recovery tests, plus new actual-file
checks. One run reached an exact 858-byte budget, rejected the next admission with
`ErrEvidenceCapacity`, retained its two earlier files, reopened at the original
budget, and admitted further material only after reopening with a reviewed larger
budget. Concurrent envelope/receipt writers remained within a seven-file quota.

Restore tests refused a nine-element legacy array under an eight-entry budget, a
65,537-byte metadata object, and an over-limit directory enumeration while preserving
all fixture bytes. Corrupt immutable payload bytes survived a retry unchanged.
No workload memory benchmark, production capacity estimate, or hardware claim is
made by these tests.

The complete `go test -race ./...` suite, `go build ./...`, and
`golangci-lint run` also passed on the archive-bounds branch. Live external
backend tests retain their explicit environment gates; no cluster or infrastructure
changes were performed for this storage unit.

## Metadata ownership correction

Independent review of `eccc517` found that its metadata copy occurred after
`payload.Read`. A synchronous reader callback could mutate the caller's shared
attribute map or control slice after validation/serialization, causing the resident
index to differ from the admitted canonical bytes without a Go data race.

`Put` now validates bounds, immediately copies those maps/slices, then serializes
and invokes the payload reader. It indexes that same frozen copy. It does not copy
unbounded input before validation, and reader callbacks cannot expand retained
metadata after admission.

The real-file regression `TestPayloadReadCannotChangeAdmittedMetadata` failed
before this correction with 65,537 unchecked attribute bytes under a 4,096-byte
quota. Afterward it passed with 1,004 admitted bytes, matching serialized/indexed
bytes and digest, unchanged original control identity, and consistent reopening.
The full storage race suite and scoped storage lint passed for this correction.
