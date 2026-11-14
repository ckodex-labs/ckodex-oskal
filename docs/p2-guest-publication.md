# Preserve the source's gaps with the security result

The guest publisher signs and archives an actual control evaluation together with
the verifier's telemetry context. This component is not yet deployed or accepted
as the Phase 2 demo: native Kubernetes publication is blocked by the retained
Kind/inotify failure, pending authorization for a shared VM limit change.

## Execution path

One verifier server owns one publisher and its monotonically allocated source
generations. Older generations cannot replace newer outcomes. Each publication
uses a deadline-aware gate; an expired queued request cannot mutate source state
or put the later generation on hold.

The publisher reads the actual Kubernetes ControlBinding and subject UID through
the uncached binding resolver. A VERIFIED telemetry window permits ingestion of
its authenticated raw Tetragon observations. The existing decoder checks real
protobuf fields; the capture resolver checks current Pod UID, ownership, creation
time and all policy epochs. Shared `Resolver.BindEnvelope` maps the observation
only through the current contract's exact type and recorder authority. Both the
existing controller and this publisher use that mapping.

Only those signed live candidates enter the existing evaluator. Telemetry
integrity alone does not create a passing assessment. Missing evidence remains
UNKNOWN. Loss, silence and fenced sessions end live eligibility while retaining
archive history. A new process starts with empty eligibility; archived positive
receipts do not restart a source. Binding identity and epochs are read again
before a receipt is produced.

The v2 receipt signs the complete body and actual assessment expiry, which can be
earlier than the heartbeat deadline. The evaluator's timestamp is preserved.
UNKNOWN uses an actual evaluation timestamp with zero standing duration. The
challenge, admitted report, export-key proof, signed heartbeat and signed receipt
are recorder-signed content-addressed archive objects. Raw protocol history has
no control references and cannot become eligible evidence. The existing archive
has explicit byte/object limits and atomic immutable publication; exhaustion
enters SAFE_HOLD and never automatically prunes history.

## Authority and limits

The operator supplies the actual subject UID, binding, recorder identity, signing
key, archive, decoder and outside-enrolled source configuration. The signing
authority is an explicit claim; key possession alone does not authenticate it.
The supervisor and transport must verify the actual attestation and source key
before calling this application port. A software TPM root remains a software
root; these components do not establish hardware or malicious-root resistance.

The supported Tetragon decoder retains Phase 1's process-execution effective-UID
scope. It does not prove privilege at subsequent file or network operations, nor
does a positive observation prove every process was non-root. Sensitive-operation
probes and their conformance tests remain required Phase 2 integration work.

## Verification boundary

Build and focused lint pass. Existing binding/controller/Tetragon race tests pass
after extracting the unchanged mapping rule. A real context/deadline test proves
an expired queued publication returns without changing a newer generation. The
shared receipt tests prove that a signed 20 ms assessment expires even when
telemetry remains valid for 500 ms. Independent source review confirmed the
reported expiry, cancellation, mapping, history and timestamp fixes.

No test in this component substitutes a Kubernetes API or returns a manufactured
positive result. Real Kubernetes publication, native BPF reads, flooding, minimum
privileges, recovery, the in-guest launcher and the complete signed demo remain
unverified. Rejected quote-attempt history is a pending transport integration,
separate from the retained last admitted quote.
