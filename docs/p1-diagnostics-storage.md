# Diagnostic proof and durable evidence recovery

Doctor reports UNKNOWN when it has observed configuration or connectivity without
performing the corresponding trust verification. A present TUF_ROOT path is not a
verified Sigstore root; a Unix connection is not an authenticated SPIFFE identity;
a kubeconfig or token file is not proof of API authentication or authorization.
The embedded-schema check compiles five schemas and validates an actual UNKNOWN
assessment-results projection. It does not establish a security-control result.

InspectSubject describes the evaluation it receives. Historical execution,
observation producer identity, receipt existence, freshness policy and lineage
remain UNKNOWN unless the corresponding evidence is supplied and checked. It
never invents an execution path, policy identifier, obligations or recovery command.
Root consistency checks only whether the supplied evidence reference digests
reproduce the reported aggregate root. It does not authenticate payloads.

InspectStoredSubject additionally reads a real persisted receipt through
ReceiptRepository and verifies it under an explicitly supplied, caller-trusted
Ed25519 public key. It checks subject, control, epoch, state, evidence root and
receipt evaluation time. The receipt authenticates the evaluator assertion, not
the observation producers or their payloads. Receipt signature and binding can
therefore be PASS while producer identity and lineage remain UNKNOWN. Missing
anchors, missing receipts, invalid signatures and binding contradictions return
errors. No verification key is inferred from the archive being inspected.

The legacy merkle_valid and lineage_verified booleans remain false. Consumers
must use root_consistency, receipt_verification, receipt_binding,
producer_identity_verification and lineage_verification to distinguish UNKNOWN
from failed verification. A sorted digest aggregate is not a Merkle inclusion tree.

Filesystem CAS restore fails closed on unreadable files, invalid digest names,
digest mismatches, malformed envelopes or malformed receipt encoding. The
constructor returns no usable repository and an IntegrityError identifying the
path and recovery action. It does not remove, overwrite or relocate corrupt
bytes. Preserve the store, investigate the affected file, and restore separately
verified bytes before explicitly reopening it. No automatic quarantine mutation
or restoration is performed.

Each restored file is bounded to 32 MiB, matching evidence payload ingestion;
new envelope and receipt writes enforce the same per-file bound. Legacy
single-envelope and envelope-list JSON remains supported and is indexed using
its actual serialized bytes. Unrelated valid JSON exports can coexist in the
store. Malformed legacy JSON is rejected because its evidence content cannot be
established. This deliberately tightens old behavior that silently skipped
corruption. Receipt parsing is structural; cryptographic authentication still
requires an explicit trust anchor.
