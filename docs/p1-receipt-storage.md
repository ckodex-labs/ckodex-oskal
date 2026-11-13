# Immutable control receipt storage

`PutReceipt` returns `rcpt-<64 lowercase SHA-256 hex characters>`. The digest is
computed over the exact stored JSON bytes, including the signature. The object is
stored under `receipts/<returned-reference>.json`. A later receipt for the same
control, including a transition from VERIFIED to UNKNOWN, receives a different
reference and cannot overwrite the earlier object.

Immutable publication uses a synced temporary file and create-only hard-link
publication. An existing object must contain exactly the expected bytes; different
bytes cause an integrity error and remain in place for investigation. Restoring
receipts verifies digest filenames against the actual bytes. Legacy 12-character
digest filenames are verified as legacy compatibility lookups, not collision-resistant
identities; new receipts never return or create these truncated references. No historical receipt is automatically
deleted or rewritten during restoration.

`rcpt-<control>` and safe subject/control aliases remain compatibility lookups.
They select the most recent EvaluatedAt value, with a deterministic receipt
payload digest tie-breaker. They are mutable names and must not be used as stable
proof references. Restoration reconstructs these lookups from retained history,
so a late write of an older receipt does not roll back the recovered latest view.
The `rcpt-<12 hex>` and `rcpt-<64 hex>` namespaces are reserved; control aliases
cannot occupy either namespace, including case variants.

Receipt filenames and lookup IDs are bounded single components. Traversal,
absolute paths, separators, NUL and unsafe control aliases are rejected before
writing. Unsafe optional subject aliases are omitted. Receipt file access uses
`os.Root` confinement so receipt-directory and file symlinks cannot redirect I/O
outside the configured archive. Digest restoration has no exception for a control
whose ID happens to equal a digest suffix. Safe legacy aliases remain readable.

Content addressing establishes byte identity, not trusted authorship. Independent
verification still requires the expected subject/control/epoch/state bindings and
an explicitly trusted signing public key. The existing ControlReceipt signature
format and signing key paths are unchanged.

Actual filesystem tests use persisted Ed25519 keys and independent signature
verification. They demonstrate two same-control versions retaining distinct full
references after reopen, immutable-file digest equality, latest compatibility
lookup behavior, traversal and reserved-alias rejection, full and legacy digest
filename tamper rejection with forensic bytes retained, safe legacy lookup, and
outside-directory/file symlink denial without outside writes. These tests establish
local filesystem behavior; power-loss recovery and native behavior on every release
platform are not claimed.
