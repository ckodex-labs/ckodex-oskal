package ports

import "errors"

// ErrEvidenceCapacity means an evidence archive's configured byte, entry or
// per-object bound prevents admission. Supervisors must retain existing history,
// invalidate affected source eligibility and enter SAFE_HOLD for operator review.
var ErrEvidenceCapacity = errors.New("evidence archive capacity exhausted")
