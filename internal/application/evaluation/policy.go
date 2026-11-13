package evaluation

import (
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// ApplyPolicies promotes only verified evaluations under an explicit policy.
func ApplyPolicies(e assurance.ClaimEvaluation, policies []assurance.AssurancePolicy, now time.Time) assurance.AssuranceState {
	if e.State != assurance.AssuranceStateVerified {
		return e.State
	}
	authorized := false
	for _, policy := range policies {
		if policy.RequiredState == assurance.AssuranceStateAssured {
			authorized = true
		}
		if policy.RequireFresh && (e.ValidUntil.IsZero() || !now.Before(e.ValidUntil)) {
			return assurance.AssuranceStateStale
		}
		if policy.MaxEvaluationAge > 0 && (e.EvaluatedAt.IsZero() || now.Sub(e.EvaluatedAt) > policy.MaxEvaluationAge) {
			return assurance.AssuranceStateStale
		}
	}
	if !authorized {
		return e.State
	}
	next, err := assurance.Transition(e.State, assurance.EventPolicyAssured)
	if err != nil {
		return assurance.AssuranceStateUnknown
	}
	return next
}
