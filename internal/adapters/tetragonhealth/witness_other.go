//go:build !linux

package tetragonhealth

import "context"

// Validate explicitly reports that native enrollment is unsupported here.
func (Enrollment) Validate() error { return ErrUnavailable }

// ReadWitness has no non-Linux backend. It never substitutes synthetic facts.
func ReadWitness(_ context.Context, enrollment Enrollment, grant RoleGrant) (KernelWitness, error) {
	return KernelWitness{Contract: ContractVersion, Availability: Unknown, Reason: ErrUnavailable.Error(), EnrollmentDigest: enrollment.Digest, GrantDigest: grant.Digest, Throttle: ThrottleObservation{Availability: Unknown, Reason: ErrUnavailable.Error()}}, ErrUnavailable
}

func CurrentCredentials() (Credentials, error) {
	return Credentials{}, ErrUnavailable
}
