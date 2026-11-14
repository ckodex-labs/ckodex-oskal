//go:build !linux

package tetragonhealth

import (
	"errors"
	"testing"
)

func TestNativeWitnessExplicitlyUnavailable(t *testing.T) {
	witness, err := ReadWitness(t.Context(), Enrollment{}, RoleGrant{})
	if !errors.Is(err, ErrUnavailable) || witness.Availability != Unknown || witness.Throttle.Availability != Unknown || len(witness.Loss) != 0 {
		t.Fatalf("unsupported substrate invented a native witness: %+v %v", witness, err)
	}
}
