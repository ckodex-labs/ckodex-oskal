//go:build !linux && !darwin

package tetragonsampler

import (
	"fmt"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"os"
)

func openGrant(string) (*os.File, error) {
	return nil, fmt.Errorf("%w: grant file platform has no enrolled native witness", tetragonhealth.ErrUnavailable)
}

func checkSocket(string, uint32, uint32) error { return tetragonhealth.ErrUnavailable }
