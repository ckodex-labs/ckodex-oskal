package main

import (
	"errors"

	"github.com/ckodex-labs/ckodex-oskal/internal/application/diagnostics"
)

type evaluationResultError struct {
	code    int
	message string
}

func (e *evaluationResultError) Error() string { return e.message }

func doctorResult(report *diagnostics.DoctorReport) error {
	switch report.OverallState {
	case diagnostics.StatusFail:
		return &evaluationResultError{code: 3, message: "doctor evaluated FAIL; inspect the reported checks and remediation before retrying"}
	case diagnostics.StatusUnknown:
		return &evaluationResultError{code: 2, message: "doctor evaluated UNKNOWN; supply and verify the missing identity, trust or connectivity evidence"}
	default:
		return nil
	}
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var result *evaluationResultError
	if errors.As(err, &result) {
		return result.code
	}
	return 1
}
