package assurance

import (
	"testing"
	"time"
)

func TestExecutionAdmissionBounds(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	valid := ExecutionLease{Namespace: "lease-tests", Name: "bounded", UID: "immutable-uid", Generation: 1, ObservedGeneration: 1, Principal: "spiffe://example.test/workload", Scope: "utcp://registry/tool/example.write", AllowedCapabilities: []string{"utcp:execute-tool"}, MaxTurns: 2, IssuedAt: now, ExpiresAt: now.Add(time.Minute), TTL: time.Minute}
	request := ExecutionRequest{LeaseNamespace: valid.Namespace, LeaseName: valid.Name, LeaseUID: valid.UID, Resource: valid.Scope, Capability: "utcp:execute-tool", RequestID: "first", Payload: []byte("effect-input")}
	admission, err := EvaluateExecution(valid, request, valid.Principal, now)
	if err != nil || admission.Turn != 1 || valid.CurrentTurn != 0 {
		t.Fatalf("pure admission changed source or failed: %+v %v", admission, err)
	}
	cases := map[string]func(*ExecutionLease){
		"zero-turns":        func(l *ExecutionLease) { l.MaxTurns = 0 },
		"oversize-history":  func(l *ExecutionLease) { l.MaxTurns = MaxLeaseTurns + 1 },
		"negative-ttl":      func(l *ExecutionLease) { l.TTL = -time.Minute },
		"missing-issuance":  func(l *ExecutionLease) { l.IssuedAt = time.Time{} },
		"expiry-extension":  func(l *ExecutionLease) { l.ExpiresAt = l.ExpiresAt.Add(time.Minute) },
		"future-issuance":   func(l *ExecutionLease) { l.IssuedAt = now.Add(time.Second); l.ExpiresAt = l.IssuedAt.Add(l.TTL) },
		"expiry-boundary":   func(l *ExecutionLease) { l.IssuedAt = now.Add(-time.Minute); l.ExpiresAt = now },
		"revoked":           func(l *ExecutionLease) { l.Revoked = true },
		"deleting":          func(l *ExecutionLease) { l.Deleting = true },
		"generation-change": func(l *ExecutionLease) { l.Generation++ },
		"exhaustion":        func(l *ExecutionLease) { l.CurrentTurn = l.MaxTurns },
		"wildcard":          func(l *ExecutionLease) { l.AllowedCapabilities = []string{"*"} },
		"replayed-id":       func(l *ExecutionLease) { l.LastRequestID = request.RequestID },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			lease := valid
			change(&lease)
			if _, err := EvaluateExecution(lease, request, valid.Principal, now); err == nil {
				t.Fatal("invalid authority admitted")
			}
		})
	}
	tooLarge := request
	tooLarge.Payload = make([]byte, MaxExecutionPayloadBytes+1)
	if _, err := EvaluateExecution(valid, tooLarge, valid.Principal, now); err == nil {
		t.Fatal("oversized payload admitted")
	}
	if _, err := EvaluateExecution(valid, request, "", now); err == nil {
		t.Fatal("missing identity admitted")
	}
	receipt, err := CompleteExecution(*admission, []byte("actual-result"), "", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	history := []ExecutionReceipt{*receipt}
	if err := ValidateExecutionLineage(history, admission.Hash, receipt.Hash, 1); err != nil {
		t.Fatal(err)
	}
	history[0].Admission.Resource = "utcp://registry/tool/other.write"
	if err := ValidateExecutionLineage(history, admission.Hash, receipt.Hash, 1); err == nil {
		t.Fatal("tampered admission accepted")
	}
	history[0] = *receipt
	history[0].ResultDigest = "sha256:tampered"
	if err := ValidateExecutionLineage(history, admission.Hash, receipt.Hash, 1); err == nil {
		t.Fatal("tampered completion accepted")
	}
	if err := ValidateExecutionLineage(nil, admission.Hash, receipt.Hash, 0); err == nil {
		t.Fatal("missing history accepted")
	}
}
