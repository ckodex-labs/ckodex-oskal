package oskal

import (
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

// ReceiptManager handles issuing and offline verification of cryptographic control receipts.
type ReceiptManager struct {
	inner *receipts.ReceiptManager
}

// NewReceiptManager creates a ReceiptManager with an evaluator authority identity.
func NewReceiptManager(evaluator AuthorityRef) (*ReceiptManager, error) {
	mgr, err := receipts.NewReceiptManager(evaluator)
	if err != nil {
		return nil, fmt.Errorf("failed to create receipt manager: %w", err)
	}
	return &ReceiptManager{inner: mgr}, nil
}

// PublicKey returns the evaluator's Ed25519 public key in hexadecimal format.
func (m *ReceiptManager) PublicKey() string {
	return m.inner.PublicKey()
}

// IssueReceipt generates and signs a new ControlReceipt binding the subject, control, state, epoch, and evidence root.
func (m *ReceiptManager) IssueReceipt(
	subject SubjectRef,
	control ControlRef,
	state AssuranceState,
	epoch AssuranceEpoch,
	evidences []EvidenceRef,
	evaluatedAt time.Time,
) (assurance.ControlReceipt, error) {
	return m.inner.IssueReceipt(subject, control, state, epoch, evidences, evaluatedAt)
}

// VerifyReceipt checks the Ed25519 digital signature and structural integrity of a ControlReceipt.
func (m *ReceiptManager) VerifyReceipt(rcpt assurance.ControlReceipt) bool {
	valid, _ := receipts.VerifyIndependentReceipt(rcpt, m.inner.PublicKey())
	return valid
}

// VerifyIndependentReceipt verifies a ControlReceipt using an explicit evaluator public key hex string.
func VerifyIndependentReceipt(rcpt assurance.ControlReceipt, publicKeyHex string) (bool, error) {
	return receipts.VerifyIndependentReceipt(rcpt, publicKeyHex)
}
