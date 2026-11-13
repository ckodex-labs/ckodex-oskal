package oskal

import (
	"context"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

// ReceiptManager handles issuing and offline verification of cryptographic control receipts.
type ReceiptManager struct {
	inner *receipts.ReceiptManager
}

// NewReceiptManager requires an explicit evaluator authority. A signing key does
// not authenticate that authority claim or establish trust in its evidence.
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

// VerifyReceipt requires this manager's configured full evaluator and key. It
// does not authenticate external identity, supplemental metadata or observations.
func (m *ReceiptManager) VerifyReceipt(rcpt assurance.ControlReceipt) bool {
	if m == nil {
		return false
	}
	valid, _ := m.inner.VerifyReceipt(context.Background(), rcpt)
	return valid
}

// VerifyIndependentReceipt checks evaluator semantics and the legacy canonical
// signature under an explicit public key. Supplemental JSON metadata and external
// identity are not authenticated by this operation.
func VerifyIndependentReceipt(rcpt assurance.ControlReceipt, publicKeyHex string) (bool, error) {
	return receipts.VerifyIndependentReceipt(rcpt, publicKeyHex)
}
