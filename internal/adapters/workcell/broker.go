package workcell

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/telemetry"
)

// EffectBroker mediates and gates agent tool execution requests against bounded CapabilityLeases.
type EffectBroker struct {
	mu     sync.RWMutex
	leases map[string]*assurance.CapabilityLease
}

// NewEffectBroker creates a new in-memory trusted effect broker.
func NewEffectBroker() *EffectBroker {
	return &EffectBroker{
		leases: make(map[string]*assurance.CapabilityLease),
	}
}

// RegisterLease adds a capability lease to the broker.
func (b *EffectBroker) RegisterLease(lease *assurance.CapabilityLease) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.leases[lease.ID] = lease
}

// GetLease retrieves an active lease by ID.
func (b *EffectBroker) GetLease(leaseID string) (*assurance.CapabilityLease, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	lease, exists := b.leases[leaseID]
	return lease, exists
}

// RequestExecution gates an agent turn execution request and returns a verifiable CheckReceipt.
func (b *EffectBroker) RequestExecution(
	ctx context.Context,
	leaseID string,
	capability string,
	payload []byte,
	prevReceiptHash string,
) (*assurance.CheckReceipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	lease, exists := b.leases[leaseID]
	if !exists {
		telemetry.RecordEvidenceProcessed("workcell", capability, "DENIED_NO_LEASE")
		return nil, fmt.Errorf("no capability lease found with id '%s'", leaseID)
	}

	now := time.Now().UTC()
	rcpt, err := lease.EvaluateTurn(capability, payload, prevReceiptHash, now)

	// Record telemetry
	telemetry.RecordEvidenceProcessed("workcell", capability, rcpt.Disposition)
	if rcpt.Disposition == "ADMIT" {
		telemetry.RecordReceiptIssued(leaseID, "ADMITTED")
	}

	return rcpt, err
}

// Revoke terminates a capability lease immediately.
func (b *EffectBroker) Revoke(leaseID, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	lease, exists := b.leases[leaseID]
	if !exists {
		return fmt.Errorf("lease '%s' not found", leaseID)
	}

	lease.Revoke(reason)
	telemetry.RecordDriftInvalidation(leaseID, "lease_revoked")
	return nil
}
