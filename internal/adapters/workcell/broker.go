package workcell

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/telemetry"
)

// MaxActiveLeases bounds total stored capability leases in EffectBroker per Constitution Section 30.
const MaxActiveLeases = 4096

// EffectBroker mediates and gates agent tool execution requests against bounded CapabilityLeases.
type EffectBroker struct {
	mu     sync.RWMutex
	leases map[string]*assurance.CapabilityLease
	order  []string
}

// NewEffectBroker creates a new in-memory trusted effect broker.
func NewEffectBroker() *EffectBroker {
	return &EffectBroker{
		leases: make(map[string]*assurance.CapabilityLease),
	}
}

func cloneLease(src *assurance.CapabilityLease) *assurance.CapabilityLease {
	if src == nil {
		return nil
	}
	cp := *src
	if len(src.AllowedCapabilities) > 0 {
		cp.AllowedCapabilities = make([]string, len(src.AllowedCapabilities))
		copy(cp.AllowedCapabilities, src.AllowedCapabilities)
	}
	return &cp
}

// RegisterLease adds a capability lease to the broker with bounded capacity enforcement.
func (b *EffectBroker) RegisterLease(lease *assurance.CapabilityLease) {
	if lease == nil || lease.ID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.leases[lease.ID]; !exists && len(b.leases) >= MaxActiveLeases {
		now := time.Now().UTC()
		var kept []string
		for _, id := range b.order {
			l, ok := b.leases[id]
			if !ok {
				continue
			}
			if l.Phase(now) != assurance.LeasePhaseActive {
				delete(b.leases, id)
			} else {
				kept = append(kept, id)
			}
		}
		b.order = kept
		if len(b.leases) >= MaxActiveLeases && len(b.order) > 0 {
			evictID := b.order[0]
			b.order = b.order[1:]
			delete(b.leases, evictID)
		}
	}

	if _, exists := b.leases[lease.ID]; !exists {
		b.order = append(b.order, lease.ID)
	}
	b.leases[lease.ID] = cloneLease(lease)
}

// GetLease retrieves a thread-safe snapshot of an active lease by ID.
func (b *EffectBroker) GetLease(leaseID string) (*assurance.CapabilityLease, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	lease, exists := b.leases[leaseID]
	if !exists {
		return nil, false
	}
	return cloneLease(lease), true
}

// RequestExecution gates an agent turn execution request and returns a verifiable CheckReceipt.
func (b *EffectBroker) RequestExecution(
	ctx context.Context,
	leaseID string,
	capability string,
	payload []byte,
	prevReceiptHash string,
) (*assurance.CheckReceipt, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	lease, exists := b.leases[leaseID]
	if !exists {
		telemetry.RecordEvidenceProcessed("workcell", capability, "DENIED_NO_LEASE")
		return nil, fmt.Errorf("no capability lease found with id '%s'", leaseID)
	}

	now := time.Now().UTC()
	rcpt, err := lease.EvaluateTurn(capability, payload, prevReceiptHash, now)
	if rcpt != nil {
		telemetry.RecordEvidenceProcessed("workcell", capability, rcpt.Disposition)
		if rcpt.Disposition == "ADMIT" {
			telemetry.RecordReceiptIssued(leaseID, "ADMITTED")
		}
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
