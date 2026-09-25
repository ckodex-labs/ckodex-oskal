package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// LeasePhase represents the state of a CapabilityLease.
type LeasePhase string

const (
	LeasePhaseActive    LeasePhase = "ACTIVE"
	LeasePhaseExhausted LeasePhase = "EXHAUSTED"
	LeasePhaseExpired   LeasePhase = "EXPIRED"
	LeasePhaseRevoked   LeasePhase = "REVOKED"
)

// CheckReceipt is a cryptographically chained receipt confirming a turn execution gating decision.
type CheckReceipt struct {
	ReceiptID           string    `json:"receipt_id"`
	LeaseID             string    `json:"lease_id"`
	Turn                int       `json:"turn"`
	CapabilityRequested string    `json:"capability_requested"`
	Disposition         string    `json:"disposition"` // "ADMIT", "DENY", "QUARANTINE"
	Reason              string    `json:"reason"`
	PayloadHash         string    `json:"payload_hash"`
	PrevReceiptHash     string    `json:"prev_receipt_hash"`
	ReceiptHash         string    `json:"receipt_hash"`
	Timestamp           time.Time `json:"timestamp"`
}

// ComputeHash computes the SHA-256 digest of the CheckReceipt content.
func (r *CheckReceipt) ComputeHash() string {
	raw := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%d",
		r.ReceiptID,
		r.LeaseID,
		r.Turn,
		r.CapabilityRequested,
		r.Disposition,
		r.PayloadHash,
		r.PrevReceiptHash,
		r.Timestamp.UnixNano(),
	)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// CapabilityLease governs bounded, attenuated execution authority for an AI agent or workcell.
type CapabilityLease struct {
	ID                  string    `json:"id"`
	Principal           string    `json:"principal"`
	Scope               string    `json:"scope"`
	AllowedCapabilities []string  `json:"allowed_capabilities"`
	MaxTurns            int       `json:"max_turns"`
	CurrentTurn         int       `json:"current_turn"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Revoked             bool      `json:"revoked"`
	RevocationReason    string    `json:"revocation_reason,omitempty"`
	LastReceiptHash     string    `json:"last_receipt_hash"`
}

// NewCapabilityLease constructs a new active capability lease.
func NewCapabilityLease(id, principal, scope string, allowed []string, maxTurns int, ttl time.Duration) *CapabilityLease {
	now := time.Now().UTC()
	return &CapabilityLease{
		ID:                  id,
		Principal:           principal,
		Scope:               scope,
		AllowedCapabilities: allowed,
		MaxTurns:            maxTurns,
		CurrentTurn:         0,
		IssuedAt:            now,
		ExpiresAt:           now.Add(ttl),
		Revoked:             false,
		LastReceiptHash:     "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

// Phase evaluates the current operational phase of the lease.
func (l *CapabilityLease) Phase(now time.Time) LeasePhase {
	if l.Revoked {
		return LeasePhaseRevoked
	}
	if now.After(l.ExpiresAt) {
		return LeasePhaseExpired
	}
	if l.MaxTurns > 0 && l.CurrentTurn >= l.MaxTurns {
		return LeasePhaseExhausted
	}
	return LeasePhaseActive
}

// Revoke terminates the lease immediately with an audited justification.
func (l *CapabilityLease) Revoke(reason string) {
	l.Revoked = true
	l.RevocationReason = reason
}

// EvaluateTurn gates an agent capability request, validates turn integrity, and produces a CheckReceipt.
func (l *CapabilityLease) EvaluateTurn(capability string, payload []byte, prevHash string, now time.Time) (*CheckReceipt, error) {
	currentPhase := l.Phase(now)

	payloadHashBytes := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadHashBytes[:])

	receipt := &CheckReceipt{
		ReceiptID:           fmt.Sprintf("rcpt-%s-turn-%d", l.ID, l.CurrentTurn+1),
		LeaseID:             l.ID,
		Turn:                l.CurrentTurn + 1,
		CapabilityRequested: capability,
		PayloadHash:         payloadHash,
		PrevReceiptHash:     prevHash,
		Timestamp:           now,
	}

	// 1. Verify previous receipt hash chaining
	if prevHash != l.LastReceiptHash {
		receipt.Disposition = "DENY"
		receipt.Reason = fmt.Sprintf("chain violation: expected prev_receipt_hash %s, got %s", l.LastReceiptHash, prevHash)
		receipt.ReceiptHash = receipt.ComputeHash()
		return receipt, fmt.Errorf("cryptographic turn chain broken: %s", receipt.Reason)
	}

	// 2. Verify lease is currently active
	if currentPhase != LeasePhaseActive {
		receipt.Disposition = "DENY"
		receipt.Reason = fmt.Sprintf("lease not active: current phase is %s", currentPhase)
		receipt.ReceiptHash = receipt.ComputeHash()
		return receipt, fmt.Errorf("lease inactive: %s", receipt.Reason)
	}

	// 3. Verify requested capability is within lease scope
	allowed := false
	for _, cap := range l.AllowedCapabilities {
		if cap == capability || cap == "*" {
			allowed = true
			break
		}
	}

	if !allowed {
		receipt.Disposition = "DENY"
		receipt.Reason = fmt.Sprintf("capability '%s' exceeds granted lease permissions", capability)
		receipt.ReceiptHash = receipt.ComputeHash()
		return receipt, fmt.Errorf("capability denied: %s", receipt.Reason)
	}

	// 4. Admit and advance turn counter
	l.CurrentTurn++
	receipt.Disposition = "ADMIT"
	receipt.Reason = "capability verified and admitted under active lease"
	receipt.ReceiptHash = receipt.ComputeHash()
	l.LastReceiptHash = receipt.ReceiptHash

	return receipt, nil
}
