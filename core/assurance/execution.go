package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ExecutionRequest binds a single effect to a namespaced lease identity. Actor
// identity is deliberately absent: the broker obtains it from authentication.
type ExecutionRequest struct {
	LeaseNamespace        string `json:"leaseNamespace"`
	LeaseName             string `json:"leaseName"`
	LeaseUID              string `json:"leaseUID"`
	Resource              string `json:"resource"`
	Capability            string `json:"capability"`
	RequestID             string `json:"requestId"`
	Payload               []byte `json:"payload"`
	PreviousAdmissionHash string `json:"previousAdmissionHash"`
}

// ExecutionAdmission is a pre-execution reservation, never a completion receipt.
type ExecutionAdmission struct {
	LeaseNamespace  string    `json:"leaseNamespace"`
	LeaseName       string    `json:"leaseName"`
	LeaseUID        string    `json:"leaseUID"`
	LeaseGeneration int64     `json:"leaseGeneration"`
	Principal       string    `json:"principal"`
	Resource        string    `json:"resource"`
	Capability      string    `json:"capability"`
	RequestID       string    `json:"requestId"`
	PayloadDigest   string    `json:"payloadDigest"`
	Turn            int       `json:"turn"`
	PreviousHash    string    `json:"previousHash"`
	Hash            string    `json:"hash"`
	AdmittedAt      time.Time `json:"admittedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// ExecutionLease is an immutable snapshot supplied by the authoritative store.
type ExecutionLease struct {
	Namespace           string
	Name                string
	UID                 string
	Generation          int64
	ObservedGeneration  int64
	Principal           string
	Scope               string
	AllowedCapabilities []string
	MaxTurns            int
	CurrentTurn         int
	IssuedAt            time.Time
	ExpiresAt           time.Time
	TTL                 time.Duration
	Revoked             bool
	Deleting            bool
	LastAdmissionHash   string
	LastRequestID       string
}

const MaxExecutionPayloadBytes = 1 << 20

// ValidateExecutionGrant checks the bounds of an admitted grant snapshot. It
// grants no operation and produces no admission or execution receipt.
func ValidateExecutionGrant(lease ExecutionLease, now time.Time) error {
	if lease.Principal == "" || len(lease.Principal) > 512 || lease.UID == "" || lease.Namespace == "" || lease.Name == "" {
		return fmt.Errorf("lease identity and principal are required")
	}
	if lease.Generation <= 0 || lease.ObservedGeneration != lease.Generation {
		return fmt.Errorf("lease policy generation is not admitted")
	}
	if lease.MaxTurns <= 0 || lease.MaxTurns > MaxLeaseTurns || lease.TTL <= 0 || lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() || !lease.ExpiresAt.Equal(lease.IssuedAt.Add(lease.TTL)) {
		return fmt.Errorf("lease requires finite valid execution bounds")
	}
	if now.Before(lease.IssuedAt) || !now.Before(lease.ExpiresAt) {
		return fmt.Errorf("lease is outside its validity interval")
	}
	resource, err := url.Parse(lease.Scope)
	if err != nil || resource.Scheme == "" || resource.Host == "" || resource.User != nil || resource.Fragment != "" || len(lease.Scope) > 2048 || strings.ContainsAny(lease.Scope, "*\r\n") {
		return fmt.Errorf("lease requires an exact resource scope")
	}
	if len(lease.AllowedCapabilities) == 0 || len(lease.AllowedCapabilities) > 128 {
		return fmt.Errorf("lease requires 1..128 exact capabilities")
	}
	for _, capability := range lease.AllowedCapabilities {
		if capability == "" || len(capability) > 128 || strings.ContainsAny(capability, "*\r\n") {
			return fmt.Errorf("lease capabilities must be exact and bounded")
		}
	}
	return nil
}

// EvaluateExecution validates a request against authoritative state without I/O
// or mutation. Its result is not usable until a store atomically reserves it.
func EvaluateExecution(lease ExecutionLease, request ExecutionRequest, principal string, now time.Time) (*ExecutionAdmission, error) {
	if err := ValidateExecutionGrant(lease, now); err != nil {
		return nil, err
	}
	if principal == "" || len(principal) > 512 || principal != lease.Principal {
		return nil, fmt.Errorf("authenticated principal does not match lease")
	}
	if request.LeaseNamespace == "" || request.LeaseName == "" || request.LeaseUID == "" || request.LeaseNamespace != lease.Namespace || request.LeaseName != lease.Name || request.LeaseUID != lease.UID {
		return nil, fmt.Errorf("lease identity mismatch")
	}
	if lease.Deleting || lease.Revoked {
		return nil, fmt.Errorf("lease is revoked or deleting")
	}
	if lease.CurrentTurn < 0 || lease.CurrentTurn >= lease.MaxTurns {
		return nil, fmt.Errorf("lease turn budget exhausted")
	}
	if len(request.Resource) > 2048 || len(request.Capability) > 128 {
		return nil, fmt.Errorf("execution authority fields exceed bounds")
	}
	resource, err := url.Parse(request.Resource)
	if err != nil || resource.Scheme == "" || resource.Host == "" || resource.User != nil || resource.Fragment != "" || request.Resource != lease.Scope || strings.ContainsAny(request.Resource, "*\r\n") {
		return nil, fmt.Errorf("requested resource is outside exact lease scope")
	}
	if request.RequestID == "" || len(request.RequestID) > 128 || request.RequestID == lease.LastRequestID {
		return nil, fmt.Errorf("missing, oversized or replayed request identity")
	}
	if request.PreviousAdmissionHash != lease.LastAdmissionHash {
		return nil, fmt.Errorf("admission chain mismatch")
	}
	if len(request.Payload) > MaxExecutionPayloadBytes {
		return nil, fmt.Errorf("execution payload exceeds %d bytes", MaxExecutionPayloadBytes)
	}
	allowed := false
	for _, capability := range lease.AllowedCapabilities {
		if capability != "" && capability != "*" && capability == request.Capability {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("requested capability is not granted")
	}
	digest := sha256.Sum256(request.Payload)
	admission := &ExecutionAdmission{LeaseNamespace: lease.Namespace, LeaseName: lease.Name, LeaseUID: lease.UID, LeaseGeneration: lease.Generation, Principal: principal, Resource: request.Resource, Capability: request.Capability, RequestID: request.RequestID, PayloadDigest: "sha256:" + hex.EncodeToString(digest[:]), Turn: lease.CurrentTurn + 1, PreviousHash: lease.LastAdmissionHash, AdmittedAt: now.UTC(), ExpiresAt: lease.ExpiresAt.UTC()}
	encoded, err := json.Marshal(admission)
	if err != nil {
		return nil, fmt.Errorf("encode admission: %w", err)
	}
	hash := sha256.Sum256(encoded)
	admission.Hash = "sha256:" + hex.EncodeToString(hash[:])
	return admission, nil
}

// MaxLeaseTurns bounds retained lineage and Kubernetes status size.
const MaxLeaseTurns = 128

// ExecutionReceipt records an actually completed effect. Hash chaining supplies
// integrity linkage, not a signature or independent proof of producer identity.
type ExecutionReceipt struct {
	Admission    ExecutionAdmission `json:"admission"`
	ResultDigest string             `json:"resultDigest"`
	CompletedAt  time.Time          `json:"completedAt"`
	PreviousHash string             `json:"previousHash"`
	Hash         string             `json:"hash"`
}

// CompleteExecution binds the observed result to its prior admission.
func CompleteExecution(admission ExecutionAdmission, result []byte, previous string, now time.Time) (*ExecutionReceipt, error) {
	digest := sha256.Sum256(result)
	receipt := &ExecutionReceipt{Admission: admission, ResultDigest: "sha256:" + hex.EncodeToString(digest[:]), CompletedAt: now.UTC(), PreviousHash: previous}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode completion: %w", err)
	}
	hash := sha256.Sum256(encoded)
	receipt.Hash = "sha256:" + hex.EncodeToString(hash[:])
	return receipt, nil
}

// ValidateExecutionLineage checks retained admission/completion integrity before
// another effect is authorized. A hash chain does not authenticate its writer.
func ValidateExecutionLineage(history []ExecutionReceipt, lastAdmission, lastExecution string, currentTurn int) error {
	if currentTurn < 0 || len(history) != currentTurn || len(history) > MaxLeaseTurns {
		return fmt.Errorf("execution lineage length mismatch")
	}
	admissionHash, executionHash := "", ""
	for i, receipt := range history {
		admission := receipt.Admission
		if admission.Turn != i+1 || admission.PreviousHash != admissionHash || receipt.PreviousHash != executionHash {
			return fmt.Errorf("execution lineage chain mismatch at turn %d", i+1)
		}
		expectedAdmission := admission.Hash
		admission.Hash = ""
		encoded, err := json.Marshal(admission)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(encoded)
		if "sha256:"+hex.EncodeToString(digest[:]) != expectedAdmission {
			return fmt.Errorf("admission integrity mismatch at turn %d", i+1)
		}
		expectedReceipt := receipt.Hash
		receipt.Hash = ""
		encoded, err = json.Marshal(receipt)
		if err != nil {
			return err
		}
		digest = sha256.Sum256(encoded)
		if "sha256:"+hex.EncodeToString(digest[:]) != expectedReceipt {
			return fmt.Errorf("completion integrity mismatch at turn %d", i+1)
		}
		admissionHash, executionHash = expectedAdmission, expectedReceipt
	}
	if admissionHash != lastAdmission || executionHash != lastExecution {
		return fmt.Errorf("execution lineage tip mismatch")
	}
	return nil
}
