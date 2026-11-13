package policycollection

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/opa"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/policyreports"
)

// PrincipalResolver is structurally compatible with ports.PrincipalResolver.
// It must freshly verify peer identity, not trust a header or a log-supplied ID.
type PrincipalResolver interface {
	AuthenticatedPrincipal(context.Context) (string, error)
}

type tlsStateKey struct{}

// PeerTLSState exposes only the handler-provided TLS state to the parent's fresh
// PKI/SPIFFE verifier. VerifiedChains may be nil under custom SPIFFE verification;
// its absence is not replaced with a trust decision here.
func PeerTLSState(ctx context.Context) (tls.ConnectionState, bool) {
	state, ok := ctx.Value(tlsStateKey{}).(tls.ConnectionState)
	return state, ok
}

type OPAConfig struct {
	Decoder           *opa.Decoder
	Principals        PrincipalResolver
	ExpectedPrincipal string
	BeginBatch        BeginBatch
	RequestTimeout    time.Duration
}

type OPAReceiver struct {
	config OPAConfig
	active chan struct{}
}

func NewOPAReceiver(config OPAConfig) (*OPAReceiver, error) {
	if config.Decoder == nil || config.Principals == nil || config.ExpectedPrincipal == "" || config.BeginBatch == nil {
		return nil, fmt.Errorf("OPA decoder, fresh principal resolver, exact expected publisher and batch factory are required")
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute {
		return nil, fmt.Errorf("OPA request deadline is outside bounds")
	}
	return &OPAReceiver{config: config, active: make(chan struct{}, 1)}, nil
}

// ServeHTTP requires TLS and an authenticated publisher before reading the body
// or beginning a session. A collector's producer/signature is not an OPA
// publisher signature; the verified publisher is retained as separate metadata.
func (h *OPAReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "authenticated TLS 1.3 client is required", http.StatusUnauthorized)
		return
	}
	// Bound fresh authentication as well as decoding and persistence. Taking a
	// local capacity slot grants no source/session authority and reads no body.
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "a source request is already active", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.config.RequestTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, tlsStateKey{}, *r.TLS)
	principal, err := h.config.Principals.AuthenticatedPrincipal(ctx)
	if ctx.Err() != nil {
		http.Error(w, "publisher verification deadline exceeded", http.StatusServiceUnavailable)
		return
	}
	if err != nil || principal == "" {
		http.Error(w, "publisher authentication failed", http.StatusUnauthorized)
		return
	}
	if principal != h.config.ExpectedPrincipal {
		http.Error(w, "publisher is not authorized", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST is required", http.StatusMethodNotAllowed)
		return
	}
	status, err := h.accept(ctx, w, r, principal)
	if err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *OPAReceiver) accept(ctx context.Context, w http.ResponseWriter, r *http.Request, principal string) (status int, result error) {
	writer, end, err := h.config.BeginBatch(ctx)
	if end != nil {
		defer func() {
			if result == nil && ctx.Err() != nil {
				status = http.StatusServiceUnavailable
				result = ctx.Err()
			}
			end(result)
		}()
	}
	if err != nil {
		return http.StatusServiceUnavailable, fmt.Errorf("begin OPA batch: %w", err)
	}
	if writer == nil || end == nil {
		return http.StatusServiceUnavailable, fmt.Errorf("OPA batch requires writer and completion callback")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) != "gzip" {
		return http.StatusUnsupportedMediaType, fmt.Errorf("OPA requires gzip application/json")
	}
	if r.ContentLength > opa.MaxCompressedBytes {
		return http.StatusRequestEntityTooLarge, fmt.Errorf("%w: OPA compressed body exceeds bound", ErrSafeHold)
	}
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	if err := controller.SetReadDeadline(deadline); err != nil {
		return http.StatusServiceUnavailable, fmt.Errorf("OPA transport cannot enforce read deadline: %w", err)
	}
	defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	captures, err := h.config.Decoder.DecodeBatch(http.MaxBytesReader(w, r.Body, opa.MaxCompressedBytes))
	if err != nil {
		if ctx.Err() != nil {
			return http.StatusServiceUnavailable, ctx.Err()
		}
		var limit *http.MaxBytesError
		if errors.As(err, &limit) || errors.Is(err, opa.ErrBatchLimit) {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("%w: %w", ErrSafeHold, err)
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return http.StatusRequestTimeout, err
		}
		return http.StatusBadRequest, fmt.Errorf("OPA batch rejected: %w", err)
	}
	for _, capture := range captures {
		if err := ctx.Err(); err != nil {
			return http.StatusServiceUnavailable, err
		}
		capture.Record.Metadata = maps.Clone(capture.Record.Metadata)
		capture.Record.Metadata["authenticatedPublisher"] = principal
		capture.Record.Metadata["observer"] = capture.Event.Producer.Canonical()
		payload, err := json.Marshal(capture.Record)
		if err != nil {
			return http.StatusBadRequest, err
		}
		if len(payload) > policyreports.MaxSnapshotBytes {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("%w: OPA authenticated capture exceeds byte bound", ErrSafeHold)
		}
		capture.Event.Payload = payload
		if err := writer.WriteCapturedEvent(ctx, capture.Event); err != nil {
			return http.StatusServiceUnavailable, fmt.Errorf("persist OPA batch: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return http.StatusServiceUnavailable, err
	}
	return http.StatusNoContent, nil
}
