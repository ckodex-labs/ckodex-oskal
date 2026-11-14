package guesttransport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

const MaxFrameBytes = signedrecords.MaxEnvelopeBytes
const maxQuoteProofBytes = 16 << 10

type Limits struct {
	MaxConnections  int
	MaxStreams      int
	HelloTimeout    time.Duration
	SendTimeout     time.Duration
	VerifyTimeout   time.Duration
	PublishTimeout  time.Duration
	ShutdownTimeout time.Duration
}

func DefaultLimits() Limits {
	return Limits{MaxConnections: 16, MaxStreams: 8, HelloTimeout: 5 * time.Second, SendTimeout: 2 * time.Second, VerifyTimeout: 2 * time.Second, PublishTimeout: 2 * time.Second, ShutdownTimeout: 5 * time.Second}
}
func (l Limits) validate() error {
	if l.MaxConnections < 1 || l.MaxConnections > 64 || l.MaxStreams < 1 || l.MaxStreams > l.MaxConnections {
		return fmt.Errorf("transport requires 1..64 connections and 1..connection-limit streams")
	}
	for _, limit := range []time.Duration{l.HelloTimeout, l.SendTimeout, l.VerifyTimeout, l.PublishTimeout, l.ShutdownTimeout} {
		if limit < time.Millisecond || limit > time.Minute {
			return fmt.Errorf("transport operation timeouts must be 1ms..1m")
		}
	}
	return nil
}

// ReceiptScope is outside-owned context, never taken from a producer frame.
type ReceiptScope struct {
	Key       ed25519.PublicKey
	Authority assurance.AuthorityRef
	Subject   assurance.SubjectRef
	Control   assurance.ControlRef
	Epoch     assurance.AssuranceEpoch
}

func (s ReceiptScope) validate() error {
	if len(s.Key) != ed25519.PublicKeySize {
		return fmt.Errorf("pinned verifier receipt key is required")
	}
	if err := s.Authority.Validate(); err != nil {
		return err
	}
	if err := s.Subject.Validate(); err != nil {
		return err
	}
	return s.Control.Validate()
}
func cloneScope(s ReceiptScope) ReceiptScope {
	s.Key = bytes.Clone(s.Key)
	s.Subject.Attributes = maps.Clone(s.Subject.Attributes)
	return s
}
func cloneEnrollment(e guest.Enrollment) guest.Enrollment {
	e.Caveats = slices.Clone(e.Caveats)
	e.Policy.RequiredSignals = slices.Clone(e.Policy.RequiredSignals)
	return e
}
func nilPort(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// ServerConfig admits one outside-enrolled source. Its Publisher must have one
// server owner for its lifetime; restart with a new publisher and no live state.
type ServerConfig struct {
	EnrollmentID string
	Enrollment   guest.Enrollment
	Verifier     ports.AttestationVerifier
	Publisher    guest.Publisher
	Receipt      ReceiptScope
	TLS          *tls.Config
	Limits       Limits
}

func validateTLS(config *tls.Config, server bool) error {
	if config == nil || config.MinVersion < tls.VersionTLS13 || config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13 {
		return fmt.Errorf("explicit TLS 1.3 configuration is required")
	}
	if server {
		if len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
			return fmt.Errorf("server TLS identity is required")
		}
		if config.ClientAuth == tls.RequireAndVerifyClientCert && config.ClientCAs == nil {
			return fmt.Errorf("explicit client trust roots are required")
		}
		verified := config.ClientAuth == tls.RequireAndVerifyClientCert || config.ClientAuth == tls.RequireAnyClientCert && (config.VerifyPeerCertificate != nil || config.VerifyConnection != nil)
		if !verified {
			return fmt.Errorf("server requires verified mutual TLS peers")
		}
	} else {
		if config.RootCAs == nil && config.VerifyPeerCertificate == nil && config.VerifyConnection == nil {
			return fmt.Errorf("explicit server trust roots or verifier are required")
		}
		if config.InsecureSkipVerify && config.VerifyPeerCertificate == nil && config.VerifyConnection == nil {
			return fmt.Errorf("client TLS verification cannot be disabled")
		}
	}
	return nil
}
