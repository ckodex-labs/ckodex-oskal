//go:build integration

package tpm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

// These tests use real TPM quotes, Ed25519/DSSE and TLS exporters. Explicit
// application timestamps exercise deterministic transition boundaries; they do
// not claim wall-clock watchdog behavior or live sensor counter completeness.
type sessionFixture struct {
	session    *guest.Session
	provider   *Provider
	signer     *signedrecords.Signer
	key        ed25519.PublicKey
	channel    [32]byte
	enrollment guest.Enrollment
	challenge  guest.Challenge
	report     []byte
	proof      []byte
	start      time.Time
}

func newSessionFixture(t *testing.T, provider *Provider, verifier *Verifier, channel [32]byte, edit func(*guest.Enrollment)) *sessionFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signedrecords.NewSigner(private)
	if err != nil {
		t.Fatal(err)
	}
	facts := verifier.Environment()
	e := guest.Enrollment{SourceInstance: "dedicated-software-TPM-test", MeasurementDigest: facts.MeasurementDigest,
		PolicyDigest: assurance.ComputeStringDigest("explicit-test-policy/v1"), RootKind: facts.RootKind, RootLabel: facts.RootLabel,
		Caveats:      []string{"trusted test harness; no hardware or live sensor completeness proof"},
		Policy:       assurance.TelemetryPolicy{HeartbeatInterval: time.Second, Tolerance: 100 * time.Millisecond, MaxSampleAge: 3 * time.Second, MaxAttestationAge: 8 * time.Second, RequiredSignals: []string{"observer.lost"}},
		ChallengeTTL: 500 * time.Millisecond, ReattestInterval: 3 * time.Second}
	if edit != nil {
		edit(&e)
	}
	start := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	session, err := guest.NewSession(e, verifier, public, channel, start)
	if err != nil {
		t.Fatal(err)
	}
	f := &sessionFixture{session: session, provider: provider, signer: signer, key: public, channel: channel, enrollment: e, start: start}
	f.challenge, err = session.Challenge(start)
	if err != nil {
		t.Fatal(err)
	}
	qualification, err := guest.Qualification(f.challenge, public, channel)
	if err != nil {
		t.Fatal(err)
	}
	f.replaceQuote(t, qualification)
	return f
}

func (f *sessionFixture) replaceQuote(t *testing.T, qualification [64]byte) {
	t.Helper()
	var err error
	f.report, err = f.provider.Attest(t.Context(), qualification)
	if err != nil {
		t.Fatal(err)
	}
	f.proof = proofFor(t, f.signer, f.challenge, f.report)
}

func proofFor(t *testing.T, signer *signedrecords.Signer, challenge guest.Challenge, report []byte) []byte {
	t.Helper()
	payload, err := json.Marshal(guest.QuoteProof{Version: 1, SessionID: challenge.SessionID, ChallengeID: challenge.ID, ReportDigest: assurance.ComputeDigest(report)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signer.Sign(t.Context(), guest.QuoteProofPayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *sessionFixture) admit(t *testing.T) {
	t.Helper()
	standing, err := f.session.AcceptQuote(t.Context(), f.challenge.ID, f.report, f.proof, f.start)
	if err != nil || standing.RootLabel != SoftwareRootLabel {
		t.Fatalf("real quote admission: %+v %v", standing, err)
	}
}

func (f *sessionFixture) record(t *testing.T, sequence, slot uint64, previous string, counter uint64, edit func(*guest.Record)) ([]byte, guest.AcceptedRecord, error) {
	t.Helper()
	at := f.start.Add(time.Duration(slot) * time.Second)
	r := guest.Record{Version: 1, SessionID: f.challenge.SessionID, SourceInstance: f.enrollment.SourceInstance, Sequence: sequence, Slot: slot, SampledAt: at, PreviousDigest: previous,
		Counters: []assurance.TelemetryLossCounter{{ID: "observer.lost", Value: counter, Status: assurance.TelemetrySignalObserved}}}
	if edit != nil {
		edit(&r)
	}
	payload, err := guest.EncodeRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.signer.Sign(t.Context(), guest.HeartbeatPayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := f.session.AcceptRecord(t.Context(), raw, at)
	return raw, accepted, err
}

func baseline(t *testing.T, f *sessionFixture, counter uint64) (string, []byte) {
	t.Helper()
	raw, accepted, err := f.record(t, 1, 0, "", counter, nil)
	if err != nil || accepted.Integrity.State != assurance.AssuranceStateUnknown {
		t.Fatalf("baseline must be UNKNOWN: %+v %v", accepted, err)
	}
	return accepted.SignedDigest, raw
}

func requireUnknown(t *testing.T, s *guest.Session, now time.Time) assurance.TelemetryIntegrity {
	t.Helper()
	r, err := s.Snapshot(now)
	if err != nil || r.State != assurance.AssuranceStateUnknown {
		t.Fatalf("snapshot=%+v err=%v", r, err)
	}
	return r
}

func requireFenced(t *testing.T, f *sessionFixture, now time.Time) {
	t.Helper()
	if _, err := f.session.Challenge(now); !errors.Is(err, guest.ErrSessionClosed) {
		t.Fatalf("session recovered without fresh admission: %v", err)
	}
}

func TestRealTPMSessionTransitions(t *testing.T) {
	provider, verifier := realProvider(t)
	channel, otherChannel := realTLSBinding(t), realTLSBinding(t)
	if channel == otherChannel {
		t.Fatal("different real TLS connections shared a binding")
	}
	t.Log(SoftwareRootLabel, "; actual TPM/DSSE/TLS, explicit application transition times")
	for _, name := range []string{"wrong_nonce", "wrong_export_key_binding", "wrong_actual_TLS_channel", "wrong_export_key_proof", "measurement_mismatch", "root_mismatch", "expired_challenge"} {
		t.Run(name, func(t *testing.T) {
			var edit func(*guest.Enrollment)
			if name == "measurement_mismatch" {
				edit = func(e *guest.Enrollment) { e.MeasurementDigest = assurance.ComputeStringDigest("another measurement") }
			}
			if name == "root_mismatch" {
				edit = func(e *guest.Enrollment) { e.RootKind = "HARDWARE_TPM"; e.RootLabel = "hardware TPM root" }
			}
			f := newSessionFixture(t, provider, verifier, channel, edit)
			qualification, err := guest.Qualification(f.challenge, f.key, channel)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "wrong_nonce":
				qualification[0] ^= 1
				f.replaceQuote(t, qualification)
			case "wrong_export_key_binding":
				key, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				qualification, err = guest.Qualification(f.challenge, key, channel)
				if err != nil {
					t.Fatal(err)
				}
				f.replaceQuote(t, qualification)
			case "wrong_actual_TLS_channel":
				qualification, err = guest.Qualification(f.challenge, f.key, otherChannel)
				if err != nil {
					t.Fatal(err)
				}
				f.replaceQuote(t, qualification)
			case "wrong_export_key_proof":
				_, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := signedrecords.NewSigner(private)
				if err != nil {
					t.Fatal(err)
				}
				f.proof = proofFor(t, signer, f.challenge, f.report)
			}
			received := f.start
			if name == "expired_challenge" {
				received = received.Add(f.enrollment.ChallengeTTL)
			}
			if _, err := f.session.AcceptQuote(t.Context(), f.challenge.ID, f.report, f.proof, received); !errors.Is(err, guest.ErrSessionClosed) {
				t.Fatalf("invalid admission accepted: %v", err)
			}
			requireUnknown(t, f.session, received)
			if standing, digest := f.session.Standing(); standing != nil || digest != "" {
				t.Fatal("rejected quote left an admitted environment")
			}
			requireFenced(t, f, received)
		})
	}
	t.Run("quote_replay_is_consumed", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		if _, err := f.session.AcceptQuote(t.Context(), f.challenge.ID, f.report, f.proof, f.start); !errors.Is(err, guest.ErrSessionClosed) {
			t.Fatalf("replayed quote accepted: %v", err)
		}
		requireUnknown(t, f.session, f.start)
	})
	t.Run("concurrent_quote_consumption", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		outcomes := make(chan error, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				_, err := f.session.AcceptQuote(t.Context(), f.challenge.ID, f.report, f.proof, f.start)
				outcomes <- err
			})
		}
		wg.Wait()
		close(outcomes)
		admitted := 0
		for err := range outcomes {
			if err == nil {
				admitted++
			} else if !errors.Is(err, guest.ErrSessionClosed) {
				t.Fatal(err)
			}
		}
		// A duplicate may fence the session while the first verification runs
		// outside the mutex, so zero successful admissions is also safe. The
		// invariant is single use and terminal fencing, not scheduler ordering.
		if admitted > 1 {
			t.Fatalf("challenge accepted %d times", admitted)
		}
		requireUnknown(t, f.session, f.start)
		requireFenced(t, f, f.start)
		if standing, digest := f.session.Standing(); admitted == 0 && (standing != nil || digest != "") {
			t.Fatal("a rejected concurrent admission left historical standing")
		}
		t.Logf("concurrent duplicate calls: %d successful admissions; terminal UNKNOWN and fenced", admitted)
	})
	t.Run("record_replay_is_fenced", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		_, raw := baseline(t, f, 0)
		if _, err := f.session.AcceptRecord(t.Context(), raw, f.start.Add(time.Millisecond)); !errors.Is(err, guest.ErrSessionClosed) {
			t.Fatalf("record replay accepted: %v", err)
		}
		requireUnknown(t, f.session, f.start.Add(time.Millisecond))
	})
	t.Run("missed_heartbeat_preserves_exact_range", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		baseline(t, f, 0)
		at := f.start.Add(4*time.Second + f.enrollment.Policy.Tolerance)
		r := requireUnknown(t, f.session, at)
		if len(r.Gaps) != 1 || r.Gaps[0] != (assurance.TelemetryGap{Kind: "HEARTBEAT", First: 1, Last: 4}) {
			t.Fatalf("lost gap range: %+v", r)
		}
		requireFenced(t, f, at)
	})
	t.Run("sequence_gap_preserves_exact_range", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		previous, _ := baseline(t, f, 0)
		if _, _, err := f.record(t, 4, 1, previous, 0, nil); !errors.Is(err, guest.ErrSessionClosed) {
			t.Fatalf("sequence gap accepted: %v", err)
		}
		r := requireUnknown(t, f.session, f.start.Add(time.Second))
		if len(r.Gaps) != 1 || r.Gaps[0] != (assurance.TelemetryGap{Kind: "SEQUENCE", First: 2, Last: 3}) {
			t.Fatalf("lost sequence range: %+v", r)
		}
	})
	t.Run("invalid_initial_sample_cannot_be_baseline", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		if _, _, err := f.record(t, 1, 0, "", 0, func(r *guest.Record) { r.SampledAt = r.SampledAt.Add(2 * f.enrollment.Policy.Tolerance) }); !errors.Is(err, guest.ErrSessionClosed) {
			t.Fatalf("invalid baseline accepted: %v", err)
		}
		requireFenced(t, f, f.start)
	})
	t.Run("counter_reset_requires_fresh_session", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		previous, _ := baseline(t, f, 5)
		if _, _, err := f.record(t, 2, 1, previous, 0, nil); !errors.Is(err, guest.ErrSessionClosed) {
			t.Fatalf("counter reset accepted: %v", err)
		}
		requireFenced(t, f, f.start.Add(time.Second))
	})
	t.Run("healthy_windows_and_periodic_reattest", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		previous, _ := baseline(t, f, 0)
		for slot := uint64(1); slot <= 8; slot++ {
			_, accepted, err := f.record(t, slot+1, slot, previous, 0, nil)
			if err != nil || accepted.Integrity.State != assurance.AssuranceStateVerified {
				t.Fatalf("slot%d: %+v %v", slot, accepted, err)
			}
			previous = accepted.SignedDigest
			if slot == 3 || slot == 6 {
				at := f.start.Add(time.Duration(slot) * time.Second)
				f.challenge, err = f.session.Challenge(at)
				if err != nil {
					t.Fatal(err)
				}
				qualification, err := guest.Qualification(f.challenge, f.key, f.channel)
				if err != nil {
					t.Fatal(err)
				}
				f.replaceQuote(t, qualification)
				standing, err := f.session.AcceptQuote(t.Context(), f.challenge.ID, f.report, f.proof, at)
				if err != nil || standing.StartedAt != f.start {
					t.Fatalf("periodic attestation: %+v %v", standing, err)
				}
			}
		}
		standing, digest := f.session.Standing()
		if standing == nil || digest != assurance.ComputeDigest(f.report) {
			t.Fatal("standing lost exact verified report digest")
		}
	})
	t.Run("early_reattest_does_not_issue_challenge", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		previous, _ := baseline(t, f, 0)
		if _, err := f.session.Challenge(f.start.Add(500 * time.Millisecond)); err == nil || errors.Is(err, guest.ErrSessionClosed) {
			t.Fatalf("early reattestation must be rejected without fencing a healthy session: %v", err)
		}
		_, accepted, err := f.record(t, 2, 1, previous, 0, nil)
		if err != nil || accepted.Integrity.State != assurance.AssuranceStateVerified {
			t.Fatalf("early challenge request disrupted continuity: %+v %v", accepted, err)
		}
	})
	t.Run("expired_quote_cannot_be_revived", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		f.admit(t)
		previous, _ := baseline(t, f, 0)
		for slot := uint64(1); slot < 8; slot++ {
			_, accepted, err := f.record(t, slot+1, slot, previous, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			previous = accepted.SignedDigest
		}
		at := f.start.Add(f.enrollment.Policy.MaxAttestationAge)
		r := requireUnknown(t, f.session, at)
		if !strings.Contains(strings.Join(r.Reasons, ";"), "expired") {
			t.Fatalf("missing expiry diagnosis: %+v", r)
		}
		requireFenced(t, f, at)
	})
	t.Run("canceled_quote_fences_consumed_challenge", func(t *testing.T) {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := f.session.AcceptQuote(ctx, f.challenge.ID, f.report, f.proof, f.start); !errors.Is(err, guest.ErrSessionClosed) {
			t.Fatalf("canceled admission: %v", err)
		}
		requireFenced(t, f, f.start)
	})
}

func TestRealTPMSessionWatchdogConcurrency(t *testing.T) {
	provider, verifier := realProvider(t)
	channel := realTLSBinding(t)
	started := time.Now()
	var overlappingSnapshots int
	var slowestSnapshot time.Duration
	for trial := range 32 {
		f := newSessionFixture(t, provider, verifier, channel, nil)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		var admitting atomic.Bool
		quoteStarted := make(chan struct{})
		quoteDone := make(chan error, 1)
		type snapshotResult struct {
			overlap int
			slowest time.Duration
			err     error
		}
		snapshotDone := make(chan snapshotResult, 1)
		go func() {
			admitting.Store(true)
			close(quoteStarted)
			_, err := f.session.AcceptQuote(ctx, f.challenge.ID, f.report, f.proof, f.start)
			admitting.Store(false)
			quoteDone <- err
		}()
		go func() {
			<-quoteStarted
			var result snapshotResult
			for range 32 {
				before := time.Now()
				integrity, err := f.session.Snapshot(f.start)
				elapsed := time.Since(before)
				if elapsed > result.slowest {
					result.slowest = elapsed
				}
				if err != nil || integrity.State != assurance.AssuranceStateUnknown {
					result.err = fmt.Errorf("snapshot before a complete heartbeat window: state=%s error=%v", integrity.State, err)
					break
				}
				if admitting.Load() {
					result.overlap++
				}
				runtime.Gosched()
			}
			snapshotDone <- result
		}()
		select {
		case err := <-quoteDone:
			if err != nil {
				cancel()
				t.Fatalf("trial %d quote admission: %v", trial, err)
			}
		case <-ctx.Done():
			cancel()
			t.Fatalf("trial %d quote admission exceeded test bound", trial)
		}
		select {
		case result := <-snapshotDone:
			if result.err != nil {
				cancel()
				t.Fatal(result.err)
			}
			overlappingSnapshots += result.overlap
			if result.slowest > slowestSnapshot {
				slowestSnapshot = result.slowest
			}
		case <-ctx.Done():
			cancel()
			t.Fatalf("trial %d watchdog snapshot exceeded test bound", trial)
		}
		cancel()
		if standing, digest := f.session.Standing(); standing == nil || digest != assurance.ComputeDigest(f.report) {
			t.Fatalf("trial %d lost successfully verified standing", trial)
		}
	}
	t.Logf("32 real quote admissions with 1024 concurrent snapshots: elapsed=%s max_snapshot_call=%s observed_in_flight_snapshots=%d; scheduling observation, not stalled-verifier or production latency proof", time.Since(started), slowestSnapshot, overlappingSnapshots)
}
