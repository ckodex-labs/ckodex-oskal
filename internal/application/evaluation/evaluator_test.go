package evaluation_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
)

type fixture struct {
	archive      *storage.ContentAddressedEvidenceRepository
	signer       *receipts.ReceiptManager
	verifier     *verifier.DefaultEvidenceVerifier
	subject      assurance.SubjectRef
	producer     assurance.AuthorityRef
	control      assurance.ControlRef
	epoch        assurance.AssuranceEpoch
	contract     assurance.EvidenceContract
	directory    string
	keyDirectory string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{directory: filepath.Join(t.TempDir(), "archive"), keyDirectory: filepath.Join(t.TempDir(), "keys"), subject: assurance.SubjectRef{Scheme: "k8s", ID: "local/default/Pod/real-observation"}, producer: assurance.AuthorityRef{Scheme: "spiffe", Subject: "test.oskal/ns/runtime/sa/collector", TrustDomain: "test.oskal"}, control: assurance.ControlRef{Namespace: "nist-sp-800-53", ID: "AC-6"}}
	var err error
	f.archive, err = storage.NewFilesystemEvidenceRepository(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	f.signer, err = receipts.LoadOrCreateReceiptManager(f.producer, f.keyDirectory)
	if err != nil {
		t.Fatal(err)
	}
	f.verifier = verifier.NewDefaultEvidenceVerifier()
	key, err := hex.DecodeString(f.signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	f.verifier.RegisterPublicKey(f.producer.Canonical(), ed25519.PublicKey(key))
	f.epoch = assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeStringDigest("actual subject fixture"), ImplementationDigest: assurance.ComputeStringDigest("runtime sensor fixture configuration"), PolicyDigest: assurance.ComputeStringDigest("exact runtime observation contract"), AuthorityDigest: assurance.ComputeDigest(key), EnvironmentDigest: assurance.ComputeStringDigest("isolated local test environment")}
	f.contract = assurance.EvidenceContract{ID: "exact-runtime", Requirements: []assurance.EvidenceRequirement{{ID: "process-exec", EvidenceType: "runtime.process.exec", Required: true, MaxAge: time.Hour, AcceptedProducers: []string{f.producer.Canonical()}}}}
	return f
}
func (f *fixture) envelope(id string, payload []byte) assurance.EvidenceEnvelope {
	digest := assurance.ComputeDigest(payload)
	return assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: id, Subject: f.subject, ObservationType: "runtime.process.exec", CapturedAt: time.Now().UTC().Add(-time.Second), Producer: f.producer, Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "application/json"}, IntegrityDigest: digest, Epoch: f.epoch, ControlRefs: []assurance.ControlRef{f.control}}
}
func (f *fixture) claim() assurance.Claim {
	return assurance.Claim{ID: "runtime-claim", Subject: f.subject, Control: f.control}
}
func (f *fixture) sign(t *testing.T, envelope assurance.EvidenceEnvelope) assurance.EvidenceEnvelope {
	t.Helper()
	signed, err := f.signer.SignEvidence(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
func (f *fixture) evaluate(t *testing.T) assurance.ClaimEvaluation {
	t.Helper()
	e, err := evaluation.NewEvaluator(f.archive, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := e.Evaluate(context.Background(), f.claim(), f.contract, f.epoch)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStrictEvaluationUsesActualSignaturesAndArtifactBytes(t *testing.T) {
	f := newFixture(t)
	payload := []byte(`{"event":"exec","pid":42}`)
	envelope := f.sign(t, f.envelope("actual-signed-event", payload))
	if _, err := f.archive.Put(context.Background(), envelope, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	result := f.evaluate(t)
	if result.State != assurance.AssuranceStateVerified || result.Completeness.Verified != 1 || result.Completeness.Present != 1 || result.EvidenceRoot == "" {
		t.Fatalf("actual signed evidence not verified: %+v", result)
	}
	if !result.ValidUntil.Equal(envelope.CapturedAt.Add(time.Hour)) {
		t.Fatal("validity not bounded by original capture timestamp")
	}
	restored, err := storage.NewFilesystemEvidenceRepository(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	f.archive = restored
	if result := f.evaluate(t); result.State != assurance.AssuranceStateVerified {
		t.Fatal(result)
	}
	t.Log("real disk CAS reopen plus actual Ed25519 signature and raw artifact bytes verified")
}

func TestInvalidCandidatesCannotSatisfyContract(t *testing.T) {
	cases := map[string]func(*fixture, *assurance.EvidenceEnvelope){
		"unsigned": func(_ *fixture, e *assurance.EvidenceEnvelope) { e.SignatureRef = "" },
		"bad-signature": func(_ *fixture, e *assurance.EvidenceEnvelope) {
			e.SignatureRef = strings.Repeat("00", ed25519.SignatureSize)
		},
		"signed-field-tamper": func(_ *fixture, e *assurance.EvidenceEnvelope) { e.ID += "-changed" },
		"wrong-control": func(_ *fixture, e *assurance.EvidenceEnvelope) {
			e.ControlRefs = []assurance.ControlRef{{Namespace: "nist-sp-800-53", ID: "SC-7"}}
		},
		"wrong-subject":     func(_ *fixture, e *assurance.EvidenceEnvelope) { e.Subject.ID = "local/default/Pod/other" },
		"wrong-type-suffix": func(_ *fixture, e *assurance.EvidenceEnvelope) { e.ObservationType = "exec" },
		"artifact-binding-tamper": func(_ *fixture, e *assurance.EvidenceEnvelope) {
			e.IntegrityDigest = assurance.ComputeStringDigest("other")
		},
		"untrusted-producer": func(_ *fixture, e *assurance.EvidenceEnvelope) { e.Producer.Subject = "untrusted.oskal/collector" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			payload := []byte(`{"event":"exec"}`)
			envelope := f.sign(t, f.envelope(name, payload))
			change(f, &envelope)
			if _, err := f.archive.Put(context.Background(), envelope, bytes.NewReader(payload)); err != nil {
				t.Fatal(err)
			}
			result := f.evaluate(t)
			if result.State != assurance.AssuranceStateUnknown || result.Completeness.Verified != 0 || result.Completeness.Missing != 1 {
				t.Fatalf("invalid candidate promoted: %+v", result)
			}
		})
	}
}

func TestValidSignatureDoesNotOverrideEpochFreshnessOrProducerPolicy(t *testing.T) {
	for _, kind := range []string{"wrong-epoch", "stale", "future", "wrong-producer-policy", "optional-only", "missing-policy-failed"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			payload := []byte(`{"event":"exec"}`)
			envelope := f.envelope(kind, payload)
			switch kind {
			case "wrong-epoch":
				envelope.Epoch.SubjectDigest = assurance.ComputeStringDigest("other real subject epoch")
			case "stale":
				envelope.CapturedAt = time.Now().Add(-2 * time.Hour)
			case "future":
				envelope.CapturedAt = time.Now().Add(time.Hour)
			case "wrong-producer-policy":
				f.contract.Requirements[0].AcceptedProducers = []string{"spiffe://other.oskal/collector"}
			case "optional-only":
				f.contract.Requirements[0].Required = false
			case "missing-policy-failed":
				f.contract.OnMissingRequiredState = assurance.AssuranceStateFailed
				envelope.CapturedAt = time.Now().Add(-2 * time.Hour)
			}
			envelope = f.sign(t, envelope)
			if _, err := f.archive.Put(context.Background(), envelope, bytes.NewReader(payload)); err != nil {
				t.Fatal(err)
			}
			result := f.evaluate(t)
			want := assurance.AssuranceStateUnknown
			if kind == "missing-policy-failed" {
				want = assurance.AssuranceStateFailed
			}
			if result.State != want {
				t.Fatalf("%s promoted: %+v", kind, result)
			}
			if (kind == "wrong-epoch" || kind == "stale") && result.Completeness.Stale != 1 {
				t.Fatal("stale/epoch mismatch omitted from completeness")
			}
		})
	}
}

func TestMissingContractAuthorityAndArtifactsFailClosed(t *testing.T) {
	f := newFixture(t)
	if _, err := evaluation.NewEvaluator(f.archive, nil); err == nil {
		t.Fatal("nil verifier accepted")
	}
	evaluator, err := evaluation.NewEvaluator(f.archive, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing-contract", "missing-producers", "wildcard-producer", "missing-epoch", "unbounded-freshness", "pass-on-missing"} {
		t.Run(kind, func(t *testing.T) {
			contract := f.contract
			contract.Requirements = append([]assurance.EvidenceRequirement(nil), f.contract.Requirements...)
			epoch := f.epoch
			switch kind {
			case "missing-contract":
				contract.ID = ""
			case "missing-producers":
				contract.Requirements[0].AcceptedProducers = nil
			case "wildcard-producer":
				contract.Requirements[0].AcceptedProducers = []string{"spiffe://test.oskal/*"}
			case "missing-epoch":
				epoch.AuthorityDigest = ""
			case "unbounded-freshness":
				contract.Requirements[0].MaxAge = 0
			case "pass-on-missing":
				contract.OnMissingRequiredState = assurance.AssuranceStateVerified
			}
			result, err := evaluator.Evaluate(context.Background(), f.claim(), contract, epoch)
			if err == nil || result.State != assurance.AssuranceStateUnknown {
				t.Fatalf("invalid contract accepted: %+v %v", result, err)
			}
		})
	}
	payload := []byte("artifact intentionally absent")
	envelope := f.sign(t, f.envelope("missing-artifact", payload))
	if _, err := f.archive.Put(context.Background(), envelope, nil); err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.Evaluate(context.Background(), f.claim(), f.contract, f.epoch)
	if err == nil || result.State != assurance.AssuranceStateUnknown {
		t.Fatalf("repository read failure hidden: %+v %v", result, err)
	}
}

func TestDurablePayloadTamperStopsRepositoryRecovery(t *testing.T) {
	f := newFixture(t)
	payload := []byte(`{"pid":42}`)
	envelope := f.sign(t, f.envelope("tamper", payload))
	if _, err := f.archive.Put(context.Background(), envelope, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.directory, "blobs", "sha256", strings.TrimPrefix(envelope.Artifact.Digest, "sha256:")+".bin")
	if err := os.WriteFile(path, []byte(`{"pid":99}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.NewFilesystemEvidenceRepository(f.directory); err == nil {
		t.Fatal("tampered durable bytes restored as trusted evidence")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("forensic bytes not preserved")
	}
}

func TestSourceSessionsInvalidateEligibilityWithoutDeletingArchive(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	config := []collection.SourceConfig{{ID: "tetragon", Producer: f.producer, Signer: f.signer}}
	candidates, err := collection.NewCandidates(f.archive, config, 2)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := evaluation.NewEvaluator(candidates, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want assurance.AssuranceState) {
		t.Helper()
		result, err := evaluator.Evaluate(ctx, f.claim(), f.contract, f.epoch)
		if err != nil || result.State != want {
			t.Fatalf("state=%s want=%s error=%v", result.State, want, err)
		}
	}
	check(assurance.AssuranceStateUnknown)
	first, err := candidates.BeginSession("tetragon")
	if err != nil {
		t.Fatal(err)
	}
	check(assurance.AssuranceStateUnknown)
	payload := []byte(`{"exec":"first"}`)
	envelope := f.envelope("first", payload)
	captured := envelope.CapturedAt
	if _, err := first.Repository().Put(ctx, envelope, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	check(assurance.AssuranceStateVerified)
	observed, err := candidates.ListBySubject(ctx, f.subject)
	if err != nil || len(observed) != 1 || !observed[0].CapturedAt.Equal(captured) {
		t.Fatalf("capture time altered: %+v %v", observed, err)
	}
	if err := first.End("actual stream unavailable"); err != nil {
		t.Fatal(err)
	}
	check(assurance.AssuranceStateUnknown)
	archived, err := f.archive.ListBySubject(ctx, f.subject)
	if err != nil || len(archived) != 1 {
		t.Fatal("archive changed on source loss")
	}
	second, err := candidates.BeginSession("tetragon")
	if err != nil {
		t.Fatal(err)
	}
	check(assurance.AssuranceStateUnknown)
	if _, err := first.Repository().Put(ctx, envelope, bytes.NewReader(payload)); !errors.Is(err, collection.ErrSessionClosed) {
		t.Fatalf("superseded writer accepted: %v", err)
	}
	if err := first.End("late old stream error"); !errors.Is(err, collection.ErrSessionClosed) {
		t.Fatal("old session ended newer session")
	}
	if candidates.Snapshot()[0].Lifecycle != collection.SourceStarting {
		t.Fatal("new session status changed by old session")
	}
	payload = []byte(`{"exec":"second"}`)
	envelope = f.envelope("second", payload)
	if _, err := second.Repository().Put(ctx, envelope, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	check(assurance.AssuranceStateVerified)
	restored, err := storage.NewFilesystemEvidenceRepository(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	reopenedSigner, err := receipts.LoadOrCreateReceiptManager(f.producer, f.keyDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedSigner.PublicKey() != f.signer.PublicKey() {
		t.Fatal("persistent signing identity changed")
	}
	restarted, err := collection.NewCandidates(restored, []collection.SourceConfig{{ID: "tetragon", Producer: f.producer, Signer: reopenedSigner}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err = evaluation.NewEvaluator(restarted, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	check(assurance.AssuranceStateUnknown)
	archived, err = restored.ListBySubject(ctx, f.subject)
	if err != nil || len(archived) != 2 {
		t.Fatal("restart did not preserve both archived observations")
	}
	t.Log("RUNNING verified -> UNAVAILABLE unknown -> new STARTING unknown -> new observation verified -> process-local restart unknown; two signed observations remain on disk")
}

func TestSaturationAndWrongProducerHoldSources(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	candidates, err := collection.NewCandidates(f.archive, []collection.SourceConfig{{ID: "source", Producer: f.producer, Signer: f.signer}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, err := candidates.BeginSession("source")
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"one", "overflow"} {
		payload := []byte(id)
		_, err := session.Repository().Put(ctx, f.envelope(id, payload), bytes.NewReader(payload))
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i == 1 && !errors.Is(err, collection.ErrSaturated) {
			t.Fatalf("capacity not enforced: %v", err)
		}
	}
	if status := candidates.Snapshot()[0]; status.Lifecycle != collection.SourceSafeHold || status.Eligible != 0 {
		t.Fatal(status)
	}
	archived, err := f.archive.ListBySubject(ctx, f.subject)
	if err != nil || len(archived) != 2 {
		t.Fatal("saturation did not preserve observations")
	}
	evaluator, err := evaluation.NewEvaluator(candidates, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.Evaluate(ctx, f.claim(), f.contract, f.epoch)
	if err != nil || result.State != assurance.AssuranceStateUnknown {
		t.Fatal("saturated source retained positive eligibility")
	}
	if err := session.End("stream ended"); err != nil {
		t.Fatal(err)
	}
	if candidates.Snapshot()[0].Lifecycle != collection.SourceSafeHold {
		t.Fatal("saturation reason erased")
	}
	session, err = candidates.BeginSession("source")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("wrong identity")
	envelope := f.envelope("wrong", payload)
	envelope.Producer.Subject = "wrong.oskal/source"
	if _, err := session.Repository().Put(ctx, envelope, bytes.NewReader(payload)); err == nil {
		t.Fatal("wrong producer signed or admitted")
	}
	if candidates.Snapshot()[0].Lifecycle != collection.SourceUnavailable {
		t.Fatal("invalid producer left source usable")
	}
}

func TestEvidenceSigningRequiresExplicitAuthority(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	payload := []byte("test")
	envelope := f.envelope("one", payload)
	wrong := envelope
	wrong.Producer.Subject = "other.oskal/collector"
	if _, err := f.signer.SignEvidence(ctx, wrong); err == nil {
		t.Fatal("signer asserted a different producer")
	}
	unconfigured, err := receipts.NewReceiptManager(assurance.AuthorityRef{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unconfigured.SignEvidence(ctx, envelope); err == nil {
		t.Fatal("legacy default receipt authority signed runtime evidence")
	}
	signed := f.sign(t, envelope)
	if _, err := f.signer.SignEvidence(ctx, signed); err == nil {
		t.Fatal("already signed envelope was overwritten")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.signer.SignEvidence(cancelled, envelope); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestEndedSessionCannotPublishLateDurableObservation(t *testing.T) {
	for _, operation := range []string{"end", "replace", "concurrent-write"} {
		t.Run(operation, func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			candidates, err := collection.NewCandidates(f.archive, []collection.SourceConfig{{ID: "source", Producer: f.producer, Signer: f.signer}}, 2)
			if err != nil {
				t.Fatal(err)
			}
			session, err := candidates.BeginSession("source")
			if err != nil {
				t.Fatal(err)
			}
			reader, writer := io.Pipe()
			defer func() { _ = reader.Close(); _ = writer.Close() }()
			payload := []byte("first chunk plus remainder")
			done := make(chan error, 1)
			go func() { _, err := session.Repository().Put(ctx, f.envelope("in-flight", payload), reader); done <- err }()
			// The first pipe write returns only once the real ingestion reader consumes it.
			if _, err := writer.Write(payload[:1]); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "end":
				if err := session.End("stream closed while persisting"); err != nil {
					t.Fatal(err)
				}
			case "replace":
				if _, err := candidates.BeginSession("source"); err != nil {
					t.Fatal(err)
				}
			case "concurrent-write":
				second := []byte("parallel observation")
				if _, err := session.Repository().Put(ctx, f.envelope("parallel", second), bytes.NewReader(second)); !errors.Is(err, collection.ErrSourceBusy) {
					t.Fatal(err)
				}
			}
			if _, err := writer.Write(payload[1:]); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, collection.ErrSessionClosed) {
					t.Fatalf("late source write became eligible: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			visible, err := candidates.ListBySubject(ctx, f.subject)
			if err != nil || len(visible) != 0 {
				t.Fatalf("late evidence visible: %d %v", len(visible), err)
			}
			archived, err := f.archive.ListBySubject(ctx, f.subject)
			if err != nil || len(archived) != 1 {
				t.Fatalf("late durable observation lost: %d %v", len(archived), err)
			}
		})
	}
}

func TestConfiguredAdverseEvidenceDominatesPositiveCompleteness(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.contract.Requirements = append(f.contract.Requirements, assurance.EvidenceRequirement{ID: "violation", EvidenceType: "runtime.violation", MaxAge: time.Hour, AcceptedProducers: []string{f.producer.Canonical()}})
	for _, typ := range []string{"runtime.process.exec", "runtime.violation"} {
		payload := []byte(typ)
		envelope := f.envelope(typ, payload)
		envelope.ObservationType = typ
		envelope = f.sign(t, envelope)
		if _, err := f.archive.Put(ctx, envelope, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	result := f.evaluate(t)
	if result.State != assurance.AssuranceStateFailed || result.Completeness.Verified != 1 || result.Completeness.Required != 1 {
		t.Fatalf("adverse fact averaged away: %+v", result)
	}
	f.contract.Requirements[0].Required = false
	if result := f.evaluate(t); result.State != assurance.AssuranceStateUnknown {
		t.Fatalf("optional-only contract inferred a verdict: %+v", result)
	}
}

func TestEmptySourceRegistryNeverFallsBackToArchive(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	payload := []byte("historical observation")
	if _, err := f.archive.Put(ctx, f.sign(t, f.envelope("historical", payload)), bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	candidates, err := collection.NewCandidates(f.archive, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates.Snapshot()) != 0 {
		t.Fatal("empty registry invented a source")
	}
	if _, err := candidates.BeginSession("unconfigured"); err == nil {
		t.Fatal("unconfigured source admitted")
	}
	evaluator, err := evaluation.NewEvaluator(candidates, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluator.Evaluate(ctx, f.claim(), f.contract, f.epoch)
	if err != nil || result.State != assurance.AssuranceStateUnknown || len(result.Evidence) != 0 || result.Completeness.Missing != 1 {
		t.Fatalf("archive restored eligibility: %+v %v", result, err)
	}
	archived, err := f.archive.ListBySubject(ctx, f.subject)
	if err != nil || len(archived) != 1 {
		t.Fatal("empty registry changed archive")
	}
	if _, err := collection.NewCandidates(nil, nil, 1); err == nil {
		t.Fatal("nil archive accepted")
	}
	if _, err := collection.NewCandidates(f.archive, nil, 0); err == nil {
		t.Fatal("zero bound accepted")
	}
}
