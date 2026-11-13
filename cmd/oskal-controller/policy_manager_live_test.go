package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
)

// This test starts the actual manager against caller-authorized existing policy
// APIs. It creates no fake API, engine, reports, or capture results.
func TestRealManagerPolicyCapture(t *testing.T) {
	kubeconfig, sources := os.Getenv("OSKAL_POLICY_CONTROLLER_KUBECONFIG"), os.Getenv("OSKAL_POLICY_CONTROLLER_SOURCES")
	namespace := os.Getenv("OSKAL_POLICY_CONTROLLER_NAMESPACE")
	if kubeconfig == "" || sources == "" || namespace == "" {
		t.Skip("explicit real API, owned mutation namespace, and existing report/constraint sources required")
	}
	configuration, err := readSourceConfiguration(sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Sources) == 0 {
		t.Fatal("real policy source required")
	}
	expected := map[string]bool{}
	for _, source := range configuration.Sources {
		switch source.Kind {
		case "policy-report":
			expected["policy.report.snapshot"] = false
		case "gatekeeper":
			expected["policy.gatekeeper.audit.observed"] = false
		default:
			t.Fatal("this test requires actual report/constraint engines; OPA delivery is a separate live check")
		}
	}
	directory := os.Getenv("OSKAL_POLICY_CONTROLLER_EVIDENCE")
	if directory == "" {
		directory = t.TempDir()
	} else {
		directory = filepath.Join(directory, t.Name())
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(t.TempDir(), "oskal-controller")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual manager: %v %s", err, output)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probeAddress := probe.Addr().String()
	_ = probe.Close()
	logfile, err := os.Create(filepath.Join(directory, "manager.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logfile.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--sources", sources, "--namespace", namespace, "--evidence-dir", filepath.Join(directory, "store"), "--enable-webhook=false", "--leader-elect=false", "--metrics-bind-address=0", "--health-probe-bind-address", probeAddress, "--source-session-window=10s")
	command.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	command.Stdout = logfile
	command.Stderr = logfile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		if err := command.Wait(); err != nil {
			data, _ := os.ReadFile(logfile.Name())
			t.Errorf("actual manager exit: %v %s", err, data)
		}
	}()
	store := filepath.Join(directory, "store")
	var envelopes []assurance.EvidenceEnvelope
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		repository, err := storage.OpenFilesystemEvidenceRepository(store)
		if err == nil {
			envelopes, err = repository.ListAll(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, envelope := range envelopes {
				if _, ok := expected[envelope.ObservationType]; ok {
					expected[envelope.ObservationType] = true
				}
			}
		}
		complete := true
		for _, seen := range expected {
			complete = complete && seen
		}
		if complete {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for observation, seen := range expected {
		if !seen {
			data, _ := os.ReadFile(logfile.Name())
			t.Fatalf("actual manager did not capture %s: %s", observation, data)
		}
	}
	raw, err := os.ReadFile(filepath.Join(store, "configuration", "producer-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]string
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	signatureVerifier := verifier.NewDefaultEvidenceVerifier()
	for identity, encoded := range keys {
		key, err := hex.DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			t.Fatal("invalid actual persisted public key")
		}
		signatureVerifier.RegisterPublicKey(identity, ed25519.PublicKey(key))
	}
	repository, err := storage.OpenFilesystemEvidenceRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, envelope := range envelopes {
		if _, ok := expected[envelope.ObservationType]; !ok {
			continue
		}
		verified, err := signatureVerifier.VerifySignature(ctx, envelope)
		if err != nil || !verified {
			t.Fatalf("actual capture signature failed: %v", err)
		}
		if len(envelope.ControlRefs) != 0 || envelope.Epoch.SubjectDigest == "" || envelope.Epoch.PolicyDigest != "" || envelope.Epoch.ImplementationDigest != "" || envelope.Epoch.AuthorityDigest != "" || envelope.Epoch.EnvironmentDigest != "" {
			t.Fatalf("capture invented control or full epoch: %+v", envelope)
		}
		reader, err := repository.Get(ctx, envelope.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		payload, readErr := io.ReadAll(reader)
		if err := errors.Join(readErr, reader.Close()); err != nil {
			t.Fatal(err)
		}
		if assurance.ComputeDigest(payload) != envelope.Artifact.Digest {
			t.Fatal("actual stored bytes differ from signed artifact binding")
		}
		if !strings.Contains(string(payload), "UNKNOWN") {
			t.Fatal("actual report/audit policy revision gap was erased")
		}
		t.Logf("VERIFIED actual manager -> %s -> metadata-only target UID -> signed CAS digest=%s subject=%s; control standing remains UNKNOWN", envelope.ObservationType, envelope.Artifact.Digest, envelope.Subject.URI())
	}
	t.Logf("actual manager evidence retained at %s", directory)
}
