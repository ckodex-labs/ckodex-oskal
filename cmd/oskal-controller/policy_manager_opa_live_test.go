package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/opa"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/policyreports"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/clientcmd"
)

type policyLiveProcess struct {
	command *exec.Cmd
	done    chan error
	once    sync.Once
}

func startPolicyLiveProcess(t *testing.T, ctx context.Context, binary, logPath string, environment []string, args ...string) *policyLiveProcess {
	t.Helper()
	logfile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = environment
	command.Stdout = logfile
	command.Stderr = logfile
	if err := command.Start(); err != nil {
		_ = logfile.Close()
		t.Fatal(err)
	}
	process := &policyLiveProcess{command: command, done: make(chan error, 1)}
	go func() { err := command.Wait(); _ = logfile.Close(); process.done <- err }()
	t.Cleanup(func() { process.stop(t) })
	return process
}
func (p *policyLiveProcess) stop(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		_ = p.command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-p.done:
			if err != nil {
				t.Errorf("actual process %s exit: %v", p.command.Path, err)
			}
		case <-time.After(6 * time.Second):
			_ = p.command.Process.Kill()
			err := <-p.done
			t.Errorf("actual process failed graceful shutdown: %v", err)
		}
	})
}
func policyLiveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
func writePolicyLiveJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func policyLiveKeyVerifier(t *testing.T, store string) *verifier.DefaultEvidenceVerifier {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(store, "configuration", "producer-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]string
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	result := verifier.NewDefaultEvidenceVerifier()
	for identity, text := range keys {
		key, err := hex.DecodeString(text)
		if err != nil || len(key) != ed25519.PublicKeySize {
			t.Fatal("invalid actual persisted public key")
		}
		result.RegisterPublicKey(identity, ed25519.PublicKey(key))
	}
	return result
}

// This test runs the actual native OPA log plugin into the actual manager's
// configured TLS listener. Its only API reads are owned subject metadata.
func TestRealManagerOPACapture(t *testing.T) {
	kubeconfig, namespace, binary := os.Getenv("OSKAL_POLICY_CONTROLLER_KUBECONFIG"), os.Getenv("OSKAL_POLICY_CONTROLLER_NAMESPACE"), os.Getenv("OSKAL_POLICY_OPA_BINARY")
	if kubeconfig == "" || namespace == "" || binary == "" {
		t.Skip("explicit owned API, mutation namespace, and actual OPA binary required")
	}
	caPath, serverCert, serverKey := os.Getenv("OSKAL_POLICY_TLS_CA"), os.Getenv("OSKAL_POLICY_TLS_SERVER_CERT"), os.Getenv("OSKAL_POLICY_TLS_SERVER_KEY")
	clientCert, clientKey, caKey := os.Getenv("OSKAL_POLICY_TLS_CLIENT_CERT"), os.Getenv("OSKAL_POLICY_TLS_CLIENT_KEY"), os.Getenv("OSKAL_POLICY_TLS_CA_KEY")
	if caPath == "" || serverCert == "" || serverKey == "" || clientCert == "" || clientKey == "" || caKey == "" {
		t.Fatal("explicit owned test CA/server/client paths including test CA key required")
	}
	version, err := exec.CommandContext(t.Context(), binary, "version").CombinedOutput()
	if err != nil || !bytes.Contains(version, []byte("Version: 1.22.4\n")) {
		t.Fatalf("actual required OPA1.22.4 missing: %v %s", err, version)
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
	if err := os.WriteFile(filepath.Join(directory, "opa-version.txt"), version, 0600); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid explicit test CA")
	}
	publisherCert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(publisherCert.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 {
		t.Fatal("exact actual publisher URI required")
	}
	publisher := leaf.URIs[0].String()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Timeout = 5 * time.Second
	api, err := metadata.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	subjects := map[string]map[string]string{}
	for _, name := range []string{"has-team", "missing-team"} {
		object, err := api.Resource(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}).Namespace(namespace).Get(t.Context(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		subjects[name] = map[string]string{"apiVersion": "v1", "kind": "ConfigMap", "namespace": namespace, "name": name, "uid": string(object.UID)}
	}
	sourceDirectory := filepath.Join(directory, "source")
	if err := os.MkdirAll(sourceDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"policy.rego": "package oskal.authz\ndefault allow := false\nallow if input.subject.name == \"has-team\"\n", "mask.rego": "package system.log\nmask contains \"/input/secret\"\ndrop if input.path != \"oskal/authz/allow\"\n"} {
		if err := os.WriteFile(filepath.Join(sourceDirectory, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bundlePath := filepath.Join(directory, "policy.tar.gz")
	if output, err := exec.CommandContext(t.Context(), binary, "build", "--bundle", sourceDirectory, "--revision", "manager-policy-v1", "--output", bundlePath).CombinedOutput(); err != nil {
		t.Fatalf("actual OPA bundle build: %v %s", err, output)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundleTLS, _, _, err := policyServerTLS(opaSourceSpec{ServerCertFile: serverCert, ServerKeyFile: serverKey, ClientCAFile: caPath})
	if err != nil {
		t.Fatal(err)
	}
	bundleListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bundleServer := &http.Server{TLSConfig: bundleTLS, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bundle.tar.gz" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(bundle)
	})}
	bundleDone := make(chan error, 1)
	go func() { bundleDone <- bundleServer.ServeTLS(bundleListener, "", "") }()
	t.Cleanup(func() {
		_ = bundleServer.Close()
		if err := <-bundleDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("actual artifact server: %v", err)
		}
	})
	managerAddress, probeAddress, opaAddress := policyLiveAddress(t), policyLiveAddress(t), policyLiveAddress(t)
	configuration := sourceConfiguration{Sources: []sourceSpec{{ID: "native-opa-manager", Kind: "opa", PolicyMode: "CAPTURE", OPA: &opaSourceSpec{Listen: managerAddress, TLSMode: "pki", ExpectedPublisher: publisher, DecisionPath: "oskal/authz/allow", BundleName: "oskal", AllowResult: json.RawMessage("true"), DenyResult: json.RawMessage("false"), RequestTimeout: "5s", ServerCertFile: serverCert, ServerKeyFile: serverKey, ClientCAFile: caPath}}}}
	sourcesPath := filepath.Join(directory, "manager-sources.json")
	writePolicyLiveJSON(t, sourcesPath, configuration)
	if _, err := readSourceConfiguration(sourcesPath); err != nil {
		t.Fatal(err)
	}
	managerBinary := filepath.Join(t.TempDir(), "oskal-controller")
	if output, err := exec.CommandContext(t.Context(), "go", "build", "-o", managerBinary, ".").CombinedOutput(); err != nil {
		t.Fatalf("actual manager build: %v %s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	store := filepath.Join(directory, "store")
	managerLog := filepath.Join(directory, "manager.log")
	startPolicyLiveProcess(t, ctx, managerBinary, managerLog, append(os.Environ(), "KUBECONFIG="+kubeconfig), "--sources", sourcesPath, "--namespace", namespace, "--evidence-dir", store, "--enable-webhook=false", "--leader-elect=false", "--metrics-bind-address=0", "--health-probe-bind-address", probeAddress, "--source-session-window=10s")
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{publisherCert}}}
	defer transport.CloseIdleConnections()
	secure := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+managerAddress+"/logs", nil)
		response, err := secure.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusMethodNotAllowed {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		data, _ := os.ReadFile(managerLog)
		t.Fatalf("actual manager listener not ready: %s", data)
	}
	clientTLS := map[string]any{"ca_cert": caPath}
	credentials := map[string]any{"client_tls": map[string]any{"cert": clientCert, "private_key": clientKey}}
	opaConfig := map[string]any{"services": map[string]any{"capture": map[string]any{"url": "https://" + managerAddress, "tls": clientTLS, "credentials": credentials}, "artifact": map[string]any{"url": "https://" + bundleListener.Addr().String(), "tls": clientTLS, "credentials": credentials}}, "bundles": map[string]any{"oskal": map[string]any{"service": "artifact", "resource": "/bundle.tar.gz", "polling": map[string]any{"min_delay_seconds": 1, "max_delay_seconds": 2}}}, "decision_logs": map[string]any{"service": "capture", "resource": "/logs", "reporting": map[string]any{"min_delay_seconds": 1, "max_delay_seconds": 1}}}
	opaConfigPath := filepath.Join(directory, "opa-config.json")
	writePolicyLiveJSON(t, opaConfigPath, opaConfig)
	opaLog := filepath.Join(directory, "opa.log")
	native := startPolicyLiveProcess(t, ctx, binary, opaLog, os.Environ(), "run", "--server", "--addr", opaAddress, "--config-file", opaConfigPath, "--skip-version-check", "--shutdown-grace-period=3")
	local := &http.Client{Timeout: 2 * time.Second}
	ready = false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		response, err := local.Get("http://" + opaAddress + "/health?bundles=true")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		data, _ := os.ReadFile(opaLog)
		t.Fatalf("actual OPA bundle activation failed: %s", data)
	}
	decisions := map[string]bool{}
	for _, name := range []string{"has-team", "missing-team"} {
		query, err := json.Marshal(map[string]any{"input": map[string]any{"subject": subjects[name], "secret": "OPA_MANAGER_INPUT_MUST_NOT_PERSIST"}})
		if err != nil {
			t.Fatal(err)
		}
		response, err := local.Post("http://"+opaAddress+"/v1/data/oskal/authz/allow", "application/json", bytes.NewReader(query))
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			ID     string `json:"decision_id"`
			Result bool   `json:"result"`
		}
		decodeErr := json.NewDecoder(response.Body).Decode(&result)
		_ = response.Body.Close()
		if decodeErr != nil || response.StatusCode != 200 || result.ID == "" || result.Result != (name == "has-team") {
			t.Fatalf("actual OPA decision mismatch: %+v %v", result, decodeErr)
		}
		decisions[result.ID] = result.Result
	}
	seen := map[string]bool{}
	var sourceBytes []byte
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		repository, err := storage.OpenFilesystemEvidenceRepository(store)
		if err != nil {
			t.Fatal(err)
		}
		envelopes, err := repository.ListAll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		verify := policyLiveKeyVerifier(t, store)
		for _, envelope := range envelopes {
			reader, err := repository.Get(ctx, envelope.Artifact)
			if err != nil {
				// A disk observer can see a just-published envelope before the
				// writer completes its payload publication. Never treat that
				// in-flight filesystem snapshot as successful evidence.
				path := filepath.Join(store, "blobs", "sha256", strings.TrimPrefix(envelope.Artifact.Digest, "sha256:")+".bin")
				if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
					continue
				}
				t.Fatal(err)
			}
			payload, readErr := io.ReadAll(reader)
			if err := errors.Join(readErr, reader.Close()); err != nil {
				t.Fatal(err)
			}
			var record policyreports.Record
			if err := json.Unmarshal(payload, &record); err != nil {
				t.Fatal(err)
			}
			id := record.Metadata["decisionID"]
			expected, ok := decisions[id]
			if !ok || seen[id] {
				continue
			}
			valid, err := verify.VerifySignature(ctx, envelope)
			if err != nil || !valid || assurance.ComputeDigest(payload) != envelope.Artifact.Digest {
				t.Fatalf("actual signed CAS binding failed: %v", err)
			}
			if envelope.Producer.Canonical() != "local://oskal-controller" || record.Metadata["authenticatedPublisher"] != publisher || record.Metadata["observer"] != envelope.Producer.Canonical() {
				t.Fatal("actual publisher and observer identities were conflated")
			}
			if len(envelope.ControlRefs) != 0 || envelope.Epoch.SubjectDigest == "" || envelope.Epoch.PolicyDigest != "" || envelope.Epoch.AuthorityDigest != "" || envelope.Epoch.ImplementationDigest != "" || envelope.Epoch.EnvironmentDigest != "" {
				t.Fatalf("actual capture invented control standing: %+v", envelope)
			}
			var raw struct {
				ID      string `json:"decision_id"`
				Result  bool   `json:"result"`
				Bundles map[string]struct {
					Revision string `json:"revision"`
				} `json:"bundles"`
			}
			if err := json.Unmarshal(record.SourceBytes, &raw); err != nil {
				t.Fatal(err)
			}
			if raw.ID != id || raw.Result != expected || raw.Bundles["oskal"].Revision != "manager-policy-v1" || bytes.Contains(record.SourceBytes, []byte("OPA_MANAGER_INPUT_MUST_NOT_PERSIST")) {
				t.Fatal("actual raw decision lost identity/revision/result or masking")
			}
			mapping := "deny"
			if expected {
				mapping = "allow"
			}
			if record.Metadata["resultMapping"] != mapping || envelope.ObservationType != "policy.opa.decision."+mapping+".observed" {
				t.Fatal("actual explicit result mapping changed")
			}
			seen[id] = true
			sourceBytes = append([]byte(nil), record.SourceBytes...)
			t.Logf("VERIFIED native OPA1.22.4 -> actual manager mTLS -> signed CAPTURE: mapping=%s raw=%s artifact=%s observer=%s publisher=%s; epoch incomplete, controls empty", mapping, assurance.ComputeDigest(record.SourceBytes), envelope.Artifact.Digest, envelope.Producer.Canonical(), publisher)
		}
		if len(seen) == len(decisions) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(seen) != 2 {
		managerData, _ := os.ReadFile(managerLog)
		opaData, _ := os.ReadFile(opaLog)
		t.Fatalf("native decisions did not reach actual manager signed CAS: manager=%s OPA=%s", managerData, opaData)
	}
	native.stop(t)
	assertNoBoundRuntimeSources := func() {
		t.Helper()
		found := false
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			data, err := os.ReadFile(managerLog)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range bytes.Split(data, []byte("\n")) {
				var event struct {
					Sources []sourceOperationalStatus `json:"sources"`
				}
				if json.Unmarshal(line, &event) != nil {
					continue
				}
				for _, source := range event.Sources {
					if source.Mode == "BOUND_RUNTIME" {
						t.Fatal("capture-only manager acquired bound runtime source")
					}
					if source.ID == "native-opa-manager" && source.Mode == "CAPTURE" {
						found = true
					}
				}
			}
			if found {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("actual manager did not expose isolated capture source mode")
	}
	assertNoBoundRuntimeSources()

	wrong := policyWrongPublisherCertificate(t, ca, caKey, publisher+"-wrong")
	wrongTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{wrong}}}
	defer wrongTransport.CloseIdleConnections()
	wrongClient := &http.Client{Transport: wrongTransport, Timeout: 5 * time.Second}
	call := func(client *http.Client, body io.Reader, want int) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+managerAddress+"/logs", body)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Content-Encoding", "gzip")
		request.Header.Set("X-Publisher", publisher)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("actual manager HTTP%d want%d", response.StatusCode, want)
		}
		t.Logf("actual manager handler HTTP%d", response.StatusCode)
	}
	call(wrongClient, strings.NewReader("must not be read as publisher authority"), 401)
	call(secure, strings.NewReader("not gzip"), 400)
	retained := store + "-retained"
	if err := os.Rename(store, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, []byte("owned reversible storage obstruction"), 0600); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		if err := os.Rename(store, store+"-obstruction-retained"); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(retained, store); err != nil {
			t.Error(err)
			return
		}
		restored = true
	}
	defer restore()
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	if _, err := zip.Write(append(append([]byte("["), sourceBytes...), ']')); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	call(secure, bytes.NewReader(compressed.Bytes()), 503)
	restore()
	assertNoBoundRuntimeSources()
	restoredRepository, err := storage.OpenFilesystemEvidenceRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoredRepository.VerifyIntegrity(ctx); err != nil {
		t.Fatalf("retained real CAS history changed: %v", err)
	}
	call(secure, bytes.NewReader(make([]byte, opa.MaxCompressedBytes+1)), 413)
	snapshotStatus := func() collection.SourceStatus {
		t.Helper()
		data, err := os.ReadFile(managerLog)
		if err != nil {
			t.Fatal(err)
		}
		var latest collection.SourceStatus
		for _, line := range bytes.Split(data, []byte("\n")) {
			var entry struct {
				Sources []sourceOperationalStatus `json:"sources"`
			}
			if json.Unmarshal(line, &entry) != nil {
				continue
			}
			for _, status := range entry.Sources {
				if status.ID == "native-opa-manager" {
					latest = status.SourceStatus
				}
			}
		}
		return latest
	}
	var hold collection.SourceStatus
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		hold = snapshotStatus()
		if hold.Lifecycle == collection.SourceSafeHold {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if hold.Lifecycle != collection.SourceSafeHold || hold.Reason == "" {
		t.Fatalf("oversized actual source did not expose SAFE_HOLD: %+v", hold)
	}
	call(secure, bytes.NewReader(compressed.Bytes()), 503)
	time.Sleep(11 * time.Second)
	after := snapshotStatus()
	if after.Lifecycle != collection.SourceSafeHold || after.Reason != hold.Reason {
		t.Fatalf("expiry/retry changed SAFE_HOLD truth: before=%+v after=%+v", hold, after)
	}
	call(secure, bytes.NewReader(compressed.Bytes()), 503)
	assertNoBoundRuntimeSources()
	t.Logf("VERIFIED oversized actual source exposed SAFE_HOLD, stable reason across expiry, next deliveries denied; mode=%s reason=%s", after.Lifecycle, after.Reason)

	t.Logf("VERIFIED actual manager wrongpublisher401, malformedgzip400, real filesystem persistence failure503; retained history intact, bound runtime source view remained empty; evidence=%s", directory)
}

func policyWrongPublisherCertificate(t *testing.T, caPEM []byte, keyPath, identity string) tls.Certificate {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("test CA PEM missing")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(raw)
	if keyBlock == nil {
		t.Fatal("test CA key PEM missing")
	}
	var signer crypto.Signer
	switch keyBlock.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		signer, ok = key.(crypto.Signer)
		if !ok {
			t.Fatal("test CA key cannot sign")
		}
	case "RSA PRIVATE KEY":
		signer, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unsupported owned test CA key encoding")
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Owned negative publisher"}, URIs: []*url.URL{uri}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, root, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: key}
}
