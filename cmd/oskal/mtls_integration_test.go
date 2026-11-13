package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	assurancev1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRealCLIHTTPMTLSLease(t *testing.T) {
	socket, id, kubeconfig := os.Getenv("OSKAL_SPIRE_TEST_SOCKET"), os.Getenv("OSKAL_SPIRE_TEST_ID"), os.Getenv("OSKAL_CLI_KUBECONFIG")
	if socket == "" || kubeconfig == "" {
		t.Skip("explicit real SPIRE and Kubernetes test backends required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Timeout = 5 * time.Second
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, assurancev1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	api, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("oskal-cli-mtls-%d", time.Now().UnixNano())}}
	if err := api.Create(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	makeLease := func(name, principal string) *assurancev1.CapabilityLease {
		t.Helper()
		lease := &assurancev1.CapabilityLease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace.Name}, Spec: assurancev1.CapabilityLeaseSpec{Principal: principal, Scope: "utcp://registry/tool/oskal.run_doctor", AllowedCapabilities: []string{"utcp:run-doctor"}, MaxTurns: 1, TTL: metav1.Duration{Duration: time.Hour}}}
		if err := api.Create(ctx, lease); err != nil {
			t.Fatal(err)
		}
		issued := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		expires := metav1.NewTime(issued.Add(time.Hour))
		lease.Status = assurancev1.CapabilityLeaseStatus{Phase: "Active", IssuedAt: &issued, ExpiresAt: &expires, ObservedGeneration: lease.Generation}
		if err := api.Status().Update(ctx, lease); err != nil {
			t.Fatal(err)
		}
		return lease
	}
	identity, err := spire.NewWorkloadClient(ctx, socket, id, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = identity.Close() }()
	tlsConfig, err := identity.TLSClientConfig(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	logfile, err := os.Create(filepath.Join(t.TempDir(), "http-server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logfile.Close() }()
	command := exec.CommandContext(ctx, buildCLI(t), "utcp", "serve", "--addr", addr, "--base-url", "https://"+addr, "--lease-kubeconfig", kubeconfig, "--workload-api", socket, "--spiffe-id", id, "--allowed-peer-id", id)
	command.Stdout = logfile
	command.Stderr = logfile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		if err := command.Wait(); err != nil {
			data, _ := os.ReadFile(logfile.Name())
			t.Errorf("server shutdown: %v: %s", err, data)
		}
	}()
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	base := "https://" + addr
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
		response, err := httpClient.Do(req)
		if err == nil {
			_ = response.Body.Close()
			ready = response.StatusCode == 200
			if ready {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		data, _ := os.ReadFile(logfile.Name())
		t.Fatalf("actual CLI mTLS server unavailable: %s", data)
	}
	call := func(lease *assurancev1.CapabilityLease, want int) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"tool_name": "run_doctor", "lease_id": namespace.Name + "/" + lease.Name + "/" + string(lease.UID), "arguments": map[string]any{"principal": lease.Spec.Principal}})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/tools/call", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Principal", lease.Spec.Principal)
		response, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("HTTP %d want %d: %s", response.StatusCode, want, data)
		}
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		if want == 200 && result["receipt"] == nil {
			t.Fatalf("execution receipt missing: %s", data)
		}
		t.Logf("actual mTLS HTTP status=%d lease=%s caller=%s", response.StatusCode, lease.Name, id)
	}
	wrong := makeLease("spoofed-principal", "different-principal")
	call(wrong, 400)
	allowed := makeLease("authenticated-peer", id)
	call(allowed, 200)
	call(allowed, 400)
	for _, lease := range []*assurancev1.CapabilityLease{wrong, allowed} {
		var actual assurancev1.CapabilityLease
		if err := api.Get(ctx, client.ObjectKeyFromObject(lease), &actual); err != nil {
			t.Fatal(err)
		}
		want := 0
		if lease.Name == allowed.Name {
			want = 1
		}
		if actual.Status.CurrentTurn != want || len(actual.Status.ExecutionHistory) != want || actual.Status.PendingExecution != nil {
			t.Fatalf("lease outcome: %+v", actual.Status)
		}
	}
	// A plaintext request never supplies authenticated transport state.
	plain := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	response, err := plain.Do(req)
	if err == nil {
		_ = response.Body.Close()
		if response.StatusCode == 200 {
			t.Fatal("plaintext reached authenticated server")
		}
	}
	t.Logf("VERIFIED actual CLI subprocess SPIFFE mTLS -> fresh peer principal -> Kubernetes durable lease -> run_doctor -> receipt; spoof/replay/plaintext denied; retained namespace=%s", namespace.Name)
}
