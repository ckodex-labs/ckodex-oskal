package utcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	assurancev1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/workcell"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRegistryKubernetesLeaseIntegration(t *testing.T) {
	kubeconfig := os.Getenv("OSKAL_LEASE_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("set OSKAL_LEASE_KUBECONFIG to a dedicated real cluster")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := workcell.NewKubernetesPrincipal(config)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.AuthenticatedPrincipal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := workcell.NewKubernetesBroker(config, identity)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := assurancev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	leases, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	kubernetesClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	namespace := fmt.Sprintf("oskal-lease-utcp-%d", time.Now().UnixNano())
	if _, err := kubernetesClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	issue := func(name, scope, capability string) string {
		t.Helper()
		lease := &assurancev1.CapabilityLease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: assurancev1.CapabilityLeaseSpec{Principal: principal, Scope: scope, AllowedCapabilities: []string{capability}, MaxTurns: 1, TTL: metav1.Duration{Duration: time.Hour}}}
		if err := leases.Create(ctx, lease); err != nil {
			t.Fatal(err)
		}
		issued := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		expires := metav1.NewTime(issued.Add(time.Hour))
		lease.Status = assurancev1.CapabilityLeaseStatus{Phase: "Active", IssuedAt: &issued, ExpiresAt: &expires, ObservedGeneration: lease.Generation}
		if err := leases.Status().Update(ctx, lease); err != nil {
			t.Fatal(err)
		}
		return namespace + "/" + name + "/" + string(lease.UID)
	}
	reg, err := NewRegistry("", broker)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		data, err := json.Marshal(body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "actual-http-effect.json"), data, 0600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	defer server.Close()
	manual := UTCPManual{Version: ManualVersion, UTCPVersion: UTCPVersion, ManualVersion: ManualVersion, Info: Info{Title: "Payments", Version: "1"}, Tools: []Tool{{Name: "write", Description: "Writes submitted data", Inputs: map[string]interface{}{"type": "object"}, RequiredCapability: "tool:read-evidence", CallTemplate: CallTemplate{CallTemplateType: "http", HTTPMethod: "POST", URL: server.URL}}}}
	if err := reg.RegisterManualWithLease(ctx, "payments", manual, issue("register", "utcp://registry/manual/payments", "utcp:register-manual"), ""); err != nil {
		t.Fatal(err)
	}
	denied := issue("wrong-capability", "utcp://registry/tool/payments.write", "tool:read-evidence")
	if _, err := reg.CallTool(ctx, "payments.write", map[string]interface{}{"value": "denied"}, denied, ""); err == nil {
		t.Fatal("caller-supplied RequiredCapability granted authority")
	}
	if requests.Load() != 0 {
		t.Fatal("denied tool contacted external service")
	}
	leaseID := issue("execute", "utcp://registry/tool/payments.write", "utcp:execute-tool")
	result, err := reg.CallTool(ctx, "write", map[string]interface{}{"value": "actual-write"}, leaseID, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt == nil || result.Receipt.Admission.Resource != "utcp://registry/tool/payments.write" || result.Receipt.Admission.Capability != "utcp:execute-tool" {
		t.Fatalf("receipt does not bind resolved owner/capability: %+v", result.Receipt)
	}
	data, err := os.ReadFile(filepath.Join(dir, "actual-http-effect.json"))
	if err != nil || !strings.Contains(string(data), "actual-write") {
		t.Fatalf("external effect missing: %q %v", data, err)
	}
	if _, err := reg.CallTool(ctx, "payments.write", map[string]interface{}{"value": "replay"}, leaseID, ""); err == nil {
		t.Fatal("exhausted lease replayed")
	}
	if requests.Load() != 1 {
		t.Fatal("external effect executed more than once")
	}
	var status assurancev1.CapabilityLease
	if err := leases.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "execute"}, &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Status.ExecutionHistory) != 1 || status.Status.ExecutionHistory[0].Hash != result.Receipt.Hash {
		t.Fatal("transport receipt differs from durable completion")
	}
	if err := reg.DeregisterManual(ctx, "payments", issue("deregister", "utcp://registry/manual/payments", "utcp:deregister-manual"), ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.GetTool("payments.write"); ok {
		t.Fatal("governed deregistration did not remove tool")
	}
	var discoveries atomic.Int32
	discovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoveries.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(manual)
	}))
	defer discovery.Close()
	provider := ProviderConfig{Name: "remote", ProviderType: "http", URL: discovery.URL, RequiredCapability: "tool:read-evidence", LeaseID: issue("provider-denied", "utcp://registry/provider/remote", "tool:read-evidence")}
	if err := reg.RegisterToolProvider(ctx, provider); err == nil || discoveries.Load() != 0 {
		t.Fatal("provider capability spoof contacted discovery")
	}
	provider.LeaseID = issue("provider-register", "utcp://registry/provider/remote", "utcp:register-provider")
	if err := reg.RegisterToolProvider(ctx, provider); err != nil {
		t.Fatal(err)
	}
	if discoveries.Load() != 1 {
		t.Fatal("provider discovery not executed once")
	}
	if _, ok := reg.GetTool("remote.write"); !ok {
		t.Fatal("provider tool definition not registered")
	}
	if err := leases.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "provider-register"}, &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Status.ExecutionHistory) != 1 || status.Status.ExecutionHistory[0].Admission.Capability != "utcp:register-provider" {
		t.Fatal("provider mutation lacks durable receipt")
	}

	t.Logf("real API namespace=%s; authenticated=%s; actual HTTP/filesystem effects=%d; durable completion=%s", namespace, principal, requests.Load(), result.Receipt.Hash)
}

func TestExternalEffectNeverRetriesOrFollowsRedirect(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTemporaryRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/next")
				w.WriteHeader(status)
			}))
			defer server.Close()
			_, err := executeRemoteHTTPTool(context.Background(), "effect", CallTemplate{CallTemplateType: "http", HTTPMethod: "GET", URL: server.URL}, nil)
			if err == nil || calls.Load() != 1 {
				t.Fatalf("effect repeated or failure hidden: calls=%d error=%v", calls.Load(), err)
			}
		})
	}
}
