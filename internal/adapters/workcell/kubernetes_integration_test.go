package workcell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	assurancev1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// This suite requires the real CapabilityLease CRD and a dedicated API server.
// It intentionally retains its oskal-lease-* namespace for evidence inspection.
func TestKubernetesBrokerIntegration(t *testing.T) {
	kubeconfig := os.Getenv("OSKAL_LEASE_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("set OSKAL_LEASE_KUBECONFIG to a dedicated real cluster")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	principal, err := NewKubernetesPrincipal(config)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := principal.AuthenticatedPrincipal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewKubernetesBroker(config, principal)
	if err != nil {
		t.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	namespace := fmt.Sprintf("oskal-lease-%d", time.Now().UnixNano())
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Logf("real API=%s namespace=%s authenticated principal=%s", config.Host, namespace, actor)
	create := func(name string, turns int) *assurancev1.CapabilityLease {
		t.Helper()
		lease := &assurancev1.CapabilityLease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: assurancev1.CapabilityLeaseSpec{Principal: actor, Scope: "utcp://registry/tool/example.write", AllowedCapabilities: []string{"utcp:execute-tool"}, MaxTurns: turns, TTL: metav1.Duration{Duration: time.Hour}}}
		if err := broker.client.Create(ctx, lease); err != nil {
			t.Fatal(err)
		}
		issued := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		expires := metav1.NewTime(issued.Add(time.Hour))
		lease.Status = assurancev1.CapabilityLeaseStatus{Phase: "Active", IssuedAt: &issued, ExpiresAt: &expires, ObservedGeneration: lease.Generation}
		if err := broker.client.Status().Update(ctx, lease); err != nil {
			t.Fatal(err)
		}
		return lease
	}
	request := func(lease *assurancev1.CapabilityLease, id string) assurance.ExecutionRequest {
		return assurance.ExecutionRequest{LeaseNamespace: namespace, LeaseName: lease.Name, LeaseUID: string(lease.UID), Resource: lease.Spec.Scope, Capability: "utcp:execute-tool", RequestID: id, Payload: []byte("write actual filesystem evidence")}
	}
	dir := t.TempDir()
	var effects atomic.Int32
	effect := func(ctx context.Context) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := effects.Add(1)
		path := filepath.Join(dir, fmt.Sprintf("effect-%d", n))
		if err := os.WriteFile(path, []byte(fmt.Sprintf("actual-effect-%d", n)), 0600); err != nil {
			return nil, err
		}
		return os.ReadFile(path)
	}
	t.Run("completion-and-turn-limit", func(t *testing.T) {
		lease := create("bounded", 2)
		r := request(lease, "first")
		first, err := broker.Execute(ctx, r, effect)
		if err != nil {
			t.Fatal(err)
		}
		r.RequestID = "second"
		r.PreviousAdmissionHash = first.Admission.Hash
		second, err := broker.Execute(ctx, r, effect)
		if err != nil {
			t.Fatal(err)
		}
		if second.PreviousHash != first.Hash || second.Admission.PreviousHash != first.Admission.Hash {
			t.Fatal("broken receipt/admission lineage")
		}
		before := effects.Load()
		r.RequestID = "third"
		r.PreviousAdmissionHash = second.Admission.Hash
		if _, err := broker.Execute(ctx, r, effect); err == nil {
			t.Fatal("turn budget bypass")
		}
		if effects.Load() != before {
			t.Fatal("effect after exhausted lease")
		}
		stored := &assurancev1.CapabilityLease{}
		if err := broker.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: lease.Name}, stored); err != nil {
			t.Fatal(err)
		}
		if len(stored.Status.ExecutionHistory) != 2 || stored.Status.PendingExecution != nil || stored.Status.LastExecutionHash != second.Hash {
			t.Fatalf("completion not persisted: %+v", stored.Status)
		}
		expected, err := assurance.CompleteExecution(second.Admission, []byte("actual-effect-2"), first.Hash, second.CompletedAt)
		if err != nil || expected.Hash != second.Hash {
			t.Fatal("result digest/receipt mismatch")
		}
		t.Logf("actual filesystem effects=%d persisted receipts=%d last=%s", effects.Load(), len(stored.Status.ExecutionHistory), second.Hash)
	})
	t.Run("identity-scope-uid-capability-chain-and-ttl", func(t *testing.T) {
		lease := create("denials", 3)
		base := request(lease, "denied")
		cases := map[string]func(*assurance.ExecutionRequest){"scope": func(r *assurance.ExecutionRequest) { r.Resource += "/other" }, "uid": func(r *assurance.ExecutionRequest) { r.LeaseUID = "wrong-uid" }, "capability": func(r *assurance.ExecutionRequest) { r.Capability = "*" }, "chain": func(r *assurance.ExecutionRequest) { r.PreviousAdmissionHash = "wrong" }}
		before := effects.Load()
		for name, change := range cases {
			r := base
			change(&r)
			if _, err := broker.Execute(ctx, r, effect); err == nil {
				t.Fatalf("%s admitted", name)
			}
		}
		lease.Spec.Principal = "untrusted-claim"
		if err := broker.client.Update(ctx, lease); err == nil {
			t.Fatal("immutable grant was mutated")
		}
		foreign := &assurancev1.CapabilityLease{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: namespace}, Spec: lease.Spec}
		if err := broker.client.Create(ctx, foreign); err != nil {
			t.Fatal(err)
		}
		foreign.Status = lease.Status
		foreign.Status.ObservedGeneration = foreign.Generation
		if err := broker.client.Status().Update(ctx, foreign); err != nil {
			t.Fatal(err)
		}
		if _, err := broker.Execute(ctx, request(foreign, "foreign"), effect); err == nil {
			t.Fatal("authenticated actor mismatch admitted")
		}
		expired := create("expired", 1)
		issued := metav1.NewTime(time.Now().Add(-2 * time.Hour).Truncate(time.Second))
		expires := metav1.NewTime(issued.Add(time.Hour))
		expired.Status.IssuedAt = &issued
		expired.Status.ExpiresAt = &expires
		if err := broker.client.Status().Update(ctx, expired); err != nil {
			t.Fatal(err)
		}
		if _, err := broker.Execute(ctx, request(expired, "expired"), effect); err == nil {
			t.Fatal("expired lease admitted")
		}
		if effects.Load() != before {
			t.Fatal("denied request ran effect")
		}
		t.Log("wrong UID, exact scope, capability, chain, principal, immutable grants and expiry denied with zero effects")
	})
	t.Run("concurrent-reservation-and-revocation", func(t *testing.T) {
		lease := create("concurrency", 3)
		r := request(lease, "winner")
		entered := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := broker.Execute(ctx, r, func(ctx context.Context) ([]byte, error) { close(entered); <-release; return effect(ctx) })
			done <- err
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		var wg sync.WaitGroup
		var admitted atomic.Int32
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				candidate := r
				candidate.RequestID = fmt.Sprint(i)
				if _, err := broker.Execute(ctx, candidate, effect); err == nil {
					admitted.Add(1)
				}
			}(i)
		}
		wg.Wait()
		stored := &assurancev1.CapabilityLease{}
		key := types.NamespacedName{Namespace: namespace, Name: lease.Name}
		if err := broker.client.Get(ctx, key, stored); err != nil {
			t.Fatal(err)
		}
		stored.Status.Phase = "Revoked"
		stored.Status.RevocationReason = "integration revocation"
		if err := broker.client.Status().Update(ctx, stored); err != nil {
			t.Fatal(err)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if admitted.Load() != 0 {
			t.Fatal("parallel effect admitted")
		}
		if err := broker.client.Get(ctx, key, stored); err != nil {
			t.Fatal(err)
		}
		if stored.Status.Phase != "Revoked" || len(stored.Status.ExecutionHistory) != 1 {
			t.Fatal("completion overwrote revocation or lost receipt")
		}
		r.RequestID = "after-revoke"
		r.PreviousAdmissionHash = stored.Status.LastAdmissionHash
		before := effects.Load()
		if _, err := broker.Execute(ctx, r, effect); err == nil {
			t.Fatal("revoked lease admitted")
		}
		if effects.Load() != before {
			t.Fatal("revoked effect")
		}
		t.Log("20 concurrent contenders denied; already-admitted effect completed; revocation preserved and new effect denied")
	})
	t.Run("ambiguous-effect-survives-broker-restart", func(t *testing.T) {
		lease := create("pending", 2)
		r := request(lease, "uncertain")
		before := effects.Load()
		if _, err := broker.Execute(ctx, r, func(ctx context.Context) ([]byte, error) {
			_, err := effect(ctx)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("connection lost after write")
		}); !errors.Is(err, ErrExecutionUncertain) {
			t.Fatalf("uncertainty not preserved: %v", err)
		}
		restarted, err := NewKubernetesBroker(config, principal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := restarted.Execute(ctx, r, effect); !errors.Is(err, ErrExecutionUncertain) {
			t.Fatalf("restart replay: %v", err)
		}
		stored := &assurancev1.CapabilityLease{}
		if err := broker.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: lease.Name}, stored); err != nil {
			t.Fatal(err)
		}
		if effects.Load() != before+1 || stored.Status.PendingExecution == nil || stored.Status.CurrentTurn != 1 || len(stored.Status.ExecutionHistory) != 0 {
			t.Fatal("uncertain turn refunded, replayed, or represented as completed")
		}
		t.Logf("actual write count=1 after restart; pending admission=%s; completion receipts=0", stored.Status.PendingExecution.Hash)
	})
	t.Run("simultaneous-api-cas", func(t *testing.T) {
		lease := create("cas-race", 3)
		before := effects.Load()
		start := make(chan struct{})
		var wg sync.WaitGroup
		var successes atomic.Int32
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if _, err := broker.Execute(ctx, request(lease, fmt.Sprint(i)), effect); err == nil {
					successes.Add(1)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if successes.Load() != 1 || effects.Load() != before+1 {
			t.Fatalf("CAS admitted %d callbacks %d", successes.Load(), effects.Load()-before)
		}
		t.Log("8 simultaneous real API admissions: exactly one callback and completion")
	})
	t.Run("abrupt-process-exit", func(t *testing.T) {
		lease := create("process-crash", 2)
		marker := filepath.Join(dir, "crash-effect")
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKubernetesBrokerCrashChild$", "-test.v")
		command.Env = append(os.Environ(), "OSKAL_LEASE_CRASH_CHILD="+namespace+"/"+lease.Name+"/"+string(lease.UID), "OSKAL_LEASE_CRASH_MARKER="+marker)
		output, err := command.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 73 {
			t.Fatalf("child did not exit after actual effect: %v %s", err, output)
		}
		if data, err := os.ReadFile(marker); err != nil || string(data) != "written-before-process-exit" {
			t.Fatalf("child effect not observed: %q %v", data, err)
		}
		restarted, err := NewKubernetesBroker(config, principal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := restarted.Execute(ctx, request(lease, "after-process-crash"), effect); !errors.Is(err, ErrExecutionUncertain) {
			t.Fatalf("process crash replayed: %v", err)
		}
		t.Log("separate process wrote file then exited 73; fresh broker denied replay of durable pending turn")
	})

	t.Run("cancel-and-unavailable-api", func(t *testing.T) {
		lease := create("cancel", 1)
		r := request(lease, "cancel")
		cancelled, cancelNow := context.WithCancel(ctx)
		cancelNow()
		before := effects.Load()
		if _, err := broker.Execute(cancelled, r, effect); err == nil {
			t.Fatal("cancelled request admitted")
		}
		unavailable := *config
		unavailable.Host = "https://127.0.0.1:1"
		disconnected, err := NewKubernetesBroker(&unavailable, principal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := disconnected.Execute(ctx, r, effect); err == nil {
			t.Fatal("unavailable API admitted")
		}
		if effects.Load() != before {
			t.Fatal("effect without proof")
		}
		t.Log("cancelled request and unavailable authoritative API denied with zero effects")
	})
}

func TestKubernetesBrokerCrashChild(t *testing.T) {
	identity := strings.Split(os.Getenv("OSKAL_LEASE_CRASH_CHILD"), "/")
	if len(identity) != 3 {
		t.Skip("controlled subprocess only")
	}
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("OSKAL_LEASE_KUBECONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := NewKubernetesPrincipal(config)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewKubernetesBroker(config, principal)
	if err != nil {
		t.Fatal(err)
	}
	request := assurance.ExecutionRequest{LeaseNamespace: identity[0], LeaseName: identity[1], LeaseUID: identity[2], Resource: "utcp://registry/tool/example.write", Capability: "utcp:execute-tool", RequestID: "crash-process", Payload: []byte("crash after file write")}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err = broker.Execute(ctx, request, func(context.Context) ([]byte, error) {
		if err := os.WriteFile(os.Getenv("OSKAL_LEASE_CRASH_MARKER"), []byte("written-before-process-exit"), 0600); err != nil {
			return nil, err
		}
		os.Exit(73)
		panic("unreachable after process termination")
	})
	t.Fatalf("child failed before controlled process exit: %v", err)
}
