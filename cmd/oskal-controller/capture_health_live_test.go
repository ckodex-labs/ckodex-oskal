package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/policycollection"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestRealEmptyReportPollReadinessWithoutEvidence(t *testing.T) {
	kubeconfig := os.Getenv("OSKAL_POLICY_CONTROLLER_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("explicit isolated OSKAL_POLICY_CONTROLLER_KUBECONFIG required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	config.Timeout = 5 * time.Second
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := api.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "oskal-capture-empty-"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained own empty namespace %s UID %s", namespace.Name, namespace.UID)
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := storage.NewFilesystemEvidenceRepository(filepath.Join(t.TempDir(), "archive"))
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "empty-poll-test"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := collection.NewCandidates(archive, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	captures, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "reports", Producer: producer, Signer: signer}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	group := &sourceGroup{candidates: runtime, captureCandidates: captures, producer: producer, window: 5 * time.Second}
	source := preparedSource{spec: sourceSpec{ID: "reports", Kind: "policy-report", PolicyMode: "CAPTURE"}, policy: &preparedPolicySource{report: &policycollection.ReportsConfig{Client: client, GVR: schema.GroupVersionResource{Group: "openreports.io", Version: "v1alpha1", Resource: "reports"}, Kind: "Report", Namespace: namespace.Name, Producer: producer, PollInterval: time.Second, RequestTimeout: 3 * time.Second, MaxObjects: 1, MaxBatchBytes: 4096}}}
	batches := &policyBatches{group: group, source: source}
	if err := group.Ready(nil); err == nil {
		t.Fatal("report transport became ready before actual polling")
	}
	run, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- group.runPolicy(run, source, batches) }()
	defer func() {
		stop()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("report runner stop: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("report runner exceeded shutdown bound")
		}
	}()
	for group.Ready(nil) != nil {
		select {
		case err := <-done:
			t.Fatalf("actual empty poll failed: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	status := group.Snapshot()
	if len(status) != 1 || status[0].Transport != "POLLING" || status[0].Eligible != 0 || status[0].Lifecycle == collection.SourceRunning || runtime.Revision() != 0 {
		t.Fatalf("empty poll invented evidence or runtime standing: %+v", status)
	}
	t.Logf("actual empty report poll: service ready, eligible=%d, capture=%s, bound runtime sources=%d", status[0].Eligible, status[0].Lifecycle, len(runtime.Snapshot()))
	stop()
	deadline := time.Now().Add(5 * time.Second)
	for group.Ready(nil) == nil {
		if time.Now().After(deadline) {
			t.Fatal("stopped poller retained service readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
