// Command demo deploys a real controller and Tetragon into a fresh retained Kind
// cluster, then verifies signed control receipts before and after source loss.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const systemNamespace = "oskal-system"
const workloadNamespace = "oskal-demo"
const workloadName = "capture-workload"
const bindingName = workloadName + "-binding"
const evidenceDir = "/var/lib/oskal/evidence"
const tetragonVersion = "1.8.0"

type demo struct {
	source, dir, name, kubeconfig, node, architecture, image, imageConfig, imageIndex, hostCLI, publicKey string
	kube                                                                                                  kubernetes.Interface
	dynamic                                                                                               dynamic.Interface
	workloadUID, bindingUID                                                                               string
}

func main() {
	source := flag.String("source", ".", "Checkout used to build the actual controller and verification CLI")
	artifacts := flag.String("artifacts", "", "New artifact directory outside the checkout (default: unique temporary directory)")
	chart := flag.String("tetragon-chart", "", "Optional local official Tetragon 1.8.0 chart archive")
	timeout := flag.Duration("timeout", 10*time.Minute, "Overall bounded demo deadline (1m..30m)")
	flag.Parse()
	if flag.NArg() != 0 || *timeout < time.Minute || *timeout > 30*time.Minute {
		fmt.Fprintln(os.Stderr, "demo requires supported flags and a deadline between 1m and 30m")
		os.Exit(1)
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	if err := run(ctx, *source, *artifacts, *chart); err != nil {
		fmt.Fprintf(os.Stderr, "Demo failed: %v\nAll created resources and artifacts are retained for diagnosis.\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, source, artifacts, chart string) (result error) {
	started := time.Now()
	d, err := prepare(source, artifacts)
	if err != nil {
		return err
	}
	fmt.Printf("Real deployed OSKAL controller + Tetragon demo\nCluster: %s\nArtifacts: %s\n", d.name, d.dir)
	fmt.Println("Scope: current process effective-UID evidence and host-pinned local Ed25519 receipts; no SPIFFE or hardware-attestation claim.")
	fmt.Fprintf(os.Stderr, "Retained cluster; review before cleanup: kind delete cluster --name %s\n", d.name)
	defer func() {
		if result != nil {
			failedAt := time.Now()
			duration := failedAt.Sub(started).String()
			if err := d.saveJSON("failure.json", map[string]any{"startedAt": started.UTC(), "failedAt": failedAt.UTC(), "duration": duration, "error": result.Error()}); err != nil {
				fmt.Fprintf(os.Stderr, "Record failed demo attempt: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "Demo execution failed after %s.\n", duration)
			d.diagnostics()
		}
	}()
	if err := d.provenance(ctx); err != nil {
		return err
	}
	if _, err := d.exec(ctx, "kind-create", 2*time.Minute, "kind", "create", "cluster", "--name", d.name, "--kubeconfig", d.kubeconfig, "--wait", "90s", "--retain"); err != nil {
		return err
	}
	config, err := clientcmd.BuildConfigFromFlags("", d.kubeconfig)
	if err != nil {
		return err
	}
	config.Timeout = 5 * time.Second
	d.kube, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	d.dynamic, err = dynamic.NewForConfig(config)
	if err != nil {
		return err
	}
	nodes, err := d.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 2})
	if err != nil {
		return err
	}
	if len(nodes.Items) != 1 {
		return fmt.Errorf("fresh demo requires exactly one Kind node")
	}
	d.node, d.architecture = nodes.Items[0].Name, nodes.Items[0].Status.NodeInfo.Architecture
	if nodes.Items[0].Status.NodeInfo.OperatingSystem != "linux" {
		return fmt.Errorf("kind node must actually report Linux")
	}
	if d.architecture != "arm64" && d.architecture != "amd64" {
		return fmt.Errorf("unsupported observed Linux node architecture %q", d.architecture)
	}
	if err := d.saveJSON("node.json", nodes.Items[0]); err != nil {
		return err
	}
	if err := d.waitNetwork(ctx); err != nil {
		return err
	}
	keys, err := d.keys()
	if err != nil {
		return err
	}
	if err := d.build(ctx); err != nil {
		return err
	}
	if _, err := d.exec(ctx, "install-crds", time.Minute, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=10s", "apply", "-f", filepath.Join(d.source, "config/crd/bases")); err != nil {
		return err
	}
	if _, err := d.exec(ctx, "wait-crds", time.Minute, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=10s", "wait", "--for=condition=Established", "--timeout=45s", "crd", "--all"); err != nil {
		return err
	}
	if err := d.namespacesAndSecrets(ctx, keys); err != nil {
		return err
	}
	if err := d.sensor(ctx, chart); err != nil {
		return err
	}
	if err := d.objects(ctx); err != nil {
		return err
	}
	controller, err := d.controller(ctx)
	if err != nil {
		return err
	}
	before, err := d.waitState(ctx, "ASSURED", 90*time.Second, "")
	if err != nil {
		return err
	}
	if err := d.verify(ctx, controller, before, "before"); err != nil {
		return err
	}
	fmt.Printf("Before: ASSURED, %d/%d verified, root=%s, signed receipt=%s\n", before.Status.Controls[0].Completeness.Verified, before.Status.Controls[0].Completeness.Required, before.Status.EvidenceRoot, before.Status.Controls[0].ReceiptRef)
	stopped, err := d.stopSensor(ctx)
	if err != nil {
		return err
	}
	remaining := 45*time.Second - time.Since(stopped)
	if remaining <= 0 {
		return fmt.Errorf("source shutdown exhausted the 45-second transition bound")
	}
	after, err := d.waitState(ctx, "UNKNOWN", remaining, before.Status.Controls[0].ReceiptRef)
	if err != nil {
		return err
	}
	if before.Status.Controls[0].ReceiptRef == after.Status.Controls[0].ReceiptRef {
		return fmt.Errorf("source loss did not publish a new immutable receipt")
	}
	delay := time.Since(stopped)
	if err := d.verify(ctx, controller, after, "after"); err != nil {
		return err
	}
	completedAt := time.Now()
	duration := completedAt.Sub(started).String()
	if err := d.saveJSON("result.json", map[string]any{"before": "ASSURED", "after": "UNKNOWN", "sourceLossObservedAfter": delay.String(), "startedAt": started.UTC(), "completedAt": completedAt.UTC(), "duration": duration, "publicKey": d.publicKey, "beforeReceipt": before.Status.Controls[0].ReceiptRef, "afterReceipt": after.Status.Controls[0].ReceiptRef}); err != nil {
		return err
	}
	d.diagnostics()
	fmt.Printf("After: UNKNOWN, %d/%d verified, root cleared, signed receipt=%s\nSource-loss transition observed in %s.\nBoth receipts verified with the actual CLI and the host-pinned public key.\nDemo acceptance duration: %s.\n", after.Status.Controls[0].Completeness.Verified, after.Status.Controls[0].Completeness.Required, after.Status.Controls[0].ReceiptRef, delay, duration)
	return nil
}
