package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type snapshot struct {
	Metadata struct {
		Name, Namespace, UID, ResourceVersion string
		Labels                                map[string]string
	} `json:"metadata"`
	Spec struct {
		SubjectRef struct{ APIVersion, Kind, Namespace, Name, UID string } `json:"subjectRef"`
	} `json:"spec"`
	Status struct {
		State        string            `json:"state"`
		EvidenceRoot string            `json:"evidenceRoot"`
		Epoch        map[string]string `json:"epoch"`
		EvaluatedAt  time.Time         `json:"evaluatedAt"`
		Controls     []struct {
			ID              string                          `json:"id"`
			State           string                          `json:"state"`
			ReceiptRef      string                          `json:"receiptRef"`
			EvidenceSummary string                          `json:"evidenceSummary"`
			Completeness    *assurance.EvidenceCompleteness `json:"completeness"`
		} `json:"controls"`
	} `json:"status"`
}

func (d *demo) createObject(ctx context.Context, resource string, object map[string]any) (*unstructured.Unstructured, error) {
	return d.dynamic.Resource(schema.GroupVersionResource{Group: assuranceGVR.Group, Version: assuranceGVR.Version, Resource: resource}).Namespace(workloadNamespace).Create(ctx, &unstructured.Unstructured{Object: object}, metav1.CreateOptions{})
}

func (d *demo) waitState(ctx context.Context, wanted string, timeout time.Duration, previousReceipt string) (snapshot, error) {
	var selected snapshot
	err := until(ctx, timeout, func(ctx context.Context) (bool, error) {
		object, err := d.dynamic.Resource(assuranceGVR).Namespace(workloadNamespace).Get(ctx, bindingName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		raw, err := json.Marshal(object.Object)
		if err != nil {
			return false, err
		}
		var value snapshot
		if err := json.Unmarshal(raw, &value); err != nil {
			return false, err
		}
		if value.Status.State != wanted {
			return false, fmt.Errorf("actual state=%s, awaiting %s", value.Status.State, wanted)
		}
		if value.Spec.SubjectRef.UID != d.workloadUID || value.Spec.SubjectRef.Name != workloadName || value.Spec.SubjectRef.Namespace != workloadNamespace || value.Spec.SubjectRef.Kind != "Pod" {
			return false, fmt.Errorf("published state does not bind the actual workload UID")
		}
		if value.Metadata.Labels["assurance.ckodex.io/binding-uid"] != d.bindingUID || value.Metadata.Name != bindingName || value.Metadata.UID == "" {
			return false, fmt.Errorf("published state does not bind the actual ControlBinding")
		}
		if len(value.Status.Controls) != 1 || value.Status.Controls[0].ID != "runtime.process-uid" || value.Status.Controls[0].State != wanted || value.Status.Controls[0].Completeness == nil {
			return false, fmt.Errorf("published control status lacks the required numeric completeness")
		}
		control := value.Status.Controls[0]
		counts := control.Completeness
		if counts.Required != 1 || value.Status.EvaluatedAt.IsZero() {
			return false, fmt.Errorf("published control lacks actual evaluation/completeness")
		}
		if counts.Present != counts.Verified || counts.Verified+counts.Missing+counts.Stale != 1 {
			return false, fmt.Errorf("published numeric completeness is incoherent")
		}
		if wanted == "ASSURED" && (counts.Verified != 1 || counts.Missing != 0 || counts.Stale != 0 || value.Status.EvidenceRoot == "") {
			return false, fmt.Errorf("ASSURED lacks verified 1/1 current evidence and root")
		}
		if wanted == "UNKNOWN" && (counts.Verified != 0 || counts.Missing+counts.Stale < 1 || value.Status.EvidenceRoot != "") {
			return false, fmt.Errorf("UNKNOWN retained eligible evidence or evidence root")
		}
		if !receiptReference.MatchString(control.ReceiptRef) || control.ReceiptRef == previousReceipt {
			return false, fmt.Errorf("published state lacks a new immutable receipt reference")
		}
		for _, key := range []string{"subject", "policy", "implementation", "authority", "environment", "composite"} {
			if !digestReference.MatchString(value.Status.Epoch[key]) {
				return false, fmt.Errorf("state epoch %s is missing or malformed", key)
			}
		}
		selected = value
		return true, nil
	})
	return selected, err
}

var receiptReference = regexp.MustCompile(`^rcpt-[0-9a-f]{64}$`)
var digestReference = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var regexpDigest = regexp.MustCompile(`sha256:[0-9a-f]{64}$`)
var safeUID = regexp.MustCompile(`^[a-zA-Z0-9-]{1,128}$`)

func (d *demo) verify(ctx context.Context, pod *corev1.Pod, state snapshot, stage string) error {
	if !safeUID.MatchString(string(pod.UID)) || pod.Spec.NodeName != d.node {
		return fmt.Errorf("controller Pod identity differs from the owned Kind node")
	}
	current, err := d.kube.CoreV1().Pods(systemNamespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if current.UID != pod.UID || !podReady(*current) || len(current.Status.ContainerStatuses) != 1 || current.Status.ContainerStatuses[0].RestartCount != pod.Status.ContainerStatuses[0].RestartCount {
		return fmt.Errorf("controller stopped or restarted during the source-loss demonstration")
	}
	ref := state.Status.Controls[0].ReceiptRef
	if !receiptReference.MatchString(ref) {
		return fmt.Errorf("unsafe or mutable receipt reference")
	}
	root := filepath.Join("/var/lib/kubelet/pods", string(pod.UID), "volumes/kubernetes.io~empty-dir/evidence")
	inspection, err := d.exec(ctx, stage+"-inspect-volume", 10*time.Second, "docker", "exec", d.node, "stat", "--format=%F", root)
	if err != nil {
		return fmt.Errorf("inspect the owned node's actual kubelet emptyDir layout; no whole-volume fallback is permitted: %w", err)
	}
	if strings.TrimSpace(string(inspection)) != "directory" {
		return fmt.Errorf("owned node's actual evidence volume is not a directory")
	}
	actual := evidenceDir + "/receipts/" + ref + ".json"
	if _, err := d.exec(ctx, stage+"-container-cli-verify", 15*time.Second, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=10s", "exec", "-n", systemNamespace, pod.Name, "--", "/oskal", "assurance", "receipt", "verify", "--receipt-file", actual, "--public-key", d.publicKey); err != nil {
		return err
	}
	host := filepath.Join(d.dir, stage+"-receipt.json")
	if _, err := d.exec(ctx, stage+"-copy-receipt", 15*time.Second, "docker", "cp", d.node+":"+filepath.Join(root, "receipts", ref+".json"), host); err != nil {
		return err
	}
	if err := os.Chmod(host, 0600); err != nil {
		return err
	}
	hash, err := fileDigest(host)
	if err != nil {
		return err
	}
	if hash != strings.TrimPrefix(ref, "rcpt-") {
		return fmt.Errorf("actual persisted receipt body differs from its immutable reference")
	}
	raw, err := os.ReadFile(host)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return fmt.Errorf("receipt exceeds bounded demo verification size")
	}
	var receipt assurance.ControlReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return err
	}
	if receipt.Subject.Scheme != "k8s" || receipt.Subject.ID != workloadNamespace+"/Pod/"+workloadName || receipt.Subject.Attributes["uid"] != d.workloadUID || receipt.Control.Namespace != "ckodex" || receipt.Control.ID != "runtime.process-uid" || receipt.State.String() != state.Status.State || receipt.EvidenceRoot != state.Status.EvidenceRoot || receipt.Evaluator.Canonical() != "local://oskal-controller" {
		return fmt.Errorf("signed receipt does not bind the published subject/control/state/root/evaluator")
	}
	epoch := state.Status.Epoch
	if receipt.Epoch.SubjectDigest != epoch["subject"] || receipt.Epoch.PolicyDigest != epoch["policy"] || receipt.Epoch.ImplementationDigest != epoch["implementation"] || receipt.Epoch.AuthorityDigest != epoch["authority"] || receipt.Epoch.EnvironmentDigest != epoch["environment"] || receipt.Epoch.CompositeDigest() != epoch["composite"] {
		return fmt.Errorf("signed receipt epoch differs from the actual AssuranceState")
	}
	workload, err := d.kube.CoreV1().Pods(workloadNamespace).Get(ctx, workloadName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(workload.UID) != d.workloadUID || binding.PodDigest(workload) != receipt.Epoch.SubjectDigest {
		return fmt.Errorf("signed epoch does not bind the current actual Pod UID/spec snapshot")
	}
	if !receipt.EvaluatedAt.Truncate(time.Second).Equal(state.Status.EvaluatedAt.Truncate(time.Second)) {
		return fmt.Errorf("signed receipt evaluation time differs from the published state")
	}
	if _, err := d.exec(ctx, stage+"-host-cli-verify", 15*time.Second, d.hostCLI, "assurance", "receipt", "verify", "--receipt-file", host, "--public-key", d.publicKey); err != nil {
		return err
	}
	// A valid but changed root must fail the same real CLI signature check.
	var altered map[string]json.RawMessage
	if err := json.Unmarshal(raw, &altered); err != nil {
		return err
	}
	altered["evidenceRoot"] = json.RawMessage(`"sha256:` + strings.Repeat("0", 64) + `"`)
	if err := d.saveJSON(stage+"-tampered-receipt.json", altered); err != nil {
		return err
	}
	output, err := d.exec(ctx, stage+"-tamper-rejected", 15*time.Second, d.hostCLI, "assurance", "receipt", "verify", "--receipt-file", filepath.Join(d.dir, stage+"-tampered-receipt.json"), "--public-key", d.publicKey)
	if err == nil || !strings.Contains(string(output), "cryptographic verification failed") {
		return fmt.Errorf("actual CLI did not reject the altered signed receipt root")
	}
	return d.saveJSON(stage+".json", state)
}
