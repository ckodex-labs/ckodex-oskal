package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// SubjectResolver discovers and computes cryptographic digests for Kubernetes subjects.
type SubjectResolver struct {
	client client.Reader
}

// NewSubjectResolver creates a new Kubernetes subject resolver.
func NewSubjectResolver(client client.Reader) *SubjectResolver {
	return &SubjectResolver{client: client}
}

// BuildSubjectRef creates a canonical SubjectRef for a Kubernetes Deployment.
func BuildDeploymentSubjectRef(deploy *appsv1.Deployment) assurance.SubjectRef {
	images := make([]string, 0, len(deploy.Spec.Template.Spec.Containers))
	for _, c := range deploy.Spec.Template.Spec.Containers {
		images = append(images, c.Image)
	}
	sort.Strings(images)

	return assurance.SubjectRef{
		Scheme: "k8s",
		ID:     fmt.Sprintf("%s/%s/Deployment/%s", deploy.Namespace, deploy.Name, deploy.Name),
		Attributes: map[string]string{
			"cluster":         "local",
			"namespace":       deploy.Namespace,
			"kind":            "Deployment",
			"name":            deploy.Name,
			"uid":             string(deploy.UID),
			"generation":      fmt.Sprintf("%d", deploy.Generation),
			"resourceVersion": deploy.ResourceVersion,
			"images":          strings.Join(images, ","),
		},
	}
}

// ComputeSubjectDigest computes the cryptographic digest across spec, generation, UID, and container images.
func ComputeDeploymentDigest(deploy *appsv1.Deployment) string {
	images := make([]string, 0, len(deploy.Spec.Template.Spec.Containers))
	for _, c := range deploy.Spec.Template.Spec.Containers {
		images = append(images, c.Image)
	}
	sort.Strings(images)

	raw := fmt.Sprintf("deploy|%s|%s|%s|%d|%s",
		deploy.Namespace,
		deploy.Name,
		deploy.UID,
		deploy.Generation,
		strings.Join(images, ";"),
	)
	h := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(h[:])
}

// MatchesSelector checks if a deployment matches the SubjectSelector.
func MatchesSelector(deploy *appsv1.Deployment, sel assurancev1alpha1.SubjectSelector) bool {
	matchedKind := false
	for _, k := range sel.Kinds {
		if k == "Deployment" || k == "*" {
			matchedKind = true
			break
		}
	}
	if !matchedKind {
		return false
	}

	if sel.LabelSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(sel.LabelSelector)
		if err != nil || !selector.Matches(labels.Set(deploy.Labels)) {
			return false
		}
	}

	return true
}

// CalculateEpoch computes the composite AssuranceEpoch for a subject and its effective rules.
func CalculateEpoch(
	subjectDigest string,
	implementationDigest string,
	policyDigest string,
	authorityDigest string,
	environmentDigest string,
) assurance.AssuranceEpoch {
	if implementationDigest == "" {
		implementationDigest = assurance.ComputeStringDigest("provider:cel:v1")
	}
	if policyDigest == "" {
		policyDigest = assurance.ComputeStringDigest("policy:default:v1")
	}
	if authorityDigest == "" {
		authorityDigest = assurance.ComputeStringDigest("spiffe://local/ns/ckodex-assurance")
	}
	if environmentDigest == "" {
		environmentDigest = assurance.ComputeStringDigest("k8s:v1.31:oskal:v0.1.0")
	}

	return assurance.AssuranceEpoch{
		SubjectDigest:        subjectDigest,
		ImplementationDigest: implementationDigest,
		PolicyDigest:         policyDigest,
		AuthorityDigest:      authorityDigest,
		EnvironmentDigest:    environmentDigest,
	}
}

// EvaluateDrift compares an existing state against the newly computed epoch.
// If the subject digest changed, the state transitions from ASSURED to STALE.
func EvaluateDrift(currentState assurance.AssuranceState, recordedEpoch, currentEpoch assurance.AssuranceEpoch) (assurance.AssuranceState, []assurance.EpochDriftReason) {
	if recordedEpoch.Matches(currentEpoch) {
		return currentState, nil
	}

	diffs := recordedEpoch.Diff(currentEpoch)
	if currentState == assurance.AssuranceStateAssured {
		nextState, _ := assurance.Transition(currentState, assurance.EventEpochChanged)
		return nextState, diffs
	}

	return currentState, diffs
}
