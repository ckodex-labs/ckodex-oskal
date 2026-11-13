package kubernetes

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

var _ ports.SubjectResolver = (*SubjectResolver)(nil)

// SubjectResolver discovers and computes cryptographic digests for Kubernetes subjects.
type SubjectResolver struct {
	client client.Reader
}

// NewSubjectResolver creates a new Kubernetes subject resolver.
func NewSubjectResolver(client client.Reader) *SubjectResolver {
	return &SubjectResolver{client: client}
}

// ResolveSubject requires a successful authoritative API lookup.
func (r *SubjectResolver) ResolveSubject(ctx context.Context, uri string) (assurance.SubjectRef, error) {
	ctx, cancel := context.WithTimeout(ctx, binding.ResolutionTimeout)
	defer cancel()
	if !strings.HasPrefix(uri, "k8s://") {
		return assurance.SubjectRef{}, fmt.Errorf("subject must use k8s URI scheme")
	}
	w, err := binding.ResolveWorkload(ctx, r.client, assurance.SubjectRef{Scheme: "k8s", ID: strings.TrimPrefix(uri, "k8s://")})
	if err != nil {
		return assurance.SubjectRef{}, err
	}
	return w.Subject, nil
}

// ComputeSubjectDigest rejects missing resources and stale expected UIDs.
func (r *SubjectResolver) ComputeSubjectDigest(ctx context.Context, subject assurance.SubjectRef) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, binding.ResolutionTimeout)
	defer cancel()
	w, err := binding.ResolveWorkload(ctx, r.client, subject)
	if err != nil {
		return "", err
	}
	return w.Digest, nil
}

// BuildPodSubjectRef creates a canonical subject from a supplied Kubernetes Pod.
func BuildPodSubjectRef(pod *corev1.Pod) assurance.SubjectRef { return binding.PodSubject(pod) }

// ComputePodDigest includes UID, full spec, labels, and ownership.
func ComputePodDigest(pod *corev1.Pod) string { return binding.PodDigest(pod) }

// BuildDeploymentSubjectRef creates a canonical subject from a supplied Deployment.
func BuildDeploymentSubjectRef(deploy *appsv1.Deployment) assurance.SubjectRef {
	return binding.DeploymentSubject(deploy)
}

// ComputeDeploymentDigest includes UID, full spec, labels, and generation.
func ComputeDeploymentDigest(deploy *appsv1.Deployment) string {
	return binding.DeploymentDigest(deploy)
}

// MatchesSelector checks if a deployment matches the SubjectSelector.
func MatchesSelector(deploy *appsv1.Deployment, sel assurancev1alpha1.SubjectSelector) bool {
	if sel.NamespaceSelector != nil {
		return false
	} // Namespace labels require an authoritative namespace lookup.
	if len(sel.APIGroups) > 0 {
		matched := false
		for _, group := range sel.APIGroups {
			if group == "apps" || group == "*" {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
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

// CalculateEpoch assembles supplied epoch dimensions; missing dimensions stay empty.
func CalculateEpoch(
	subjectDigest string,
	implementationDigest string,
	policyDigest string,
	authorityDigest string,
	environmentDigest string,
) assurance.AssuranceEpoch {
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
