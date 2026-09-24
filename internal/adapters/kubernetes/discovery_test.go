package kubernetes

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	assurancev1alpha1 "github.com/ckodex-labs/oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/oskal/core/assurance"
)

func TestDeploymentDiscoveryAndDigest(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "payments-api",
			Namespace:  "payments",
			UID:        "19b-uid-456",
			Generation: 1,
			Labels: map[string]string{
				"assurance.ckodex.io/profile": "regulated",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "api", Image: "registry.example/payments:v1.0.0"},
					},
				},
			},
		},
	}

	sub := BuildDeploymentSubjectRef(deploy)
	if sub.URI() != "k8s://payments/payments-api/Deployment/payments-api" {
		t.Fatalf("unexpected subject URI: %s", sub.URI())
	}
	if sub.Attributes["generation"] != "1" {
		t.Fatalf("expected generation 1, got %s", sub.Attributes["generation"])
	}

	d1 := ComputeDeploymentDigest(deploy)
	if d1 == "" {
		t.Fatalf("expected non-empty deployment digest")
	}

	// Milestone 4 Exit Criteria:
	// A Deployment change causes ASSURED -> STALE without manual intervention.

	// Case 1: Generation increment (e.g. env var or config change)
	deployGen2 := deploy.DeepCopy()
	deployGen2.Generation = 2
	d2 := ComputeDeploymentDigest(deployGen2)
	if d1 == d2 {
		t.Fatalf("expected different digest when generation increments")
	}

	epoch1 := CalculateEpoch(d1, "", "", "", "")
	epoch2 := CalculateEpoch(d2, "", "", "", "")

	// Check drift transition: ASSURED -> STALE
	nextState, diffs := EvaluateDrift(assurance.AssuranceStateAssured, epoch1, epoch2)
	if nextState != assurance.AssuranceStateStale {
		t.Fatalf("M4 Exit Failure: Expected ASSURED -> STALE on generation change, got %s", nextState)
	}
	if len(diffs) != 1 || diffs[0] != assurance.DriftSubject {
		t.Fatalf("Expected DriftSubject, got %v", diffs)
	}

	// Case 2: Image digest change
	deployImageChanged := deploy.DeepCopy()
	deployImageChanged.Spec.Template.Spec.Containers[0].Image = "registry.example/payments:v1.1.0@sha256:newdigest"
	dImage := ComputeDeploymentDigest(deployImageChanged)
	if d1 == dImage {
		t.Fatalf("expected different digest when image changes")
	}

	epochImage := CalculateEpoch(dImage, "", "", "", "")
	nextStateImg, diffsImg := EvaluateDrift(assurance.AssuranceStateAssured, epoch1, epochImage)
	if nextStateImg != assurance.AssuranceStateStale {
		t.Fatalf("M4 Exit Failure: Expected ASSURED -> STALE on image change, got %s", nextStateImg)
	}
	if len(diffsImg) != 1 || diffsImg[0] != assurance.DriftSubject {
		t.Fatalf("Expected DriftSubject, got %v", diffsImg)
	}
}

func TestMatchesSelector(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "payments-api",
			Namespace: "payments",
			Labels: map[string]string{
				"assurance.ckodex.io/profile": "regulated",
			},
		},
	}

	sel := assurancev1alpha1.SubjectSelector{
		Kinds: []string{"Deployment"},
		LabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"assurance.ckodex.io/profile": "regulated",
			},
		},
	}

	if !MatchesSelector(deploy, sel) {
		t.Fatalf("expected deploy to match selector")
	}

	selNonMatching := sel
	selNonMatching.LabelSelector = &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"assurance.ckodex.io/profile": "unregulated",
		},
	}
	if MatchesSelector(deploy, selNonMatching) {
		t.Fatalf("expected deploy not to match non-matching label selector")
	}
}
