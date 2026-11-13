package oskal

import (
	"context"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"testing"
)

func TestExplicitDependenciesRequired(t *testing.T) {
	if _, err := NewEvaluationConfig(nil, "", nil, nil); err == nil {
		t.Fatal("SDK live configuration accepted missing dependencies")
	}
	if _, err := NewClient(context.Background(), "127.0.0.1:443"); err == nil {
		t.Fatal("network client silently selected plaintext")
	}
	if _, err := NewInProcessClientWithEvaluation(EvaluationConfig{}); err == nil {
		t.Fatal("live client accepted missing authority dependencies")
	}
	client := NewInProcessClient(WithEvaluatorAuthority(AuthorityRef{}))
	if _, err := client.GetAssuranceState(context.Background(), assurance.SubjectRef{Scheme: "k8s", ID: "ns/Pod/app"}); err == nil {
		t.Fatal("invalid authority silently replaced")
	}
}
