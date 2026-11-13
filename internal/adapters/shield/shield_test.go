package shield

import (
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestModelSubjectConstruction(t *testing.T) {
	digest := assurance.ComputeStringDigest("caller-supplied descriptor metadata")
	model := BuildModelSubjectRef("registry.example/models/material", digest)
	if model.URI() != "model://registry.example/models/material@"+digest || model.Attributes["digest"] != digest || model.Attributes["type"] != "foundation-model" {
		t.Fatalf("model descriptor changed caller metadata: %+v", model)
	}
}

func TestAgentSubjectConstruction(t *testing.T) {
	digest := assurance.ComputeStringDigest("caller-supplied prompt metadata")
	agent := BuildAgentSubjectRef("research-agent", "v3", digest)
	if agent.URI() != "agent://research-agent:v3" || agent.Attributes["promptDigest"] != digest || agent.Attributes["type"] != "autonomous-agent" {
		t.Fatalf("agent descriptor changed caller metadata: %+v", agent)
	}
}
