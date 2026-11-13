// Package shield provides pure model and agent subject descriptors. It does not
// inspect models, collect evidence, detect tampering, or establish admission.
package shield

import (
	"fmt"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

// BuildModelSubjectRef describes caller-supplied model identity metadata.
// The digest is not independently verified by constructing this descriptor.
func BuildModelSubjectRef(modelURI, digest string) assurance.SubjectRef {
	return assurance.SubjectRef{
		Scheme: "model",
		ID:     fmt.Sprintf("%s@%s", modelURI, digest),
		Attributes: map[string]string{
			"modelURI": modelURI,
			"digest":   digest,
			"type":     "foundation-model",
		},
	}
}

// BuildAgentSubjectRef describes caller-supplied agent identity metadata.
func BuildAgentSubjectRef(agentID, version, promptDigest string) assurance.SubjectRef {
	return assurance.SubjectRef{
		Scheme: "agent",
		ID:     fmt.Sprintf("%s:%s", agentID, version),
		Attributes: map[string]string{
			"agentID":      agentID,
			"version":      version,
			"promptDigest": promptDigest,
			"type":         "autonomous-agent",
		},
	}
}
