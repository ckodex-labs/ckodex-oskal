package oscal

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
)

func TestTelemetryUnknownPreservedInStrictOSCALProjections(t *testing.T) {
	// Explicit domain conformance input; it makes no runtime or quote claim.
	subject, evaluation := exampleEvaluation()
	evaluation.Telemetry = &assurance.TelemetryEvidence{Integrity: assurance.TelemetryIntegrity{State: assurance.AssuranceStateUnknown, RootKind: "SOFTWARE_TPM", RootLabel: "software TPM root \u2014 not hardware-backed", Caveats: []string{"Source and quote authenticity have not been established by this projection."}, Loss: []assurance.TelemetryLoss{{Signal: "tetragon_observer_ringbuf_events_lost_total", Delta: 4}}, Gaps: []assurance.TelemetryGap{{Kind: "SEQUENCE", First: 11, Last: 16}}, Reasons: []string{"kernel output loss and missing records"}, Recovery: assurance.TelemetryFreshSessionRequired}}
	projector := NewProjectorWithContext(exampleContext())
	for _, test := range []struct {
		kind    DocumentType
		project func() ([]byte, error)
	}{
		{DocTypeAssessmentResults, func() ([]byte, error) {
			return projector.ProjectAssessmentResults(t.Context(), subject, []assurance.ClaimEvaluation{evaluation}, nil)
		}},
		{DocTypeComponentDefinition, func() ([]byte, error) {
			return projector.ProjectComponentDefinition(t.Context(), "payments", []assurance.ClaimEvaluation{evaluation})
		}},
		{DocTypeSSP, func() ([]byte, error) {
			return projector.ProjectSSP(t.Context(), "payments-system", []assurance.ClaimEvaluation{evaluation})
		}},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			raw, err := test.project()
			if err != nil {
				t.Fatal(err)
			}
			validateProjection(t, test.kind, raw)
			var document any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			context := telemetryProperty(document)
			if context == "" {
				t.Fatal("projection lost full telemetry context")
			}
			var recovered assurance.TelemetryEvidence
			if err := json.Unmarshal([]byte(context), &recovered); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(recovered, *evaluation.Telemetry) {
				t.Fatalf("root, caveats, gap or loss changed: %+v", recovered)
			}
		})
	}
	evaluation.State = assurance.AssuranceStateVerified
	if _, err := projector.ProjectAssessmentResults(t.Context(), subject, []assurance.ClaimEvaluation{evaluation}, nil); err == nil {
		t.Fatal("UNKNOWN visibility projected as positive standing")
	}
}

func telemetryProperty(value any) string {
	switch v := value.(type) {
	case map[string]any:
		if v["name"] == "telemetry-context" {
			text, _ := v["value"].(string)
			return text
		}
		for _, item := range v {
			if text := telemetryProperty(item); text != "" {
				return text
			}
		}
	case []any:
		for _, item := range v {
			if text := telemetryProperty(item); text != "" {
				return text
			}
		}
	}
	return ""
}
