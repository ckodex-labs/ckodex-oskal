package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/projection/oscal"
	"github.com/spf13/cobra"
)

func readStrictJSON(path string, destination any, max int64) error {
	data, err := readBoundedFile(path, max)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s must contain exactly one JSON value", path)
	}
	return nil
}

func newExportCommand() *cobra.Command {
	var contextPath, subject, control, component, system, contractPath, findingsPath string
	options := bindingEvaluationOptions{}
	export := &cobra.Command{Use: "export", Short: "Project supplied facts into schema-validated OSCAL without inferring compliance"}
	export.PersistentFlags().StringVar(&contextPath, "projection-context", "", "Strict JSON file of actual OSCAL references and system metadata")
	export.PersistentFlags().StringVar(&subject, "subject", "", "Explicit subject URI")
	export.PersistentFlags().StringVar(&control, "control", "", "Explicit namespace:id[@version] control reference")
	export.PersistentFlags().StringVar(&component, "component", "", "Actual component name for component-definition")
	export.PersistentFlags().StringVar(&system, "system-name", "", "Actual SSP system name, or the supplied context's system-name")
	export.PersistentFlags().StringVar(&contractPath, "contract-file", "", "Actual authored EvidenceContract JSON for assessment-plan")
	export.PersistentFlags().StringVar(&findingsPath, "findings-file", "", "Caller-selected actual remediation findings JSON array; no findings are inferred from UNKNOWN")
	options.flags(export, true)
	for _, dt := range []string{"assessment-results", "component-definition", "assessment-plan", "ssp", "poam"} {
		command := &cobra.Command{Use: dt, Short: "Project OSCAL " + dt, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := readBoundedFile(contextPath, oscal.MaxProjectionContextBytes)
			if err != nil {
				return fmt.Errorf("--projection-context: %w", err)
			}
			facts, err := oscal.DecodeProjectionContext(raw)
			if err != nil {
				return err
			}
			request := oscal.ProjectionRequest{Subject: subject, DocumentType: dt, Control: control, ComponentName: component, SystemName: system, ProjectionContext: &facts}
			if contractPath != "" {
				request.Contract = &assurance.EvidenceContract{}
				if err := readStrictJSON(contractPath, request.Contract, maxBackendDocumentBytes); err != nil {
					return fmt.Errorf("contract: %w", err)
				}
			}
			if findingsPath != "" {
				if err := readStrictJSON(findingsPath, &request.Findings, maxBackendDocumentBytes); err != nil {
					return fmt.Errorf("findings: %w", err)
				}
			}
			var liveContext binding.Context
			var liveEvaluations []assurance.ClaimEvaluation
			if options.requested() {
				liveContext, liveEvaluations, err = evaluateBinding(cmd.Context(), options)
				if err != nil {
					return err
				}
				if request.Subject != "" && request.Subject != liveContext.Subject.URI() {
					return fmt.Errorf("requested subject does not match the authoritative binding")
				}
				request.Subject = liveContext.Subject.URI()
				if request.Control == "" {
					request.Controls = liveContext.Controls
				}
				if request.Contract == nil {
					request.Contract = &liveContext.Contract
				}
			}
			sub, err := request.SubjectRef()
			if err != nil {
				return err
			}
			controls, err := request.ControlRefs()
			if err != nil {
				return err
			}
			envelopes, err := loadLocalEvidence(evidenceDir, sub)
			if err != nil {
				return err
			}
			var evaluations []assurance.ClaimEvaluation
			for _, reference := range controls {
				if !options.requested() {
					evaluations = append(evaluations, evaluation.UnverifiedEvaluation(sub, reference, envelopes, time.Now().UTC()))
					continue
				}
				found := false
				for _, actual := range liveEvaluations {
					if actual.Control == reference {
						evaluations = append(evaluations, actual)
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("requested control is not part of the authoritative binding")
				}
			}
			data, err := request.Project(cmd.Context(), evaluations)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return err
		}}
		export.AddCommand(command)
	}
	return export
}
