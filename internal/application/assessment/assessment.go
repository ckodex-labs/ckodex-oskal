// Package assessment coordinates strict evidence evaluation with live binding
// authority. Transport adapters serialize its result without inventing policy.
package assessment

import (
	"context"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

type Config struct {
	Resolver  *binding.Resolver
	Evaluator *evaluation.Evaluator
	Sources   ports.EvidenceRevisioner
}

type Service struct{ config Config }

type Result struct {
	Context      binding.Context
	Evaluations  []assurance.ClaimEvaluation
	State        assurance.AssuranceState
	EvidenceRoot string
}

func New(config Config) (*Service, error) {
	if config.Resolver == nil || config.Evaluator == nil || config.Sources == nil {
		return nil, fmt.Errorf("live assessment requires authoritative binding resolver, strict evaluator and source revision")
	}
	return &Service{config: config}, nil
}

// Assess always resolves fresh context. An empty control list evaluates every
// bound control; an explicit list must be a subset of those exact canonical IDs.
func (s *Service) Assess(parent context.Context, subject assurance.SubjectRef, controls []assurance.ControlRef) (Result, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	if len(controls) > binding.MaxObjects {
		return Result{}, fmt.Errorf("assessment exceeds %d controls", binding.MaxObjects)
	}
	revision := s.config.Sources.Revision()
	resolved, err := s.config.Resolver.ContextForSubject(ctx, subject)
	if err != nil {
		return Result{}, err
	}
	if len(resolved.Controls) == 0 {
		return Result{}, fmt.Errorf("binding has no controls")
	}
	allowed := make(map[string]bool, len(resolved.Controls))
	for _, control := range resolved.Controls {
		allowed[control.Canonical()] = true
	}
	if len(controls) == 0 {
		controls = resolved.Controls
	}
	seen := make(map[string]bool, len(controls))
	result := Result{Context: resolved, State: assurance.AssuranceStateAssured}
	var evidence []assurance.EvidenceRef
	for _, control := range controls {
		if !allowed[control.Canonical()] || seen[control.Canonical()] {
			return Result{}, fmt.Errorf("control %s is unbound or repeated", control.Canonical())
		}
		seen[control.Canonical()] = true
		claim := assurance.Claim{ID: string(resolved.BindingUID) + "/" + control.Canonical(), Subject: resolved.Subject, Control: control}
		evaluated, err := s.config.Evaluator.Evaluate(ctx, claim, resolved.Contract, resolved.Epoch)
		if err != nil {
			return Result{}, err
		}
		evaluated.State = evaluation.ApplyPolicies(evaluated, resolved.Policies, time.Now().UTC())
		result.Evaluations = append(result.Evaluations, evaluated)
		evidence = append(evidence, evaluated.Evidence...)
		result.State = combine(result.State, evaluated.State)
	}
	fresh, err := s.config.Resolver.ContextForSubject(ctx, resolved.Subject)
	if err != nil {
		return Result{}, err
	}
	if fresh.BindingUID != resolved.BindingUID || fresh.Epoch != resolved.Epoch || s.config.Sources.Revision() != revision {
		return Result{}, fmt.Errorf("binding epoch or source eligibility changed during assessment; retry from fresh context")
	}
	now := time.Now().UTC()
	for _, evaluation := range result.Evaluations {
		if (evaluation.State == assurance.AssuranceStateVerified || evaluation.State == assurance.AssuranceStateAssured) && !evaluation.ValidUntil.IsZero() && !now.Before(evaluation.ValidUntil) {
			return Result{}, fmt.Errorf("evaluation expired before assessment completed")
		}
	}
	if result.State == assurance.AssuranceStateVerified || result.State == assurance.AssuranceStateAssured {
		result.EvidenceRoot = receipts.ComputeEvidenceRoot(evidence)
	}
	return result, nil
}

func combine(current, next assurance.AssuranceState) assurance.AssuranceState {
	for _, state := range []assurance.AssuranceState{assurance.AssuranceStateFailed, assurance.AssuranceStateUnknown, assurance.AssuranceStateStale, assurance.AssuranceStateVerified} {
		if current == state || next == state {
			return state
		}
	}
	if next != assurance.AssuranceStateAssured {
		return assurance.AssuranceStateUnknown
	}
	return current
}
