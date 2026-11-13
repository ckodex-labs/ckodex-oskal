package workcell

import (
	"context"
	"errors"
	"fmt"
	"time"

	assurancev1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrExecutionUncertain = errors.New("execution outcome uncertain; inspect durable state, automatic replay prohibited")

// KubernetesBroker reads the API directly on every admission. Resource-version
// CAS linearizes admission against other admissions, revocation and deletion.
// Revocation cannot fence an effect that has already been granted authority.
type KubernetesBroker struct {
	client    client.Client
	principal ports.PrincipalResolver
}

func NewKubernetesBroker(config *rest.Config, principal ports.PrincipalResolver) (*KubernetesBroker, error) {
	if config == nil || principal == nil {
		return nil, errors.New("kubernetes configuration and authenticated principal resolver are required")
	}
	scheme := runtime.NewScheme()
	if err := assurancev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	cfg := rest.CopyConfig(config)
	cfg.Timeout = 10 * time.Second
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create direct lease client: %w", err)
	}
	return &KubernetesBroker{client: c, principal: principal}, nil
}

// KubernetesPrincipal authenticates a local CLI using its actual API credential.
// It is unsuitable for a multi-user server, which must resolve its verified peer.
type KubernetesPrincipal struct{ client kubernetes.Interface }

func NewKubernetesPrincipal(config *rest.Config) (*KubernetesPrincipal, error) {
	if config == nil {
		return nil, errors.New("kubernetes configuration is required")
	}
	cfg := rest.CopyConfig(config)
	cfg.Timeout = 10 * time.Second
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &KubernetesPrincipal{client: c}, nil
}

func (p *KubernetesPrincipal) AuthenticatedPrincipal(ctx context.Context) (string, error) {
	if p == nil || p.client == nil {
		return "", errors.New("kubernetes principal is not configured")
	}
	review, err := p.client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("authenticate local Kubernetes principal: %w", err)
	}
	if review.Status.UserInfo.Username == "" {
		return "", errors.New("kubernetes returned no authenticated principal")
	}
	return review.Status.UserInfo.Username, nil
}

func (b *KubernetesBroker) Execute(ctx context.Context, request assurance.ExecutionRequest, effect func(context.Context) ([]byte, error)) (*assurance.ExecutionReceipt, error) {
	ctx, span := otel.Tracer("oskal/workcell").Start(ctx, "capability-lease.execute")
	defer span.End()
	disposition := "DENIED"
	defer func() { telemetry.RecordEvidenceProcessed("capability-lease", "execution", disposition) }()
	if b == nil || b.client == nil || b.principal == nil {
		return nil, errors.New("execution broker is not configured")
	}
	if effect == nil {
		return nil, errors.New("execution callback is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	principal, err := b.principal.AuthenticatedPrincipal(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve execution principal: %w", err)
	}
	admission, err := b.reserve(ctx, request, principal)
	if err != nil {
		return nil, err
	}
	disposition = "UNCERTAIN"
	span.AddEvent("admission.persisted", trace.WithAttributes(attribute.String("admission.hash", admission.Hash), attribute.Int("execution.turn", admission.Turn)))
	// Cancellation after reservation intentionally retains the pending turn.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExecutionUncertain, err)
	}
	executionContext, cancel := context.WithDeadline(ctx, admission.ExpiresAt)
	defer cancel()
	result, err := effect(executionContext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExecutionUncertain, err)
	}
	span.AddEvent("effect.returned")
	receipt, err := b.complete(ctx, request, *admission, result)
	if err != nil {
		return nil, fmt.Errorf("%w: completion persistence: %w", ErrExecutionUncertain, err)
	}
	disposition = "COMPLETED"
	span.AddEvent("completion.persisted", trace.WithAttributes(attribute.String("execution.hash", receipt.Hash)))
	telemetry.RecordReceiptIssued("capability-lease-execution", "COMPLETED")
	return receipt, nil
}

func (b *KubernetesBroker) reserve(ctx context.Context, r assurance.ExecutionRequest, principal string) (*assurance.ExecutionAdmission, error) {
	for attempt := 0; attempt < 5; attempt++ {
		lease := &assurancev1.CapabilityLease{}
		if err := b.client.Get(ctx, types.NamespacedName{Namespace: r.LeaseNamespace, Name: r.LeaseName}, lease); err != nil {
			return nil, fmt.Errorf("read authoritative lease: %w", err)
		}
		if lease.Status.Phase != "Active" {
			return nil, fmt.Errorf("lease phase %q does not admit execution", lease.Status.Phase)
		}
		if lease.Status.PendingExecution != nil {
			return nil, ErrExecutionUncertain
		}
		if lease.Status.IssuedAt == nil || lease.Status.ExpiresAt == nil {
			return nil, errors.New("lease validity interval missing")
		}
		if err := assurance.ValidateExecutionLineage(lease.Status.ExecutionHistory, lease.Status.LastAdmissionHash, lease.Status.LastExecutionHash, lease.Status.CurrentTurn); err != nil {
			return nil, err
		}
		lastRequest := ""
		if len(lease.Status.ExecutionHistory) > 0 {
			lastRequest = lease.Status.ExecutionHistory[len(lease.Status.ExecutionHistory)-1].Admission.RequestID
		}
		snapshot := assurance.ExecutionLease{Namespace: lease.Namespace, Name: lease.Name, UID: string(lease.UID), Generation: lease.Generation, ObservedGeneration: lease.Status.ObservedGeneration, Principal: lease.Spec.Principal, Scope: lease.Spec.Scope, AllowedCapabilities: lease.Spec.AllowedCapabilities, MaxTurns: lease.Spec.MaxTurns, CurrentTurn: lease.Status.CurrentTurn, IssuedAt: lease.Status.IssuedAt.Time, ExpiresAt: lease.Status.ExpiresAt.Time, TTL: lease.Spec.TTL.Duration, Revoked: lease.Status.RevocationReason != "", Deleting: !lease.DeletionTimestamp.IsZero(), LastAdmissionHash: lease.Status.LastAdmissionHash, LastRequestID: lastRequest}
		for _, previous := range lease.Status.ExecutionHistory {
			if previous.Admission.RequestID == r.RequestID {
				return nil, errors.New("execution request identity already consumed")
			}
		}
		admission, err := assurance.EvaluateExecution(snapshot, r, principal, time.Now())
		if err != nil {
			return nil, err
		}
		lease.Status.CurrentTurn = admission.Turn
		lease.Status.LastAdmissionHash = admission.Hash
		lease.Status.PendingExecution = admission
		if err := b.client.Status().Update(ctx, lease); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return nil, fmt.Errorf("reserve execution (ambiguous writes must be inspected): %w", err)
		}
		return admission, nil
	}
	return nil, errors.New("lease admission conflict budget exhausted")
}

func (b *KubernetesBroker) complete(ctx context.Context, r assurance.ExecutionRequest, admission assurance.ExecutionAdmission, result []byte) (*assurance.ExecutionReceipt, error) {
	completedAt := time.Now()
	for attempt := 0; attempt < 5; attempt++ {
		lease := &assurancev1.CapabilityLease{}
		if err := b.client.Get(ctx, types.NamespacedName{Namespace: r.LeaseNamespace, Name: r.LeaseName}, lease); err != nil {
			return nil, err
		}
		if string(lease.UID) != admission.LeaseUID || lease.Status.PendingExecution == nil || lease.Status.PendingExecution.Hash != admission.Hash {
			return nil, errors.New("execution reservation identity changed")
		}
		receipt, err := assurance.CompleteExecution(admission, result, lease.Status.LastExecutionHash, completedAt)
		if err != nil {
			return nil, err
		}
		lease.Status.ExecutionHistory = append(lease.Status.ExecutionHistory, *receipt)
		lease.Status.LastExecutionHash = receipt.Hash
		lease.Status.PendingExecution = nil
		if lease.Status.CurrentTurn >= lease.Spec.MaxTurns && lease.Status.Phase == "Active" {
			lease.Status.Phase = "Exhausted"
		}
		if err := b.client.Status().Update(ctx, lease); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return nil, err
		}
		return receipt, nil
	}
	return nil, errors.New("lease completion conflict budget exhausted")
}
