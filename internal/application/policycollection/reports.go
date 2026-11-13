// Package policycollection owns bounded policy-source delivery. The caller owns
// session authority, durable event writers, lifecycle supervision and retries.
package policycollection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/gatekeeper"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/policyreports"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var ErrSafeHold = errors.New("policy source requires SAFE_HOLD")
var ErrBatchActive = errors.New("policy source batch is already active")

// BeginBatch must rotate/invalidate prior eligibility before returning a writer.
// End is required on success and must not make a failed/empty batch into proof.
// CAS history remains available, but only the new session may become eligible.
type BeginBatch func(context.Context) (ports.CapturedEventWriter, func(error), error)

type ReportsConfig struct {
	Client dynamic.Interface
	GVR    schema.GroupVersionResource
	// Kind is required for the custom ConstraintTemplate-defined Gatekeeper GVR.
	Kind           string
	Namespace      string
	Producer       assurance.AuthorityRef
	PollInterval   time.Duration
	RequestTimeout time.Duration
	MaxObjects     int
	MaxBatchBytes  int
	BeginBatch     BeginBatch
	// PollCompleted reports delivery health, including a valid empty snapshot.
	// It conveys no evidence eligibility or control assessment.
	PollCompleted func(error)
}

type ReportsRunner struct {
	config     ReportsConfig
	kind       string
	gatekeeper bool
	active     chan struct{}
}

func NewReportsRunner(config ReportsConfig) (*ReportsRunner, error) {
	if config.Client == nil || config.BeginBatch == nil {
		return nil, fmt.Errorf("explicit Kubernetes client and batch factory are required")
	}
	if err := config.Producer.Validate(); err != nil {
		return nil, err
	}
	if config.PollInterval < time.Second || config.PollInterval > time.Hour || config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute {
		return nil, fmt.Errorf("policy poll interval or request deadline is outside bounds")
	}
	if config.MaxObjects <= 0 || config.MaxObjects > 256 || config.MaxBatchBytes <= 0 || config.MaxBatchBytes > 16<<20 {
		return nil, fmt.Errorf("explicit object and batch byte bounds are required")
	}
	key := config.GVR.Group + "/" + config.GVR.Version + "/" + config.GVR.Resource
	kind := ""
	cluster := false
	isGatekeeper := false
	switch key {
	case "wgpolicyk8s.io/v1alpha2/policyreports":
		kind = "PolicyReport"
	case "wgpolicyk8s.io/v1alpha2/clusterpolicyreports":
		kind = "ClusterPolicyReport"
		cluster = true
	case "openreports.io/v1alpha1/reports":
		kind = "Report"
	case "openreports.io/v1alpha1/clusterreports":
		kind = "ClusterReport"
		cluster = true
	default:
		if config.GVR.Group != "constraints.gatekeeper.sh" || config.GVR.Version != "v1beta1" || config.GVR.Resource == "" || config.Kind == "" {
			return nil, fmt.Errorf("unsupported policy collection GVR")
		}
		kind = config.Kind
		cluster = true
		isGatekeeper = true
	}
	if cluster && config.Namespace != "" || !cluster && config.Namespace == "" {
		return nil, fmt.Errorf("policy collection namespace does not match resource scope")
	}
	return &ReportsRunner{config: config, kind: kind, gatekeeper: isGatekeeper, active: make(chan struct{}, 1)}, nil
}

// Run polls immediately, then at the configured interval. The first fault ends
// this run after End(error); the caller owns the sole bounded restart budget.
func (r *ReportsRunner) Run(ctx context.Context) error {
	for {
		if err := r.Poll(ctx); err != nil {
			return err
		}
		timer := time.NewTimer(r.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Poll performs a fresh snapshot, without an RV/name cache. Deletion, replacement
// and empty lists therefore cannot carry an old batch's eligibility forward.
func (r *ReportsRunner) Poll(ctx context.Context) (result error) {
	defer func() {
		if r.config.PollCompleted != nil {
			r.config.PollCompleted(result)
		}
	}()
	select {
	case r.active <- struct{}{}:
		defer func() { <-r.active }()
	default:
		return ErrBatchActive
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.RequestTimeout)
	defer cancel()
	writer, end, err := r.config.BeginBatch(ctx)
	if end != nil {
		defer func() {
			if result == nil {
				result = ctx.Err()
			}
			end(result)
		}()
	}
	if err != nil {
		return fmt.Errorf("begin policy collection batch: %w", err)
	}
	if writer == nil || end == nil {
		return fmt.Errorf("policy collection batch requires writer and completion callback")
	}
	list, err := r.config.Client.Resource(r.config.GVR).Namespace(r.config.Namespace).List(ctx, metav1.ListOptions{Limit: int64(r.config.MaxObjects) + 1})
	if err != nil {
		return fmt.Errorf("list policy source: %w", err)
	}
	if len(list.Items) > r.config.MaxObjects || list.GetContinue() != "" {
		return fmt.Errorf("%w: policy object count or pagination exceeds snapshot bound", ErrSafeHold)
	}
	var captures []policyreports.Capture
	bytes := 0
	for _, object := range list.Items {
		// List items may omit TypeMeta. The explicit queried GVR, not the
		// object's name or claimed engine, supplies its transport type.
		if object.GetAPIVersion() == "" {
			object.SetAPIVersion(r.config.GVR.GroupVersion().String())
		}
		if object.GetKind() == "" {
			object.SetKind(r.kind)
		}
		if object.GetAPIVersion() != r.config.GVR.GroupVersion().String() || object.GetKind() != r.kind {
			return fmt.Errorf("policy list item differs from configured GVK")
		}
		raw, err := json.Marshal(object.Object)
		if err != nil {
			return fmt.Errorf("serialize actual policy object: %w", err)
		}
		bytes += len(raw)
		if bytes > r.config.MaxBatchBytes {
			return fmt.Errorf("%w: source snapshot exceeds byte bound", ErrSafeHold)
		}
		var decoded []policyreports.Capture
		if r.gatekeeper {
			capture, err := gatekeeper.DecodeConstraint(raw, r.config.Producer)
			if err != nil {
				return fmt.Errorf("decode Gatekeeper audit: %w", err)
			}
			decoded = []policyreports.Capture{capture}
		} else {
			decoded, err = policyreports.Decode(raw, r.config.Producer)
			if err != nil {
				return fmt.Errorf("decode policy report: %w", err)
			}
		}
		for _, capture := range decoded {
			bytes += len(capture.Event.Payload)
			if bytes > r.config.MaxBatchBytes || len(captures) >= 1024 {
				return fmt.Errorf("%w: decoded snapshot exceeds byte or event bound", ErrSafeHold)
			}
			captures = append(captures, capture)
		}
	}
	for _, capture := range captures {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writer.WriteCapturedEvent(ctx, capture.Event); err != nil {
			return fmt.Errorf("persist policy snapshot: %w", err)
		}
	}
	return ctx.Err()
}
