package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/utcp"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/workcell"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

type executionOptions struct {
	kubeconfig, address, ownID string
	allowedPeers               []string
}

func (o *executionOptions) flags(command *cobra.Command) {
	command.PersistentFlags().StringVar(&o.kubeconfig, "lease-kubeconfig", "", "Explicit kubeconfig for durable lease admission; local calls authenticate with a fresh SelfSubjectReview")
	command.PersistentFlags().StringVar(&o.address, "workload-api", "", "Explicit SPIRE Unix Workload API for own or peer identity")
	command.PersistentFlags().StringVar(&o.ownID, "spiffe-id", "", "Exact expected own SPIFFE ID")
	command.PersistentFlags().StringArrayVar(&o.allowedPeers, "allowed-peer-id", nil, "Exact allowed SPIFFE peer ID for HTTP effects; repeat for each peer")
}

type executionRuntime struct {
	broker   ports.ExecutionBroker
	identity *spire.WorkloadClient
}

func (r *executionRuntime) close() {
	if r != nil && r.identity != nil {
		_ = r.identity.Close()
	}
}

type workloadPrincipal struct{ identity *spire.WorkloadClient }

func (p workloadPrincipal) AuthenticatedPrincipal(ctx context.Context) (string, error) {
	identity, err := p.identity.Identity(ctx)
	if err != nil {
		return "", err
	}
	return identity.SPIFFEID, nil
}

func configureExecution(ctx context.Context, options executionOptions, httpPeer bool) (*executionRuntime, error) {
	runtime := &executionRuntime{}
	if options.address != "" || options.ownID != "" {
		identity, err := spire.NewWorkloadClient(ctx, options.address, options.ownID, 5*time.Second)
		if err != nil {
			return nil, err
		}
		runtime.identity = identity
	}
	failure := func(err error) (*executionRuntime, error) { runtime.close(); return nil, err }
	if options.kubeconfig == "" {
		return runtime, nil
	} // Registry permits only its fixed read-only operations without a broker.
	cfg, err := clientcmd.BuildConfigFromFlags("", options.kubeconfig)
	if err != nil {
		return failure(err)
	}
	var principal ports.PrincipalResolver
	if httpPeer {
		if runtime.identity == nil {
			return failure(fmt.Errorf("HTTP effects require --workload-api, --spiffe-id, and exact --allowed-peer-id; server Kubernetes identity is not the caller"))
		}
		peer, err := spire.NewPeerPrincipal(runtime.identity, options.allowedPeers, utcp.TLSStateFromContext)
		if err != nil {
			return failure(err)
		}
		principal = peer
	} else if runtime.identity != nil {
		principal = workloadPrincipal{identity: runtime.identity}
	} else {
		local, err := workcell.NewKubernetesPrincipal(cfg)
		if err != nil {
			return failure(err)
		}
		principal = local
	}
	broker, err := workcell.NewKubernetesBroker(cfg, principal)
	if err != nil {
		return failure(err)
	}
	runtime.broker = broker
	return runtime, nil
}
