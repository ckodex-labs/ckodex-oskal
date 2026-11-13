package cilium

import (
	"context"
	"fmt"
	"time"

	flowapi "github.com/cilium/cilium/api/v1/flow"
	observerapi "github.com/cilium/cilium/api/v1/observer"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Collector receives real Hubble flows. A forwarded or dropped packet does not
// establish default-deny isolation; the stored fact is only network.flow.observed.
type Collector struct {
	Connection *grpc.ClientConn
	Producer   assurance.AuthorityRef
	Writer     ports.CapturedEventWriter
	Namespace  string
}

// Run follows one live Hubble session with bounded message size and synchronous
// persistence. The caller owns authenticated dialing and bounded restart policy.
func (c *Collector) Run(ctx context.Context) error {
	if c.Connection == nil || c.Writer == nil || c.Namespace == "" {
		return fmt.Errorf("hubble connection, event writer, and namespace are required")
	}
	if err := c.Producer.Validate(); err != nil {
		return err
	}
	stream, err := observerapi.NewObserverClient(c.Connection).GetFlows(ctx, &observerapi.GetFlowsRequest{
		Follow: true, Since: timestamppb.New(time.Now()),
		Whitelist: []*flowapi.FlowFilter{{SourcePod: []string{c.Namespace + "/"}}},
	}, grpc.MaxCallRecvMsgSize(4<<20))
	if err != nil {
		return err
	}
	for {
		event, err := stream.Recv()
		if err != nil {
			return err
		}
		captured, err := c.capture(event)
		if err != nil {
			return err
		}
		if captured == nil {
			continue
		}
		if err := c.Writer.WriteCapturedEvent(ctx, *captured); err != nil {
			return err
		}
	}
}

func (c *Collector) capture(event *observerapi.GetFlowsResponse) (*ports.CapturedEvent, error) {
	if event != nil {
		if _, lost := event.ResponseTypes.(*observerapi.GetFlowsResponse_LostEvents); lost {
			return nil, fmt.Errorf("hubble reported lost events; source visibility is incomplete")
		}
	}
	if event == nil || event.GetFlow() == nil {
		return nil, nil // Relay status is not a workload fact.
	}
	f := event.GetFlow()
	source := f.GetSource()
	if source == nil || source.GetNamespace() != c.Namespace {
		return nil, nil
	}
	if source.GetPodName() == "" || f.GetUuid() == "" || f.GetVerdict() == flowapi.Verdict_VERDICT_UNKNOWN {
		return nil, fmt.Errorf("hubble flow lacks workload identity, event identity, or verdict")
	}
	if f.GetTime() == nil || f.GetTime().CheckValid() != nil {
		return nil, fmt.Errorf("hubble flow lacks a valid observed timestamp")
	}
	payload, err := protojson.Marshal(event)
	if err != nil {
		return nil, err
	}
	return &ports.CapturedEvent{
		Subject: assurance.SubjectRef{Scheme: "k8s", ID: source.GetNamespace() + "/Pod/" + source.GetPodName(), Attributes: map[string]string{
			"namespace": source.GetNamespace(), "kind": "Pod", "name": source.GetPodName(),
		}},
		Type: "network.flow.observed", CapturedAt: f.GetTime().AsTime(), Producer: c.Producer,
		Payload: payload, MediaType: "application/vnd.cilium.flow+json",
		ControlRefs: []assurance.ControlRef{{Namespace: "ckodex", ID: "network.observation"}},
	}, nil
}
