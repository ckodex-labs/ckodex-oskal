package tetragon

import (
	"context"
	"fmt"

	tetragonapi "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

// Collector consumes the real Tetragon FineGuidanceSensors event stream.
// Connection authentication and reconnect policy belong to the caller.
type Collector struct {
	Connection *grpc.ClientConn
	Producer   assurance.AuthorityRef
	Writer     ports.CapturedEventWriter
	Namespace  string
}

// Run consumes one stream session until cancellation, upstream failure, or a
// rejected event. Writes are synchronous; no unbounded queue or retry is hidden.
func (c *Collector) Run(ctx context.Context) error {
	if c.Connection == nil || c.Writer == nil || c.Namespace == "" {
		return fmt.Errorf("tetragon connection, event writer, and namespace are required")
	}
	if err := c.Producer.Validate(); err != nil {
		return err
	}
	stream, err := tetragonapi.NewFineGuidanceSensorsClient(c.Connection).GetEvents(ctx, &tetragonapi.GetEventsRequest{
		AllowList: []*tetragonapi.Filter{{Namespace: []string{c.Namespace}, EventSet: []tetragonapi.EventType{tetragonapi.EventType_PROCESS_EXEC}}},
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

func (c *Collector) capture(event *tetragonapi.GetEventsResponse) (*ports.CapturedEvent, error) {
	if event == nil || event.GetProcessExec() == nil {
		return nil, nil
	}
	p := event.GetProcessExec().GetProcess()
	if p == nil || p.GetPod() == nil {
		return nil, nil // Host processes cannot be attributed to a Kubernetes subject.
	}
	pod := p.GetPod()
	if pod.GetNamespace() != c.Namespace {
		return nil, nil
	}
	if pod.GetName() == "" || pod.GetUid() == "" || p.GetUid() == nil || p.GetExecId() == "" || p.GetBinary() == "" {
		return nil, fmt.Errorf("tetragon process event lacks pod identity, execution identity, binary, or effective UID")
	}
	if event.GetTime() == nil || event.GetTime().CheckValid() != nil {
		return nil, fmt.Errorf("tetragon process event lacks a valid observed timestamp")
	}
	observationType := "workload.runtime.process.nonroot"
	if p.GetUid().GetValue() == 0 {
		observationType = "workload.runtime.process.violation"
	}
	payload, err := protojson.Marshal(event)
	if err != nil {
		return nil, err
	}
	return &ports.CapturedEvent{
		Subject: assurance.SubjectRef{Scheme: "k8s", ID: pod.GetNamespace() + "/Pod/" + pod.GetName(), Attributes: map[string]string{
			"namespace": pod.GetNamespace(), "kind": "Pod", "name": pod.GetName(), "uid": pod.GetUid(),
		}},
		Type: observationType, CapturedAt: event.GetTime().AsTime(), Producer: c.Producer,
		Payload: payload, MediaType: "application/vnd.tetragon.event+json",
		ControlRefs: []assurance.ControlRef{{Namespace: "ckodex", ID: "container.least-privilege"}},
	}, nil
}
