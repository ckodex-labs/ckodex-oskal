package cilium

import (
	"testing"
	"time"

	flowapi "github.com/cilium/cilium/api/v1/flow"
	observerapi "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCaptureFlowNeverAssertsIsolation(t *testing.T) {
	c := &Collector{Namespace: "capture-test"}
	for _, verdict := range []flowapi.Verdict{flowapi.Verdict_FORWARDED, flowapi.Verdict_DROPPED} {
		event := &observerapi.GetFlowsResponse{ResponseTypes: &observerapi.GetFlowsResponse_Flow{Flow: &flowapi.Flow{
			Time: timestamppb.New(time.Now()), Uuid: "flow-id", Verdict: verdict,
			Source: &flowapi.Endpoint{Namespace: "capture-test", PodName: "workload"},
		}}}
		captured, err := c.capture(event)
		if err != nil || captured == nil {
			t.Fatalf("observed flow could not be captured: %v", err)
		}
		if captured.Type != "network.flow.observed" || !captured.CapturedAt.Equal(event.GetFlow().Time.AsTime()) {
			t.Fatal("capture promoted flow observation or changed source time")
		}
		event.GetFlow().Verdict = flowapi.Verdict_VERDICT_UNKNOWN
		if _, err := c.capture(event); err == nil {
			t.Fatal("missing flow verdict was interpreted as evidence")
		}
	}
	if captured, err := c.capture(&observerapi.GetFlowsResponse{}); err != nil || captured != nil {
		t.Fatal("stream status was interpreted as a workload flow")
	}
	if _, err := c.capture(&observerapi.GetFlowsResponse{ResponseTypes: &observerapi.GetFlowsResponse_LostEvents{LostEvents: &flowapi.LostEvent{}}}); err == nil {
		t.Fatal("explicit event loss was silently ignored")
	}
}
