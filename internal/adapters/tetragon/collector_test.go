package tetragon

import (
	"testing"
	"time"

	tetragonapi "github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// These are deterministic mapping checks of the official SDK messages. The real
// subscription, Kubernetes binding and disk persistence are tested separately.
func TestCaptureProcessIdentityAndValence(t *testing.T) {
	c := &Collector{Namespace: "capture-test"}
	for _, uid := range []uint32{0, 1000} {
		event := &tetragonapi.GetEventsResponse{
			Time: timestamppb.New(time.Now()),
			Event: &tetragonapi.GetEventsResponse_ProcessExec{ProcessExec: &tetragonapi.ProcessExec{Process: &tetragonapi.Process{
				Binary: "/bin/true", ExecId: "execution", Uid: wrapperspb.UInt32(uid),
				Pod: &tetragonapi.Pod{Namespace: "capture-test", Name: "workload", Uid: "pod-uid"},
			}}},
		}
		captured, err := c.capture(event)
		if err != nil || captured == nil {
			t.Fatalf("complete process could not be captured: %v", err)
		}
		expected := "workload.runtime.process.nonroot"
		if uid == 0 {
			expected = "workload.runtime.process.violation"
		}
		if captured.Type != expected || captured.Subject.Attributes["uid"] != "pod-uid" || !captured.CapturedAt.Equal(event.Time.AsTime()) {
			t.Fatal("capture changed observed valence, identity, or timestamp")
		}
		event.GetProcessExec().Process.Uid = nil
		if _, err := c.capture(event); err == nil {
			t.Fatal("missing process UID was interpreted as nonroot or root")
		}
	}
}
