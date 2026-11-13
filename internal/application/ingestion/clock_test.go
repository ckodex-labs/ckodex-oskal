package ingestion

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestCaptureClockAlignmentPreservesTimestamp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		capturedAt := time.Now().Add(200 * time.Millisecond)
		if err := waitForCaptureTime(t.Context(), capturedAt, time.Second); err != nil {
			t.Fatal(err)
		}
		if time.Now().Before(capturedAt) {
			t.Fatal("future source time was admitted")
		}
	})
}

func TestCaptureClockRejectsUnboundedSkew(t *testing.T) {
	for _, allowance := range []time.Duration{0, time.Second} {
		t.Run(allowance.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				if err := waitForCaptureTime(t.Context(), start.Add(2*time.Second), allowance); err == nil {
					t.Fatal("source clock skew exceeded explicit allowance")
				}
				if time.Now() != start {
					t.Fatal("rejected clock skew must not wait")
				}
			})
		})
	}
}

func TestCaptureClockWaitHonorsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		start := time.Now()
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		if err := waitForCaptureTime(ctx, start.Add(200*time.Millisecond), time.Second); !errors.Is(err, context.Canceled) {
			t.Fatalf("capture wait did not return cancellation: %v", err)
		}
		if time.Since(start) != 10*time.Millisecond {
			t.Fatal("cancellation did not interrupt source clock wait")
		}
	})
}

func TestCaptureClockRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name      string
		timestamp time.Time
		allowance time.Duration
	}{
		{name: "missing timestamp"},
		{name: "negative allowance", timestamp: time.Now(), allowance: -time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := waitForCaptureTime(t.Context(), test.timestamp, test.allowance); err == nil {
				t.Fatal("invalid capture clock configuration was admitted")
			}
		})
	}
}
