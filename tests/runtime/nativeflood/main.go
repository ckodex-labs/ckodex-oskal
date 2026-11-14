// Nativeflood generates bounded real exec/exit activity. It does not write BPF
// maps, throttle the sensor, disconnect collectors, or infer event-loss counts.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	workers := flag.Int("workers", 0, "explicit concurrent workers, 1..64")
	duration := flag.Duration("duration", 0, "explicit workload duration, at most 30s")
	flag.Parse()
	if *workers < 1 || *workers > 64 || *duration <= 0 || *duration > 30*time.Second {
		fmt.Fprintln(os.Stderr, "requires 1..64 workers and duration in (0,30s]")
		os.Exit(2)
	}
	runtime.GOMAXPROCS(2)
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *duration)
	defer cancel()
	started := time.Now().UTC()
	var attempted, completed, failed, canceled atomic.Uint64
	var workersDone sync.WaitGroup
	for range *workers {
		workersDone.Go(func() {
			for ctx.Err() == nil {
				attempted.Add(1)
				command := exec.CommandContext(ctx, "/bin/true")
				command.WaitDelay = 250 * time.Millisecond
				if err := command.Run(); err != nil {
					if ctx.Err() != nil {
						canceled.Add(1)
						return
					}
					failed.Add(1)
					continue
				}
				completed.Add(1)
			}
		})
	}
	workersDone.Wait()
	result := struct {
		StartedAt   time.Time     `json:"startedAt"`
		CompletedAt time.Time     `json:"completedAt"`
		Workers     int           `json:"workers"`
		Budget      time.Duration `json:"budgetNS"`
		Attempted   uint64        `json:"attempted"`
		Completed   uint64        `json:"completed"`
		Failed      uint64        `json:"failed"`
		Canceled    uint64        `json:"canceledAtDeadline"`
	}{started, time.Now().UTC(), *workers, *duration, attempted.Load(), completed.Load(), failed.Load(), canceled.Load()}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if failed.Load() != 0 {
		os.Exit(1)
	}
}
