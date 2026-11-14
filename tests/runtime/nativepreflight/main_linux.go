//go:build linux

// Nativepreflight measures the local kernel resources needed to start a Kind
// node. It does not change sysctls, inspect other processes, or enroll a sensor.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type observation struct {
	ObservedAt          time.Time `json:"observedAt"`
	Kernel              string    `json:"kernel"`
	EffectiveUID        int       `json:"effectiveUID"`
	OpenDescriptors     int       `json:"openDescriptors"`
	OpenDescriptorLimit uint64    `json:"openDescriptorLimit"`
	InotifyInstanceMax  string    `json:"inotifyInstanceMax"`
	InotifyAllocation   string    `json:"inotifyAllocation"`
	InotifyError        string    `json:"inotifyError,omitempty"`
}

func observe() (observation, error) {
	out := observation{ObservedAt: time.Now().UTC(), EffectiveUID: os.Geteuid(), InotifyAllocation: "UNKNOWN"}
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return out, err
	}
	out.Kernel = strings.TrimSpace(string(kernel))
	maximum, err := os.ReadFile("/proc/sys/fs/inotify/max_user_instances")
	if err != nil {
		return out, err
	}
	out.InotifyInstanceMax = strings.TrimSpace(string(maximum))
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return out, err
	}
	out.OpenDescriptorLimit = limit.Cur
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return out, err
	}
	out.OpenDescriptors = len(fds)
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		out.InotifyAllocation = "UNAVAILABLE"
		out.InotifyError = err.Error()
		return out, fmt.Errorf("actual inotify_init1 failed: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return out, fmt.Errorf("close measured inotify descriptor: %w", err)
	}
	out.InotifyAllocation = "OBSERVED"
	return out, nil
}

func main() {
	out, err := observe()
	if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
