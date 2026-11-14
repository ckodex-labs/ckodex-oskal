//go:build linux

// Nativehealth inventories actual sensor objects and executes an externally
// authorized read grant. Inventory is observed metadata, never self-enrollment.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

type input struct {
	Enrollment tetragonhealth.Enrollment `json:"enrollment"`
	Grant      tetragonhealth.RoleGrant  `json:"grant"`
}

type inventory struct {
	ObservedAt          time.Time                  `json:"observedAt"`
	Kernel              string                     `json:"kernel"`
	Cgroup              string                     `json:"cgroup"`
	Credentials         tetragonhealth.Credentials `json:"credentials"`
	CandidateEnrollment tetragonhealth.Enrollment  `json:"candidateEnrollment"`
}

func boundedFile(path string, maximum int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return raw, nil
}

func inspect(pid int, podUID, root string) (inventory, error) {
	out := inventory{ObservedAt: time.Now().UTC()}
	if pid < 1 || len(podUID) != 36 || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return out, fmt.Errorf("explicit sensor PID, Pod UID, and absolute clean BPF root are required")
	}
	credentials, err := tetragonhealth.CurrentCredentials()
	if err != nil {
		return out, err
	}
	out.Credentials = credentials
	kernel, err := boundedFile("/proc/sys/kernel/osrelease", 256)
	if err != nil {
		return out, err
	}
	out.Kernel = strings.TrimSpace(string(kernel))
	boot, err := boundedFile("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return out, err
	}
	stat, err := boundedFile(fmt.Sprintf("/proc/%d/stat", pid), 16<<10)
	if err != nil {
		return out, err
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return out, fmt.Errorf("sensor stat has no command terminator")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return out, fmt.Errorf("sensor stat has no start ticks")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return out, err
	}
	cgroup, err := boundedFile(fmt.Sprintf("/proc/%d/cgroup", pid), 16<<10)
	if err != nil {
		return out, err
	}
	out.Cgroup = string(cgroup)
	e := tetragonhealth.Enrollment{BootID: strings.TrimSpace(string(boot)), SensorPID: pid, ProcessStartTicks: ticks, PodUID: podUID, MapRoot: root, ThrottleEnabled: true, MaxPossibleCPUs: 256, MaxThrottleEntries: 1024}
	for _, name := range []string{"tg_stats_map", "execve_map", "execve_map_stats", "tg_execve_joined_info_map", "tg_execve_joined_info_map_stats", "cgroup_rate_options_map", "cgroup_rate_map"} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(root, name), &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			return out, fmt.Errorf("inventory %s: %w", name, err)
		}
		info, infoErr := m.Info()
		closeErr := m.Close()
		if infoErr != nil {
			return out, infoErr
		}
		if closeErr != nil {
			return out, closeErr
		}
		id, ok := info.ID()
		if !ok {
			return out, fmt.Errorf("map %s has no observed kernel ID", name)
		}
		e.Maps = append(e.Maps, tetragonhealth.MapEnrollment{Name: name, ID: uint32(id), Type: uint32(info.Type), KeySize: info.KeySize, ValueSize: info.ValueSize, MaxEntries: info.MaxEntries})
	}
	canonical, err := json.Marshal(e)
	if err != nil {
		return out, err
	}
	e.Digest = assurance.ComputeDigest(canonical)
	out.CandidateEnrollment = e
	return out, nil
}

func read(path string) (tetragonhealth.KernelWitness, error) {
	raw, err := boundedFile(path, 64<<10)
	if err != nil {
		return tetragonhealth.KernelWitness{Availability: tetragonhealth.Unknown}, err
	}
	var in input
	if err := signedrecords.DecodeJSON(raw, &in, 64<<10); err != nil {
		return tetragonhealth.KernelWitness{Availability: tetragonhealth.Unknown}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tetragonhealth.ReadWitness(ctx, in.Enrollment, in.Grant)
}

func run() (any, error) {
	mode := flag.String("mode", "", "inventory, credentials, or read; no mutation mode")
	pid := flag.Int("sensor-pid", 0, "actual sensor PID in this proc namespace")
	podUID := flag.String("pod-uid", "", "externally observed sensor Pod UID")
	root := flag.String("map-root", "", "explicit pinned BPF map root")
	path := flag.String("input", "", "private externally authorized enrollment/grant JSON")
	flag.Parse()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	switch *mode {
	case "inventory":
		return inspect(*pid, *podUID, *root)
	case "credentials":
		return tetragonhealth.CurrentCredentials()
	case "read":
		return read(*path)
	default:
		return nil, fmt.Errorf("mode must be inventory, credentials, or read")
	}
}

func main() {
	result, err := run()
	out := struct {
		Result any    `json:"result"`
		Error  string `json:"error,omitempty"`
	}{Result: result}
	if err != nil {
		out.Error = err.Error()
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
