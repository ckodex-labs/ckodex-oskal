//go:build linux

package tetragonhealth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	kernelStatsBytes = 256 * 7 * 8
	readRole         = "tetragon.health.read"
)

type kernelStats struct {
	SentFailed [256][7]uint64
}

type cgroupRateValue struct {
	Curr, Prev, Time, Rate, Throttled uint64
}

type nativeRead struct {
	grant      RoleGrant
	enrollment Enrollment
}

// ReadWitness reads actual pinned Tetragon maps. It creates no maps, programs,
// mounts, capabilities or synthetic zero values. The caller must authenticate
// the enrollment and grant independently before invoking this adapter.
func ReadWitness(ctx context.Context, enrollment Enrollment, grant RoleGrant) (out KernelWitness, err error) {
	out = KernelWitness{Contract: ContractVersion, Availability: Unknown, EnrollmentDigest: enrollment.Digest, GrantDigest: grant.Digest, StartedAt: time.Now().UTC(), Throttle: ThrottleObservation{Availability: Unknown, Reason: "effective throttle configuration has not been measured"}}
	defer func() {
		out.CompletedAt = time.Now().UTC()
		if err != nil {
			out.Availability, out.Reason = Unknown, err.Error()
		}
	}()
	if err = validateEnrollment(enrollment); err != nil {
		return out, err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		return out, fmt.Errorf("native read requires a context deadline within five seconds")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r := nativeRead{grant: grant, enrollment: enrollment}
	if err = r.check(ctx); err != nil {
		return out, err
	}
	out.Credentials = grant.Credentials
	out.Identity, err = r.identity(ctx)
	if err != nil {
		return out, err
	}
	out.PossibleCPUs, err = ebpf.PossibleCPU()
	if err != nil || out.PossibleCPUs < 1 || out.PossibleCPUs > enrollment.MaxPossibleCPUs {
		return out, fmt.Errorf("possible CPU count unavailable or exceeds enrollment bound: %d (%v)", out.PossibleCPUs, err)
	}
	if err = r.checkCPUCount(ctx, out.PossibleCPUs); err != nil {
		return out, err
	}
	opened := make(map[string]*ebpf.Map, len(enrollment.Maps))
	defer func() {
		for _, m := range opened {
			if closeErr := m.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("close BPF descriptor: %w", closeErr)
			}
		}
	}()
	for _, expected := range enrollment.Maps {
		m, openErr := r.open(ctx, expected)
		if openErr != nil {
			return out, openErr
		}
		opened[expected.Name] = m
		out.Maps = append(out.Maps, MapObservation{MapEnrollment: expected})
	}
	var perCPU []kernelStats
	if err = r.lookup(ctx, opened["tg_stats_map"], uint32(0), &perCPU); err != nil {
		return out, fmt.Errorf("read kernel output failures: %w", err)
	}
	if len(perCPU) != out.PossibleCPUs {
		return out, fmt.Errorf("kernel output failure CPU layout mismatch")
	}
	var sum kernelStats
	for _, cpu := range perCPU {
		for op, failures := range cpu.SentFailed {
			for failure, value := range failures {
				if math.MaxUint64-sum.SentFailed[op][failure] < value {
					return out, fmt.Errorf("kernel output failure counter overflow")
				}
				sum.SentFailed[op][failure] += value
			}
		}
	}
	errorNames := [...]string{"unknown", "ENOENT", "E2BIG", "EBUSY", "EINVAL", "ENOSPC", "EAGAIN"}
	for op, failures := range sum.SentFailed {
		for failure, value := range failures {
			out.Loss = append(out.Loss, KernelLoss{Opcode: uint8(op), Error: errorNames[failure], Value: value})
		}
	}
	for i := range out.Maps {
		name := out.Maps[i].Name
		if name != "execve_map" && name != "tg_execve_joined_info_map" {
			continue
		}
		stats, statsErr := r.mapStats(ctx, opened[name+"_stats"], out.PossibleCPUs)
		if statsErr != nil {
			return out, fmt.Errorf("read %s statistics: %w", name, statsErr)
		}
		if stats.Entries > uint64(out.Maps[i].MaxEntries) {
			return out, fmt.Errorf("%s usage exceeds enrolled capacity", name)
		}
		out.Maps[i].Stats = &stats
	}
	if enrollment.ThrottleEnabled {
		out.Throttle, err = r.throttle(ctx, opened["cgroup_rate_options_map"], opened["cgroup_rate_map"], out.PossibleCPUs)
		if err != nil {
			return out, err
		}
	}
	// Reopening catches pin replacement or removal while an old descriptor was readable.
	for _, expected := range enrollment.Maps {
		m, reopenErr := r.open(ctx, expected)
		if reopenErr != nil {
			return out, fmt.Errorf("revalidate pinned map: %w", reopenErr)
		}
		if err = m.Close(); err != nil {
			return out, fmt.Errorf("close revalidated map: %w", err)
		}
	}
	finalIdentity, identityErr := r.identity(ctx)
	if identityErr != nil {
		return out, identityErr
	}
	if finalIdentity != out.Identity {
		return out, fmt.Errorf("sensor identity changed during read")
	}
	if err = r.check(ctx); err != nil {
		return out, err
	}
	if err = r.checkCPUCount(ctx, out.PossibleCPUs); err != nil {
		return out, err
	}
	if out.Throttle.Availability != Observed {
		out.Reason = out.Throttle.Reason
		return out, nil
	}
	out.Availability = Observed
	return out, nil
}

func validateEnrollment(e Enrollment) error {
	if !validDigest(e.Digest) || !validUUID(e.BootID) || !validUUID(e.PodUID) || e.SensorPID < 1 || e.ProcessStartTicks == 0 || !filepath.IsAbs(e.MapRoot) || filepath.Clean(e.MapRoot) != e.MapRoot || e.MapRoot == "/" || e.MaxPossibleCPUs < 1 || e.MaxPossibleCPUs > 256 || e.MaxThrottleEntries < 1 || e.MaxThrottleEntries > 1024 {
		return fmt.Errorf("complete bounded sensor enrollment is required")
	}
	required := map[string]bool{"tg_stats_map": false, "execve_map": false, "execve_map_stats": false, "tg_execve_joined_info_map": false, "tg_execve_joined_info_map_stats": false}
	if e.ThrottleEnabled {
		required["cgroup_rate_options_map"], required["cgroup_rate_map"] = false, false
	}
	if len(e.Maps) != len(required) {
		return fmt.Errorf("map enrollment must contain exactly the required v1.8 maps")
	}
	for _, m := range e.Maps {
		present, ok := required[m.Name]
		if !ok || present || m.ID == 0 || m.MaxEntries == 0 || m.MaxEntries > 1<<24 {
			return fmt.Errorf("invalid, duplicate or unbounded enrolled map %q", m.Name)
		}
		required[m.Name] = true
		if err := validateMapABI(m); err != nil {
			return err
		}
	}
	return nil
}

func validateMapABI(m MapEnrollment) error {
	typ, key, value, capacity := uint32(ebpf.PerCPUArray), uint32(4), uint32(8), uint32(3)
	switch m.Name {
	case "tg_stats_map":
		value, capacity = kernelStatsBytes, 1
	case "execve_map_stats", "tg_execve_joined_info_map_stats":
	case "execve_map":
		typ, value, capacity = uint32(ebpf.Hash), m.ValueSize, m.MaxEntries
	case "tg_execve_joined_info_map":
		typ, key, value, capacity = uint32(ebpf.LRUHash), 8, m.ValueSize, m.MaxEntries
	case "cgroup_rate_options_map":
		typ, value, capacity = uint32(ebpf.Array), 16, 1
	case "cgroup_rate_map":
		typ, key, value, capacity = uint32(ebpf.PerCPUHash), 8, 40, 32768
	default:
		return fmt.Errorf("unsupported v1.8 health map")
	}
	if m.Type != typ || m.KeySize != key || m.ValueSize != value || value < 1 || value > 64<<10 || m.MaxEntries != capacity {
		return fmt.Errorf("map %s has incompatible v1.8 ABI", m.Name)
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}

func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && s == strings.ToLower(s)
}

// CurrentCredentials measures this OS thread. It is not a role authorization.
func CurrentCredentials() (Credentials, error) {
	var out Credentials
	raw, err := readBoundedFile("/proc/thread-self/status", 32<<10)
	if err != nil {
		return out, err
	}
	uidFound, capsFound := false, false
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" {
			effective, effectiveErr := strconv.ParseUint(fields[2], 10, 32)
			filesystem, filesystemErr := strconv.ParseUint(fields[4], 10, 32)
			if effectiveErr != nil || filesystemErr != nil {
				return out, fmt.Errorf("invalid current UID status")
			}
			out.EffectiveUID, out.FilesystemUID = uint32(effective), uint32(filesystem)
			uidFound = true
		}
		if len(fields) == 2 && fields[0] == "CapEff:" {
			out.EffectiveCaps, err = strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return out, fmt.Errorf("invalid current capability status: %w", err)
			}
			capsFound = true
		}
	}
	if !uidFound || !capsFound {
		return out, fmt.Errorf("current credentials unavailable")
	}
	out.UserNamespace, err = os.Readlink("/proc/thread-self/ns/user")
	if err != nil {
		return out, err
	}
	out.MountNamespace, err = os.Readlink("/proc/thread-self/ns/mnt")
	return out, err
}

func (r nativeRead) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.grant.Role != readRole || !validDigest(r.grant.Digest) || r.grant.EnrollmentDigest != r.enrollment.Digest || !time.Now().Before(r.grant.ValidUntil) || r.grant.Credentials.UserNamespace == "" || r.grant.Credentials.MountNamespace == "" {
		return fmt.Errorf("current read role grant missing, expired or invalid")
	}
	actual, err := CurrentCredentials()
	if err != nil {
		return fmt.Errorf("measure operation-time credentials: %w", err)
	}
	if actual != r.grant.Credentials {
		return fmt.Errorf("operation-time credentials differ from read grant")
	}
	return nil
}

func (r nativeRead) open(ctx context.Context, expected MapEnrollment) (*ebpf.Map, error) {
	if err := r.check(ctx); err != nil {
		return nil, err
	}
	// Never follow a symlink into an unrelated filesystem or map directory.
	for path := r.enrollment.MapRoot; path != "/"; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("map root contains a missing or non-directory component")
		}
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(r.enrollment.MapRoot, &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		return nil, fmt.Errorf("enrolled map root is not mounted bpffs")
	}
	path := filepath.Join(r.enrollment.MapRoot, expected.Name)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("enrolled pin missing or a symlink: %s", expected.Name)
	}
	if err := r.check(ctx); err != nil {
		return nil, err
	}
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("open read-only %s: %w", expected.Name, err)
	}
	if err := r.check(ctx); err != nil {
		_ = m.Close()
		return nil, err
	}
	actual, err := m.Info()
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("read map information: %w", err)
	}
	id, hasID := actual.ID()
	if !hasID || uint32(id) != expected.ID || uint32(actual.Type) != expected.Type || actual.KeySize != expected.KeySize || actual.ValueSize != expected.ValueSize || actual.MaxEntries != expected.MaxEntries {
		_ = m.Close()
		return nil, fmt.Errorf("map %s identity or ABI differs from enrollment", expected.Name)
	}
	if err := r.check(ctx); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

func (r nativeRead) lookup(ctx context.Context, m *ebpf.Map, key, value any) error {
	if err := r.check(ctx); err != nil {
		return err
	}
	if err := m.Lookup(key, value); err != nil {
		return err
	}
	return r.check(ctx)
}

func (r nativeRead) checkCPUCount(ctx context.Context, expected int) error {
	if err := r.check(ctx); err != nil {
		return err
	}
	raw, err := readBoundedFile("/sys/devices/system/cpu/possible", 256)
	if err != nil {
		return fmt.Errorf("read current possible CPUs: %w", err)
	}
	spec := strings.TrimSpace(string(raw))
	if expected == 1 && spec == "0" {
		return r.check(ctx)
	}
	if spec != "0-"+strconv.Itoa(expected-1) {
		return fmt.Errorf("current possible CPU layout differs from BPF library layout")
	}
	return r.check(ctx)
}

func (r nativeRead) mapStats(ctx context.Context, m *ebpf.Map, cpus int) (MapStats, error) {
	var out MapStats
	values := []*uint64{&out.Entries, &out.UpdateErrors, &out.DeleteErrors}
	for key, target := range values {
		var perCPU []int64
		if err := r.lookup(ctx, m, int32(key), &perCPU); err != nil {
			return out, err
		}
		if len(perCPU) != cpus {
			return out, fmt.Errorf("map statistic CPU layout mismatch")
		}
		// Signed per-CPU entry deltas may be negative; the checked total must not be.
		var total int64
		for _, n := range perCPU {
			if (n > 0 && total > math.MaxInt64-n) || (n < 0 && total < math.MinInt64-n) {
				return out, fmt.Errorf("map statistic overflow")
			}
			total += n
		}
		if total < 0 {
			return out, fmt.Errorf("negative aggregate map statistic")
		}
		*target = uint64(total)
	}
	return out, nil
}

func (r nativeRead) throttle(ctx context.Context, options, rates *ebpf.Map, cpus int) (ThrottleObservation, error) {
	out := ThrottleObservation{Availability: Unknown}
	var config struct{ Events, Interval uint64 }
	if err := r.lookup(ctx, options, uint32(0), &config); err != nil {
		return out, fmt.Errorf("read throttle options: %w", err)
	}
	if config.Events == 0 || config.Interval == 0 {
		return out, fmt.Errorf("enrolled enabled throttle has inactive options")
	}
	out.Events, out.IntervalNS = config.Events, config.Interval
	first, active, err := r.throttleEntries(ctx, rates, cpus)
	if err != nil {
		return out, err
	}
	second, moreActive, err := r.throttleEntries(ctx, rates, cpus)
	if err != nil {
		return out, err
	}
	if !slices.Equal(first, second) {
		return out, fmt.Errorf("throttle map keys changed during bounded enumeration")
	}
	var finalConfig struct{ Events, Interval uint64 }
	if err := r.lookup(ctx, options, uint32(0), &finalConfig); err != nil || config != finalConfig {
		return out, fmt.Errorf("throttle options changed or became unreadable")
	}
	out.Entries = len(first)
	out.ActiveCgroups = append(active, moreActive...)
	slices.Sort(out.ActiveCgroups)
	out.ActiveCgroups = slices.Compact(out.ActiveCgroups)
	out.Availability = Observed
	return out, nil
}

func (r nativeRead) throttleEntries(ctx context.Context, m *ebpf.Map, cpus int) ([]uint64, []uint64, error) {
	var keys, active []uint64
	var previous any
	seen := make(map[uint64]bool)
	for {
		if err := r.check(ctx); err != nil {
			return nil, nil, err
		}
		var key uint64
		err := m.NextKey(previous, &key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("enumerate throttle map: %w", err)
		}
		if seen[key] || len(keys) >= r.enrollment.MaxThrottleEntries {
			return nil, nil, fmt.Errorf("throttle enumeration repeated a key or exceeded bound")
		}
		seen[key] = true
		keys = append(keys, key)
		var values []cgroupRateValue
		if err := r.lookup(ctx, m, key, &values); err != nil {
			return nil, nil, fmt.Errorf("read throttle cgroup: %w", err)
		}
		if len(values) != cpus {
			return nil, nil, fmt.Errorf("throttle CPU layout mismatch")
		}
		for _, value := range values {
			if value.Throttled != 0 {
				active = append(active, key)
				break
			}
		}
		previous = key
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys, active, nil
}

func (r nativeRead) identity(ctx context.Context) (SensorIdentity, error) {
	var out SensorIdentity
	if err := r.check(ctx); err != nil {
		return out, err
	}
	boot, err := readBoundedFile("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return out, err
	}
	out.BootID = strings.TrimSpace(string(boot))
	out.SensorPID = r.enrollment.SensorPID
	proc := "/proc/" + strconv.Itoa(out.SensorPID)
	if err := r.check(ctx); err != nil {
		return out, err
	}
	stat, err := readBoundedFile(proc+"/stat", 16<<10)
	if err != nil {
		return out, err
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return out, fmt.Errorf("sensor process stat is malformed")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return out, fmt.Errorf("sensor process stat has no start time")
	}
	if fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return out, fmt.Errorf("enrolled sensor process is no longer alive")
	}
	out.ProcessStartTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return out, fmt.Errorf("decode process start ticks: %w", err)
	}
	if err := r.check(ctx); err != nil {
		return out, err
	}
	cgroup, err := readBoundedFile(proc+"/cgroup", 16<<10)
	if err != nil {
		return out, err
	}
	out.CgroupDigest = digest(cgroup)
	uid := r.enrollment.PodUID
	if !cgroupContainsPod(cgroup, uid) {
		return out, fmt.Errorf("sensor cgroup does not contain enrolled Pod UID")
	}
	out.PodUID = uid
	if out.BootID != r.enrollment.BootID || out.ProcessStartTicks != r.enrollment.ProcessStartTicks {
		return out, fmt.Errorf("actual boot or process generation differs from enrollment")
	}
	return out, r.check(ctx)
}

func cgroupContainsPod(raw []byte, uid string) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, component := range strings.Split(parts[2], "/") {
			for _, form := range []string{uid, strings.ReplaceAll(uid, "-", "_")} {
				if component == "pod"+form || component == "pod"+form+".slice" || strings.HasSuffix(component, "-pod"+form+".slice") {
					return true
				}
			}
		}
	}
	return false
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maximum+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(raw)) > maximum {
		return nil, fmt.Errorf("proc file exceeds byte bound")
	}
	return raw, nil
}
