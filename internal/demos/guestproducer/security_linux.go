//go:build linux

package guestproducer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DropCapabilities applies to every runtime thread. Calling a thread-local
// capset alone would leave sampling goroutines able to inherit other threads'
// startup authority. Build this source with CGO_ENABLED=0.
func DropCapabilities() error {
	raw, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return err
	}
	last, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || last < 0 || last > 63 {
		return fmt.Errorf("kernel capability range is unavailable or unsupported")
	}
	for capability := 0; capability <= last; capability++ {
		present, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, uintptr(capability), 0)
		if errno != 0 {
			return errno
		}
		if present != 0 {
			if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(capability), 0); errno != 0 {
				return errno
			}
		}
	}
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
