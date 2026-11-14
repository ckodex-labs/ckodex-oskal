//go:build linux

// Nativefilter emits an arm64 classic-BPF filter consumed by setpriv. It limits
// only bpf(2); other system calls remain allowed. This is a read-boundary
// experiment, not a complete production seccomp profile.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func main() {
	profile := flag.String("profile", "", "explicit read-only or deny BPF profile")
	flag.Parse()
	if runtime.GOARCH != "arm64" || (*profile != "read-only" && *profile != "deny") {
		fmt.Fprintln(os.Stderr, "requires Linux arm64 and profile read-only or deny")
		os.Exit(1)
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.AUDIT_ARCH_AARCH64},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	if *profile == "deny" {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_BPF},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	} else {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 6, K: unix.SYS_BPF},
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 4, K: unix.BPF_MAP_LOOKUP_ELEM},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 3, K: unix.BPF_MAP_GET_NEXT_KEY},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, K: unix.BPF_OBJ_GET},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.BPF_OBJ_GET_INFO_BY_FD},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	}
	if err := binary.Write(os.Stdout, binary.LittleEndian, filter); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
