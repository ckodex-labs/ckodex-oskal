//go:build linux || darwin

package tetragonsampler

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func openGrant(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func checkSocket(path string, uid, gid uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uid || st.Gid != gid || st.Mode&0002 != 0 {
		return fmt.Errorf("unix sensor endpoint differs from outside-owned socket DAC scope")
	}
	return nil
}
