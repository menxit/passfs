//go:build linux

package passfs

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type linuxProtectedLinkReference struct {
	fd int
}

func openProtectedLinkReference(path string) (protectedLinkReference, error) {
	fd, err := unix.Open(
		path,
		unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	return &linuxProtectedLinkReference{fd: fd}, nil
}

func (reference *linuxProtectedLinkReference) currentPath() (string, bool, error) {
	var status unix.Stat_t
	if err := unix.Fstat(reference.fd, &status); err != nil {
		return "", false, err
	}
	if status.Nlink == 0 {
		return "", false, nil
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", reference.fd))
	if err != nil {
		return "", false, err
	}
	return filepath.Clean(path), true, nil
}

func (reference *linuxProtectedLinkReference) close() error {
	return unix.Close(reference.fd)
}
