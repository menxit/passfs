//go:build darwin

package passfs

import (
	"errors"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

type darwinProtectedLinkReference struct {
	fd int
}

func openProtectedLinkReference(path string) (protectedLinkReference, error) {
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_SYMLINK|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	return &darwinProtectedLinkReference{fd: fd}, nil
}

func (reference *darwinProtectedLinkReference) currentPath() (string, bool, error) {
	var status unix.Stat_t
	if err := unix.Fstat(reference.fd, &status); err != nil {
		return "", false, err
	}
	if status.Nlink == 0 {
		return "", false, nil
	}

	buffer := make([]byte, 4096)
	_, err := unix.FcntlInt(
		uintptr(reference.fd),
		unix.F_GETPATH,
		int(uintptr(unsafe.Pointer(&buffer[0]))),
	)
	if err != nil {
		return "", false, err
	}
	for index, value := range buffer {
		if value == 0 {
			if index == 0 {
				return "", false, errors.New(
					"kernel returned an empty protected link path",
				)
			}
			return filepath.Clean(string(buffer[:index])), true, nil
		}
	}
	return "", false, errors.New("protected link path exceeds the macOS limit")
}

func (reference *darwinProtectedLinkReference) close() error {
	return unix.Close(reference.fd)
}
