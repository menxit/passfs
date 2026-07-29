//go:build darwin || linux

package passfs

import "golang.org/x/sys/unix"

func MarkProtectedLink(targetPath string) error {
	return setControlXattr(targetPath, linkMarkerName, []byte(targetPath))
}

func setControlXattr(targetPath, name string, value []byte) error {
	return unix.Setxattr(targetPath, name, value, 0)
}
