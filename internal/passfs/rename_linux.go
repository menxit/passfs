//go:build linux

package passfs

import "golang.org/x/sys/unix"

func renameNoReplace(oldPath, newPath string) error {
	return unix.Renameat2(
		unix.AT_FDCWD,
		oldPath,
		unix.AT_FDCWD,
		newPath,
		unix.RENAME_NOREPLACE,
	)
}

func exchangePaths(firstPath, secondPath string) error {
	return unix.Renameat2(
		unix.AT_FDCWD,
		firstPath,
		unix.AT_FDCWD,
		secondPath,
		unix.RENAME_EXCHANGE,
	)
}
