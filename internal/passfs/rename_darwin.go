//go:build darwin

package passfs

import "golang.org/x/sys/unix"

func renameNoReplace(oldPath, newPath string) error {
	return unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
}

func exchangePaths(firstPath, secondPath string) error {
	return unix.RenamexNp(firstPath, secondPath, unix.RENAME_SWAP)
}
