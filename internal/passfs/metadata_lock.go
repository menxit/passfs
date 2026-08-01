//go:build darwin || linux

package passfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const metadataLockFileName = "metadata.lock"

// withMetadataFileLock serializes metadata.json replacements across the CLI,
// the FUSE service, and an FSKit extension process. The lock lives in a
// separate inode because metadata.json itself is replaced atomically.
func withMetadataFileLock(root string, action func() error) error {
	lockPath := filepath.Join(root, internalDirName, metadataLockFileName)
	file, err := openCoordinationLock(lockPath)
	if err != nil {
		return fmt.Errorf("open metadata lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return fmt.Errorf("lock metadata: %w", err)
	}

	actionErr := action()
	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		unlockErr = fmt.Errorf("unlock metadata: %w", unlockErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close metadata lock: %w", closeErr)
	}
	return errors.Join(actionErr, unlockErr, closeErr)
}

// Keep the lock descriptor read-only. Merely closing an O_RDWR descriptor
// produces a filesystem write event on Linux even when no bytes changed,
// which would wake the metadata watcher and immediately reconcile again.
func openCoordinationLock(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return file, err
	}
	file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return os.Open(path)
	}
	return file, err
}
