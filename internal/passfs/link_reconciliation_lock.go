//go:build darwin || linux

package passfs

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const linkReconciliationLockFileName = "link-reconciliation.lock"

// WithLinkReconciliationLock serializes CLI imports with background
// protected-link reconciliation. It keeps a move/delete cleanup from changing
// the mounted target between classification and the atomic link replacement.
func WithLinkReconciliationLock(root string, action func() error) error {
	lockPath := filepath.Join(
		root,
		internalDirName,
		linkReconciliationLockFileName,
	)
	file, err := openCoordinationLock(lockPath)
	if err != nil {
		return fmt.Errorf("open link reconciliation lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		closeErr := file.Close()
		return errors.Join(
			fmt.Errorf("lock link reconciliation: %w", err),
			closeErr,
		)
	}
	actionErr := action()
	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		unlockErr = fmt.Errorf("unlock link reconciliation: %w", unlockErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close link reconciliation lock: %w", closeErr)
	}
	return errors.Join(actionErr, unlockErr, closeErr)
}
