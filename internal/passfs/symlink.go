package passfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// exchangePathWithSymlink atomically installs a symlink and validates the
// displaced entry before deleting it. If validation fails, the original entry
// is swapped back. A failed rollback preserves the displaced entry for manual
// recovery.
func exchangePathWithSymlink(
	path string,
	target string,
	validateDisplaced func(string) error,
) (installed bool, resultErr error) {
	parent := filepath.Dir(path)
	temporaryDirectory, err := os.MkdirTemp(parent, ".passfs-link-*")
	if err != nil {
		return false, fmt.Errorf("create protected link directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporaryDirectory)
		}
	}()

	temporaryPath := filepath.Join(temporaryDirectory, "link")
	if err := os.Symlink(target, temporaryPath); err != nil {
		return false, fmt.Errorf("create protected link: %w", err)
	}
	if err := exchangePaths(temporaryPath, path); err != nil {
		return false, fmt.Errorf("atomically install protected link: %w", err)
	}

	rollback := func(cause error) (bool, error) {
		rollbackErr := exchangePaths(temporaryPath, path)
		if rollbackErr == nil {
			return false, errors.Join(cause, syncDirectory(parent))
		}
		cleanup = false
		return true, errors.Join(
			cause,
			fmt.Errorf("rollback protected link: %w", rollbackErr),
			fmt.Errorf("the displaced source entry was preserved at %s", temporaryPath),
		)
	}

	if err := validateDisplaced(temporaryPath); err != nil {
		return rollback(err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return rollback(fmt.Errorf("remove displaced entry: %w", err))
	}
	if err := syncDirectory(temporaryDirectory); err != nil {
		return true, fmt.Errorf("sync displaced entry removal: %w", err)
	}
	if err := os.Remove(temporaryDirectory); err != nil {
		return true, fmt.Errorf("remove protected link staging directory: %w", err)
	}
	cleanup = false
	if err := syncDirectory(parent); err != nil {
		return true, fmt.Errorf("sync protected link: %w", err)
	}
	return true, nil
}
