package passfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

var ErrAlreadyRunning = errors.New("passfs is already running")

const instanceLockRetryInterval = 25 * time.Millisecond

// AcquireInstanceLock prevents multiple passfs servers for the same OS user,
// even if someone invokes the internal server with a different config file.
func AcquireInstanceLock() (*os.File, error) {
	settingsPath, err := DefaultSettingsPath()
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(filepath.Dir(settingsPath), "passfs.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("lock passfs instance: %w", err)
	}
	return file, nil
}

// AcquireInstanceLockContext waits for a shutting-down server to release the
// global lock. This closes the short interval between a filesystem becoming
// unmounted and its service process exiting.
func AcquireInstanceLockContext(ctx context.Context) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ticker := time.NewTicker(instanceLockRetryInterval)
	defer ticker.Stop()

	for {
		file, err := AcquireInstanceLock()
		if !errors.Is(err, ErrAlreadyRunning) {
			return file, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
