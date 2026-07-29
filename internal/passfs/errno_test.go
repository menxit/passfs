package passfs

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestErrnoFromErrorPreservesWrappedErrno(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("open encrypted target: %w", syscall.ENOENT)
	if got := errnoFromError(err); got != syscall.ENOENT {
		t.Fatalf("errnoFromError() = %v, want %v", got, syscall.ENOENT)
	}
}

func TestErrnoFromErrorUsesIOForUnknownError(t *testing.T) {
	t.Parallel()

	if got := errnoFromError(errors.New("prompt helper failed")); got != syscall.EIO {
		t.Fatalf("errnoFromError() = %v, want %v", got, syscall.EIO)
	}
}
