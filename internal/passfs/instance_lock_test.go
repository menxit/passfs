package passfs

import (
	"errors"
	"testing"
)

func TestInstanceLockIsGlobalPerUser(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, err := AcquireInstanceLock()
	if err != nil {
		t.Fatalf("first AcquireInstanceLock: %v", err)
	}
	defer first.Close()

	second, err := AcquireInstanceLock()
	if second != nil {
		_ = second.Close()
		t.Fatal("second AcquireInstanceLock returned a file")
	}
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second AcquireInstanceLock error = %v, want ErrAlreadyRunning", err)
	}
}
