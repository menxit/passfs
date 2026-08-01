package passfs

import (
	"context"
	"errors"
	"testing"
	"time"
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

func TestAcquireInstanceLockContextWaitsForRelease(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, err := AcquireInstanceLock()
	if err != nil {
		t.Fatalf("first AcquireInstanceLock: %v", err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(2 * instanceLockRetryInterval)
		_ = first.Close()
		close(released)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := AcquireInstanceLockContext(ctx)
	if err != nil {
		t.Fatalf("AcquireInstanceLockContext: %v", err)
	}
	defer second.Close()
	<-released
}

func TestAcquireInstanceLockContextHonorsDeadline(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, err := AcquireInstanceLock()
	if err != nil {
		t.Fatalf("first AcquireInstanceLock: %v", err)
	}
	defer first.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		2*instanceLockRetryInterval,
	)
	defer cancel()
	second, err := AcquireInstanceLockContext(ctx)
	if second != nil {
		_ = second.Close()
		t.Fatal("AcquireInstanceLockContext returned a file")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf(
			"AcquireInstanceLockContext error = %v, want context deadline exceeded",
			err,
		)
	}
}
