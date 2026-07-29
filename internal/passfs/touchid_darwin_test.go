//go:build darwin

package passfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTouchIDPromptCanBeCancelledWhileNativeCallIsBlocked(t *testing.T) {
	nativeCall := make(chan struct{})
	prompter := &TouchIDPrompter{
		copyIdentity: func(string, string) ([]byte, error) {
			<-nativeCall
			return nil, ErrPromptCancelled
		},
		timeout: time.Minute,
	}
	ctx, cancel := context.WithCancel(t.Context())

	result := make(chan error, 1)
	go func() {
		_, err := prompter.PromptIdentity(ctx, PromptRequest{})
		result <- err
	}()
	waitForTouchIDPrompt(t, prompter)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("PromptIdentity error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("PromptIdentity did not return after cancellation")
	}

	if _, err := prompter.PromptIdentity(t.Context(), PromptRequest{}); !errors.Is(
		err,
		ErrTouchIDInProgress,
	) {
		t.Fatalf("concurrent PromptIdentity error = %v, want in-progress error", err)
	}
	close(nativeCall)
}

func TestTouchIDPromptTimesOutWhileNativeCallIsBlocked(t *testing.T) {
	nativeCall := make(chan struct{})
	prompter := &TouchIDPrompter{
		copyIdentity: func(string, string) ([]byte, error) {
			<-nativeCall
			return nil, ErrPromptCancelled
		},
		timeout: 10 * time.Millisecond,
	}

	_, err := prompter.PromptIdentity(t.Context(), PromptRequest{})
	if !errors.Is(err, ErrTouchIDTimeout) {
		t.Fatalf("PromptIdentity error = %v, want timeout", err)
	}
	close(nativeCall)
}

func TestTouchIDHelperTimesOut(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "blocked-touchid-helper")
	if err := os.WriteFile(
		executable,
		[]byte("#!/bin/sh\nexec /bin/sleep 30\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	prompter := &TouchIDHelperPrompter{
		executable: executable,
		vault:      t.TempDir(),
		timeout:    10 * time.Millisecond,
	}
	if _, err := prompter.PromptIdentity(
		t.Context(),
		PromptRequest{},
	); !errors.Is(err, ErrTouchIDTimeout) {
		t.Fatalf("PromptIdentity error = %v, want timeout", err)
	}
}

func waitForTouchIDPrompt(t *testing.T, prompter *TouchIDPrompter) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		prompter.mu.Lock()
		active := prompter.active
		prompter.mu.Unlock()
		if active {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Touch ID prompt did not start")
}
