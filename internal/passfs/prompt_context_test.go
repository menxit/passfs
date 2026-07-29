package passfs

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
)

type blockingPrompt struct {
	started chan struct{}
}

func (p *blockingPrompt) Prompt(
	ctx context.Context,
	_ PromptRequest,
) (string, error) {
	close(p.started)
	<-ctx.Done()
	return "", ctx.Err()
}

type blockingIdentityPrompt struct {
	blockingPrompt
}

func (p *blockingIdentityPrompt) PromptIdentity(
	ctx context.Context,
	_ PromptRequest,
) (*age.X25519Identity, error) {
	close(p.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWithCancellationStopsActivePrompt(t *testing.T) {
	shutdown, stop := context.WithCancel(t.Context())
	prompter := &blockingPrompt{started: make(chan struct{})}
	wrapped := WithCancellation(prompter, shutdown)

	result := make(chan error, 1)
	go func() {
		_, err := wrapped.Prompt(context.Background(), PromptRequest{})
		result <- err
	}()
	<-prompter.started
	stop()

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Prompt error = %v, want context cancellation", err)
	}
}

func TestWithCancellationPreservesIdentityPrompter(t *testing.T) {
	shutdown, stop := context.WithCancel(t.Context())
	prompter := &blockingIdentityPrompt{
		blockingPrompt: blockingPrompt{started: make(chan struct{})},
	}
	wrapped := WithCancellation(prompter, shutdown)
	identityPrompter, ok := wrapped.(IdentityPrompter)
	if !ok {
		t.Fatal("wrapped prompter does not implement IdentityPrompter")
	}

	result := make(chan error, 1)
	go func() {
		_, err := identityPrompter.PromptIdentity(
			context.Background(),
			PromptRequest{},
		)
		result <- err
	}()
	<-prompter.started
	stop()

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("PromptIdentity error = %v, want context cancellation", err)
	}
}

func TestServiceCancellationReleasesBlockedFUSECreate(t *testing.T) {
	initialized, _ := initializeTestVolume(t, "unused passphrase", 1024*1024)
	shutdown, stop := context.WithCancel(t.Context())
	prompter := &blockingIdentityPrompt{
		blockingPrompt: blockingPrompt{started: make(chan struct{})},
	}
	volume, err := LoadVolume(
		initialized.root,
		WithCancellation(prompter, shutdown),
		1024*1024,
		0,
	)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := volume.createFile(
			context.Background(),
			"files/tmp/cancelled.env",
			syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL,
			0o600,
		)
		result <- err
	}()
	<-prompter.started
	stop()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("createFile error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("createFile remained blocked after service cancellation")
	}

	volume.locksMu.Lock()
	defer volume.locksMu.Unlock()
	if len(volume.locks) != 0 {
		t.Fatalf("path locks remain after cancelled create: %d", len(volume.locks))
	}
}
