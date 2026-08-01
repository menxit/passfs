//go:build darwin

package passfs

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type brokerTestPrompter struct {
	mu       sync.Mutex
	response string
	err      error
	requests []PromptRequest
}

type blockingBrokerTestPrompter struct {
	started chan struct{}
	once    sync.Once
}

func (prompter *blockingBrokerTestPrompter) Prompt(
	ctx context.Context,
	_ PromptRequest,
) (string, error) {
	prompter.once.Do(func() { close(prompter.started) })
	<-ctx.Done()
	return "", ctx.Err()
}

func (prompter *brokerTestPrompter) Prompt(
	_ context.Context,
	request PromptRequest,
) (string, error) {
	prompter.mu.Lock()
	defer prompter.mu.Unlock()
	prompter.requests = append(prompter.requests, request)
	return prompter.response, prompter.err
}

func allowAuthorizationPeer(*net.UnixConn, string) error {
	return nil
}

func newBrokerTestVault(t *testing.T) string {
	t.Helper()
	vault := t.TempDir()
	if err := os.Mkdir(filepath.Join(vault, internalDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFileAtomic(
		filepath.Join(vault, internalDirName, publicConfigName),
		PublicConfig{
			Version:   formatVersion,
			VolumeID:  strings.ReplaceAll(objectID, "-", ""),
			Recipient: "test-recipient",
		},
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return vault
}

func newBrokerTestRuntimeDirectory(t *testing.T) string {
	t.Helper()
	runtimeDirectory, err := os.MkdirTemp("/tmp", "passfs-auth-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(runtimeDirectory); err != nil {
			t.Error(err)
		}
	})
	return runtimeDirectory
}

func TestFSKitPassphraseBrokerRoundTrip(t *testing.T) {
	vault := newBrokerTestVault(t)
	runtimeDirectory := newBrokerTestRuntimeDirectory(t)
	prompter := &brokerTestPrompter{response: "correct horse battery staple"}
	broker, err := startFSKitPassphraseBrokerIn(
		vault,
		prompter,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := broker.Close(); err != nil {
			t.Error(err)
		}
	})

	socketPath, err := authorizationBrokerSocketPathIn(vault, runtimeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	socketInfo, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := socketInfo.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("socket permissions = %o, want 600", permissions)
	}
	promptClient, err := newFSKitPassphrasePrompterIn(
		vault,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := PromptRequest{
		Path:      "/Users/federico/project/.env",
		Operation: "read",
	}
	passphrase, err := promptClient.Prompt(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if passphrase != prompter.response {
		t.Fatalf("passphrase = %q, want broker response", passphrase)
	}
	prompter.mu.Lock()
	defer prompter.mu.Unlock()
	if len(prompter.requests) != 1 || prompter.requests[0] != request {
		t.Fatalf("requests = %#v, want %#v", prompter.requests, request)
	}
}

func TestFSKitPassphraseBrokerPreservesCancellation(t *testing.T) {
	vault := newBrokerTestVault(t)
	runtimeDirectory := newBrokerTestRuntimeDirectory(t)
	prompter := &brokerTestPrompter{err: ErrPromptCancelled}
	broker, err := startFSKitPassphraseBrokerIn(
		vault,
		prompter,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	promptClient, err := newFSKitPassphrasePrompterIn(
		vault,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := promptClient.Prompt(
		t.Context(),
		PromptRequest{Path: "/project/.env", Operation: "read"},
	); !errors.Is(err, ErrPromptCancelled) {
		t.Fatalf("Prompt error = %v, want ErrPromptCancelled", err)
	}
}

func TestFSKitPassphraseBrokerCloseCancelsActivePrompt(t *testing.T) {
	vault := newBrokerTestVault(t)
	runtimeDirectory := newBrokerTestRuntimeDirectory(t)
	prompter := &blockingBrokerTestPrompter{started: make(chan struct{})}
	broker, err := startFSKitPassphraseBrokerIn(
		vault,
		prompter,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	promptClient, err := newFSKitPassphrasePrompterIn(
		vault,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		_ = broker.Close()
		t.Fatal(err)
	}
	promptDone := make(chan error, 1)
	go func() {
		_, promptErr := promptClient.Prompt(
			t.Context(),
			PromptRequest{Path: "/project/.env", Operation: "read"},
		)
		promptDone <- promptErr
	}()
	select {
	case <-prompter.started:
	case <-time.After(5 * time.Second):
		_ = broker.Close()
		t.Fatal("passphrase prompt did not start")
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-promptDone:
		if err == nil {
			t.Fatal("active prompt succeeded while the broker was closing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active prompt did not stop with the broker")
	}
}

func TestFSKitPassphraseBrokerUnlocksVolumeUsingVisibleAlias(t *testing.T) {
	const passphrase = "FSKit broker recovery passphrase"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	runtimeDirectory := newBrokerTestRuntimeDirectory(t)
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	storage, err := objectStoragePath(objectID)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("TOKEN=broker-value\n")
	createTestFile(t, volume, storage, plaintext)
	alias := filepath.Join(t.TempDir(), ".env")
	if err := volume.setLinkSource(storage, alias); err != nil {
		t.Fatal(err)
	}
	alias, err = ResolvePathEntry(alias)
	if err != nil {
		t.Fatal(err)
	}

	prompter := &brokerTestPrompter{response: passphrase}
	broker, err := startFSKitPassphraseBrokerIn(
		volume.root,
		prompter,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	promptClient, err := newFSKitPassphrasePrompterIn(
		volume.root,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := LoadVolume(volume.root, promptClient, 1024*1024, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := reader.openFile(t.Context(), storage, syscall.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	if got := readOpenFile(t, handle); !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
	if errno := handle.Close(t.Context()); errno != 0 {
		t.Fatal(errno)
	}
	prompter.mu.Lock()
	defer prompter.mu.Unlock()
	if len(prompter.requests) != 1 || prompter.requests[0].Path != alias {
		t.Fatalf("prompt requests = %#v, want visible alias %q", prompter.requests, alias)
	}
}

func TestFSKitPassphraseBrokerRejectsUntrustedClient(t *testing.T) {
	vault := newBrokerTestVault(t)
	runtimeDirectory := newBrokerTestRuntimeDirectory(t)
	prompter := &brokerTestPrompter{response: "must-not-be-returned"}
	reject := func(*net.UnixConn, string) error {
		return errors.New("untrusted test client")
	}
	broker, err := startFSKitPassphraseBrokerIn(
		vault,
		prompter,
		reject,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	promptClient, err := newFSKitPassphrasePrompterIn(
		vault,
		allowAuthorizationPeer,
		runtimeDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := promptClient.Prompt(
		t.Context(),
		PromptRequest{Path: "/project/.env", Operation: "read"},
	); err == nil {
		t.Fatal("Prompt accepted an untrusted broker client")
	}
	prompter.mu.Lock()
	defer prompter.mu.Unlock()
	if len(prompter.requests) != 0 {
		t.Fatalf("untrusted client triggered %d prompts", len(prompter.requests))
	}
}
