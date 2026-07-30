package passfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"passfs/internal/fsapi"
)

type recordingPrompter struct {
	mu        sync.Mutex
	responses []string
	fallback  string
	requests  []PromptRequest
	err       error
}

func (p *recordingPrompter) Prompt(
	ctx context.Context,
	request PromptRequest,
) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, request)
	if p.err != nil {
		return "", p.err
	}
	if len(p.responses) > 0 {
		response := p.responses[0]
		p.responses = p.responses[1:]
		return response, nil
	}
	return p.fallback, nil
}

func (p *recordingPrompter) requestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.requests)
}

type recordingIdentityPrompter struct {
	mu               sync.Mutex
	identity         *age.X25519Identity
	identityRequests []PromptRequest
	passwordRequests []PromptRequest
}

func (p *recordingIdentityPrompter) Prompt(
	_ context.Context,
	request PromptRequest,
) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passwordRequests = append(p.passwordRequests, request)
	return "", errors.New("unexpected passphrase prompt")
}

func (p *recordingIdentityPrompter) PromptIdentity(
	_ context.Context,
	request PromptRequest,
) (*age.X25519Identity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identityRequests = append(p.identityRequests, request)
	return p.identity, nil
}

func (p *recordingIdentityPrompter) counts() (identity, password int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.identityRequests), len(p.passwordRequests)
}

func initializeTestVolume(t *testing.T, passphrase string, maxFileSize int64) (*Volume, *recordingPrompter) {
	t.Helper()
	root := t.TempDir()
	initPrompter := &recordingPrompter{responses: []string{passphrase, passphrase}}
	if err := InitVolume(context.Background(), root, initPrompter); err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	if initPrompter.requestCount() != 2 {
		t.Fatalf("initialization prompts = %d, want 2", initPrompter.requestCount())
	}

	prompter := &recordingPrompter{fallback: passphrase}
	volume, err := LoadVolume(root, prompter, maxFileSize, 0)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	return volume, prompter
}

func TestInitVolumeIdentityHookUsesGeneratedIdentity(t *testing.T) {
	const passphrase = "identity hook password"
	prompter := &recordingPrompter{
		responses: []string{passphrase, passphrase},
	}
	var called bool
	err := initVolume(
		context.Background(),
		t.TempDir(),
		prompter,
		func(public PublicConfig, identity *age.X25519Identity) error {
			called = true
			if identity.Recipient().String() != public.Recipient {
				return errors.New("identity recipient mismatch")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initVolume: %v", err)
	}
	if !called {
		t.Fatal("identity hook was not called")
	}
	if got := prompter.requestCount(); got != 2 {
		t.Fatalf("passphrase prompts = %d, want 2", got)
	}
}

func TestInitVolumeOptionalIdentityFailureKeepsRecoveryVolume(t *testing.T) {
	const passphrase = "optional identity recovery password"
	hookErr := errors.New("optional identity store unavailable")
	root := t.TempDir()
	prompter := &recordingPrompter{
		responses: []string{passphrase, passphrase},
	}

	configured, warning, err := initVolumeWithOptionalIdentity(
		context.Background(),
		root,
		prompter,
		func(PublicConfig, *age.X25519Identity) error {
			return hookErr
		},
	)
	if err != nil {
		t.Fatalf("initVolumeWithOptionalIdentity: %v", err)
	}
	if configured {
		t.Fatal("optional identity reported as configured")
	}
	if !errors.Is(warning, hookErr) {
		t.Fatalf("warning = %v, want %v", warning, hookErr)
	}

	public, err := loadPublicConfig(root)
	if err != nil {
		t.Fatalf("load recovery public config: %v", err)
	}
	privateData, err := unlockPrivateConfig(
		context.Background(),
		root,
		public,
		&recordingPrompter{fallback: passphrase},
		PromptRequest{Operation: "test recovery"},
	)
	if err != nil {
		t.Fatalf("unlock passphrase recovery identity: %v", err)
	}
	defer wipe(privateData)
	identity, err := parsePrivateIdentity(privateData)
	if err != nil {
		t.Fatalf("parse recovery identity: %v", err)
	}
	if identity.Recipient().String() != public.Recipient {
		t.Fatal("recovery identity does not match the public recipient")
	}
}

func TestInitVolumeOptionalIdentitySuccessIsConfigured(t *testing.T) {
	const passphrase = "optional identity success password"
	prompter := &recordingPrompter{
		responses: []string{passphrase, passphrase},
	}

	configured, warning, err := initVolumeWithOptionalIdentity(
		context.Background(),
		t.TempDir(),
		prompter,
		func(PublicConfig, *age.X25519Identity) error {
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initVolumeWithOptionalIdentity: %v", err)
	}
	if !configured || warning != nil {
		t.Fatalf("configured = %t, warning = %v", configured, warning)
	}
}

func createTestFile(t *testing.T, volume *Volume, relative string, plaintext []byte) {
	t.Helper()
	createTestFileWithContext(
		t,
		context.Background(),
		volume,
		relative,
		plaintext,
	)
}

func createTestFileWithContext(
	t *testing.T,
	ctx context.Context,
	volume *Volume,
	relative string,
	plaintext []byte,
) {
	t.Helper()
	handle, err := volume.createFile(
		ctx,
		relative,
		syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR,
		0o600,
	)
	if err != nil {
		t.Fatalf("createFile: %v", err)
	}
	if written, errno := handle.Write(ctx, plaintext, 0); errno != 0 {
		t.Fatalf("Write: %v", errno)
	} else if written != len(plaintext) {
		t.Fatalf("Write = %d, want %d", written, len(plaintext))
	}
	if errno := handle.Flush(ctx); errno != 0 {
		t.Fatalf("Flush: %v", errno)
	}
	if errno := handle.Close(ctx); errno != 0 {
		t.Fatalf("Release: %v", errno)
	}
}

func readOpenFile(t *testing.T, handle *OpenFile) []byte {
	t.Helper()
	buffer := make([]byte, 4096)
	count, errno := handle.Read(context.Background(), buffer, 0)
	if errno != 0 {
		t.Fatalf("Read: %v", errno)
	}
	return append([]byte(nil), buffer[:count]...)
}

func TestEncryptedFileRoundTripPromptsOnEveryOpen(t *testing.T) {
	const passphrase = "correct horse battery staple"
	volume, prompter := initializeTestVolume(t, passphrase, 1024*1024)
	plaintext := []byte("SECRET_TOKEN=not-on-disk\n")

	createTestFile(t, volume, "file.md", plaintext)
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("prompts after create = %d, want 1", got)
	}

	plainPath := filepath.Join(volume.root, "file.md")
	if _, err := os.Stat(plainPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext path exists or returned unexpected error: %v", err)
	}
	cipherPath := filepath.Join(volume.root, "file.md.age")
	ciphertext, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if bytes.Contains(ciphertext, plaintext) || bytes.Contains(ciphertext, []byte("SECRET_TOKEN")) {
		t.Fatal("ciphertext contains plaintext")
	}

	for openNumber := 0; openNumber < 2; openNumber++ {
		handle, err := volume.openFile(context.Background(), "file.md", syscall.O_RDONLY)
		if err != nil {
			t.Fatalf("openFile %d: %v", openNumber+1, err)
		}
		if got := readOpenFile(t, handle); !bytes.Equal(got, plaintext) {
			t.Fatalf("read %q, want %q", got, plaintext)
		}
		if errno := handle.Close(context.Background()); errno != 0 {
			t.Fatalf("Release: %v", errno)
		}
	}
	if got := prompter.requestCount(); got != 3 {
		t.Fatalf("total prompts = %d, want 3 (create plus two opens)", got)
	}
	if request := prompter.requests[len(prompter.requests)-1]; request.Path != "/file.md" || request.Operation != "read" {
		t.Fatalf("last prompt = %#v", request)
	}

	meta := volume.fileMeta("file.md", nil)
	if meta.Size != uint64(len(plaintext)) {
		t.Fatalf("metadata size = %d, want %d", meta.Size, len(plaintext))
	}
}

func TestWrongPassphraseCannotOpenFile(t *testing.T) {
	volume, _ := initializeTestVolume(t, "right password", 1024*1024)
	createTestFile(t, volume, "secret.env", []byte("PASSWORD=hunter2\n"))

	wrongPrompter := &recordingPrompter{fallback: "wrong password"}
	lockedVolume, err := LoadVolume(volume.root, wrongPrompter, 1024*1024, 0)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	handle, err := lockedVolume.openFile(context.Background(), "secret.env", syscall.O_RDONLY)
	if handle != nil {
		_ = handle.Close(context.Background())
		t.Fatal("openFile returned a handle with the wrong passphrase")
	}
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("openFile error = %v, want ErrAuthentication", err)
	}
	if wrongPrompter.requestCount() != 1 {
		t.Fatalf("wrong passphrase prompts = %d, want 1", wrongPrompter.requestCount())
	}
}

func TestIdentityPrompterUnlocksWithoutRequestingPassphrase(t *testing.T) {
	const passphrase = "Touch ID recovery passphrase"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	plaintext := []byte("TOKEN=biometric\n")
	createTestFile(t, volume, "touchid.env", plaintext)

	public, err := loadPublicConfig(volume.root)
	if err != nil {
		t.Fatalf("loadPublicConfig: %v", err)
	}
	privateData, err := unlockPrivateConfig(
		context.Background(),
		volume.root,
		public,
		&recordingPrompter{fallback: passphrase},
		PromptRequest{},
	)
	if err != nil {
		t.Fatalf("unlockPrivateConfig: %v", err)
	}
	defer wipe(privateData)
	identity, err := parsePrivateIdentity(privateData)
	if err != nil {
		t.Fatalf("parsePrivateIdentity: %v", err)
	}

	prompter := &recordingIdentityPrompter{identity: identity}
	touchIDVolume, err := LoadVolume(volume.root, prompter, 1024*1024, 0)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	for openNumber := 0; openNumber < 2; openNumber++ {
		handle, err := touchIDVolume.openFile(
			context.Background(),
			"touchid.env",
			syscall.O_RDONLY,
		)
		if err != nil {
			t.Fatalf("openFile %d: %v", openNumber+1, err)
		}
		if got := readOpenFile(t, handle); !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext = %q, want %q", got, plaintext)
		}
		_ = handle.Close(context.Background())
	}
	identityPrompts, passwordPrompts := prompter.counts()
	if identityPrompts != 2 || passwordPrompts != 0 {
		t.Fatalf(
			"identity prompts = %d, password prompts = %d; want 2, 0",
			identityPrompts,
			passwordPrompts,
		)
	}
}

func TestUnlockWindowReusesIdentityOnlyInMemory(t *testing.T) {
	const passphrase = "cached password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	createTestFile(t, volume, "cached.env", []byte("TOKEN=value\n"))
	createTestFile(t, volume, "other.env", []byte("OTHER=value\n"))

	prompter := &recordingPrompter{fallback: passphrase}
	cachedVolume, err := LoadVolume(volume.root, prompter, 1024*1024, 5*time.Minute)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	for openNumber := 0; openNumber < 2; openNumber++ {
		handle, err := cachedVolume.openFile(context.Background(), "cached.env", syscall.O_RDONLY)
		if err != nil {
			t.Fatalf("openFile %d: %v", openNumber+1, err)
		}
		_ = handle.Close(context.Background())
	}
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("prompts within unlock window = %d, want 1", got)
	}
	otherHandle, err := cachedVolume.openFile(context.Background(), "other.env", syscall.O_RDONLY)
	if err != nil {
		t.Fatalf("open other file: %v", err)
	}
	_ = otherHandle.Close(context.Background())
	if got := prompter.requestCount(); got != 2 {
		t.Fatalf("prompts for a different path = %d, want 2", got)
	}

	cachedVolume.Lock()
	handle, err := cachedVolume.openFile(context.Background(), "cached.env", syscall.O_RDONLY)
	if err != nil {
		t.Fatalf("openFile after Lock: %v", err)
	}
	_ = handle.Close(context.Background())
	if got := prompter.requestCount(); got != 3 {
		t.Fatalf("prompts after Lock = %d, want 3", got)
	}
}

func TestEditSessionUsesOneAuthorizationUntilItEnds(t *testing.T) {
	const passphrase = "edit session password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	createTestFile(t, volume, "editable.env", []byte("TOKEN=value\n"))

	prompter := &recordingPrompter{fallback: passphrase}
	editingVolume, err := LoadVolume(volume.root, prompter, 1024*1024, 0)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	const sessionID = "0123456789abcdef0123456789abcdef"
	pid := uint32(os.Getpid())
	if err := editingVolume.beginEditSession(
		context.Background(),
		"editable.env",
		sessionID,
		pid,
	); err != nil {
		t.Fatalf("beginEditSession: %v", err)
	}
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("begin session prompts = %d, want 1", got)
	}

	for index := 0; index < 3; index++ {
		handle, err := editingVolume.openFile(
			context.Background(),
			"editable.env",
			syscall.O_RDWR,
		)
		if err != nil {
			t.Fatalf("open during edit session: %v", err)
		}
		if errno := handle.Close(context.Background()); errno != 0 {
			t.Fatal(errno)
		}
	}
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("prompts during edit session = %d, want 1", got)
	}
	if err := editingVolume.endEditSession("editable.env", sessionID, pid); err != nil {
		t.Fatalf("endEditSession: %v", err)
	}

	handle, err := editingVolume.openFile(
		context.Background(),
		"editable.env",
		syscall.O_RDONLY,
	)
	if err != nil {
		t.Fatalf("open after edit session: %v", err)
	}
	_ = handle.Close(context.Background())
	if got := prompter.requestCount(); got != 2 {
		t.Fatalf("prompts after edit session = %d, want 2", got)
	}
}

func TestEncryptSessionUsesOneAuthorizationAndIsScopedToOwnerPID(t *testing.T) {
	const passphrase = "encrypt session password"
	volume, prompter := initializeTestVolume(t, passphrase, 1024*1024)
	const sessionID = "0123456789abcdef0123456789abcdef"
	ownerPID := uint32(os.Getpid())
	ownerContext := fsapi.WithCaller(
		context.Background(),
		fsapi.Caller{PID: ownerPID},
	)

	if err := volume.beginEncryptSession(ownerContext, sessionID, ownerPID); err != nil {
		t.Fatalf("beginEncryptSession: %v", err)
	}
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("begin session prompts = %d, want 1", got)
	}

	createTestFileWithContext(t, ownerContext, volume, "first.env", []byte("A=1\n"))
	createTestFileWithContext(t, ownerContext, volume, "second.env", []byte("B=2\n"))
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("owner prompts during batch = %d, want 1", got)
	}

	otherContext := fsapi.WithCaller(
		context.Background(),
		fsapi.Caller{PID: ownerPID + 1_000_000},
	)
	createTestFileWithContext(t, otherContext, volume, "other.env", []byte("C=3\n"))
	if got := prompter.requestCount(); got != 2 {
		t.Fatalf("other process prompts = %d, want 2", got)
	}

	if err := volume.endEncryptSession(sessionID, ownerPID); err != nil {
		t.Fatalf("endEncryptSession: %v", err)
	}
	createTestFileWithContext(t, ownerContext, volume, "after.env", []byte("D=4\n"))
	if got := prompter.requestCount(); got != 3 {
		t.Fatalf("prompts after batch = %d, want 3", got)
	}
}

func TestConcurrentReadsShareOnlyTheInMemoryAuthorization(t *testing.T) {
	const passphrase = "concurrent read password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	plaintext := []byte("TOKEN=concurrent\n")
	createTestFile(t, volume, "concurrent.env", plaintext)

	prompter := &recordingPrompter{fallback: passphrase}
	cachedVolume, err := LoadVolume(volume.root, prompter, 1024*1024, time.Minute)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}

	const readers = 32
	start := make(chan struct{})
	results := make(chan error, readers)
	for index := 0; index < readers; index++ {
		go func() {
			<-start
			handle, err := cachedVolume.openFile(
				context.Background(),
				"concurrent.env",
				syscall.O_RDONLY,
			)
			if err != nil {
				results <- err
				return
			}
			buffer := make([]byte, len(plaintext)+16)
			count, errno := handle.Read(context.Background(), buffer, 0)
			if errno != 0 {
				_ = handle.Close(context.Background())
				results <- errno
				return
			}
			data := buffer[:count]
			if !bytes.Equal(data, plaintext) {
				_ = handle.Close(context.Background())
				results <- fmt.Errorf("plaintext = %q, want %q", data, plaintext)
				return
			}
			if errno := handle.Close(context.Background()); errno != 0 {
				results <- errno
				return
			}
			results <- nil
		}()
	}
	close(start)
	for index := 0; index < readers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent read: %v", err)
		}
	}
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("passphrase prompts = %d, want 1", got)
	}
}

func TestConcurrentWritesRemainWholeAndEncrypted(t *testing.T) {
	const passphrase = "concurrent write password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	createTestFile(t, volume, "concurrent.env", []byte("initial\n"))

	prompter := &recordingPrompter{fallback: passphrase}
	cachedVolume, err := LoadVolume(volume.root, prompter, 1024*1024, time.Minute)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}

	const writers = 16
	start := make(chan struct{})
	results := make(chan error, writers)
	expected := make(map[string]bool, writers)
	for index := 0; index < writers; index++ {
		value := fmt.Sprintf("TOKEN=writer-%02d\n", index)
		expected[value] = true
		go func(value string) {
			<-start
			handle, err := cachedVolume.openFile(
				context.Background(),
				"concurrent.env",
				syscall.O_WRONLY|syscall.O_TRUNC,
			)
			if err != nil {
				results <- err
				return
			}
			if _, errno := handle.Write(context.Background(), []byte(value), 0); errno != 0 {
				_ = handle.Close(context.Background())
				results <- errno
				return
			}
			if errno := handle.Flush(context.Background()); errno != 0 {
				_ = handle.Close(context.Background())
				results <- errno
				return
			}
			if errno := handle.Close(context.Background()); errno != 0 {
				results <- errno
				return
			}
			results <- nil
		}(value)
	}
	close(start)
	for index := 0; index < writers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}

	handle, err := cachedVolume.openFile(context.Background(), "concurrent.env", syscall.O_RDONLY)
	if err != nil {
		t.Fatalf("open final value: %v", err)
	}
	finalValue := string(readOpenFile(t, handle))
	_ = handle.Close(context.Background())
	if !expected[finalValue] {
		t.Fatalf("final value is partial or unexpected: %q", finalValue)
	}
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("passphrase prompts = %d, want 1", got)
	}

	ciphertext, err := os.ReadFile(filepath.Join(volume.root, "concurrent.env.age"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("TOKEN=writer-")) {
		t.Fatal("ciphertext contains a concurrent plaintext write")
	}
}

func TestReleasedHandlesDoNotLeakPathLocks(t *testing.T) {
	volume, _ := initializeTestVolume(t, "lock cleanup password", 1024*1024)
	createTestFile(t, volume, "cleanup.env", []byte("TOKEN=value\n"))
	volume.unlockFor = time.Minute
	defer volume.Lock()
	for index := 0; index < 50; index++ {
		handle, err := volume.openFile(context.Background(), "cleanup.env", syscall.O_RDONLY)
		if err != nil {
			t.Fatal(err)
		}
		if errno := handle.Close(context.Background()); errno != 0 {
			t.Fatal(errno)
		}
	}
	volume.locksMu.Lock()
	defer volume.locksMu.Unlock()
	if len(volume.locks) != 0 {
		t.Fatalf("released path locks remain cached: %d", len(volume.locks))
	}
}

func TestChangePassphrase(t *testing.T) {
	const oldPassphrase = "old password"
	const newPassphrase = "new password"
	volume, _ := initializeTestVolume(t, oldPassphrase, 1024*1024)
	createTestFile(t, volume, "config.json", []byte(`{"secret":"value"}`))

	changePrompter := &recordingPrompter{
		responses: []string{oldPassphrase, newPassphrase, newPassphrase},
	}
	if err := ChangePassphrase(context.Background(), volume.root, changePrompter); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	if got := changePrompter.requestCount(); got != 3 {
		t.Fatalf("change passphrase prompts = %d, want 3", got)
	}

	oldVolume, err := LoadVolume(volume.root, &recordingPrompter{fallback: oldPassphrase}, 1024*1024, 0)
	if err != nil {
		t.Fatalf("LoadVolume old: %v", err)
	}
	if handle, err := oldVolume.openFile(context.Background(), "config.json", syscall.O_RDONLY); !errors.Is(err, ErrAuthentication) {
		if handle != nil {
			_ = handle.Close(context.Background())
		}
		t.Fatalf("old passphrase error = %v, want ErrAuthentication", err)
	}

	newVolume, err := LoadVolume(volume.root, &recordingPrompter{fallback: newPassphrase}, 1024*1024, 0)
	if err != nil {
		t.Fatalf("LoadVolume new: %v", err)
	}
	handle, err := newVolume.openFile(context.Background(), "config.json", syscall.O_RDONLY)
	if err != nil {
		t.Fatalf("open with new passphrase: %v", err)
	}
	if got := string(readOpenFile(t, handle)); got != `{"secret":"value"}` {
		t.Fatalf("plaintext = %q", got)
	}
	_ = handle.Close(context.Background())
}

func TestWriteHonorsMaximumPlaintextSize(t *testing.T) {
	volume, _ := initializeTestVolume(t, "password", 4)
	handle, err := volume.createFile(
		context.Background(),
		"small.txt",
		syscall.O_CREAT|syscall.O_RDWR,
		0o600,
	)
	if err != nil {
		t.Fatalf("createFile: %v", err)
	}
	if _, errno := handle.Write(context.Background(), []byte("12345"), 0); errno != syscall.EFBIG {
		t.Fatalf("Write errno = %v, want EFBIG", errno)
	}
	_ = handle.Close(context.Background())
}

func TestPrivateIdentityIsEncrypted(t *testing.T) {
	volume, _ := initializeTestVolume(t, "password", 1024)
	data, err := os.ReadFile(filepath.Join(volume.root, internalDirName, identityFileName))
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if bytes.Contains(data, []byte("AGE-SECRET-KEY-")) {
		t.Fatal("identity file contains an unencrypted private key")
	}
}

func TestValidateRelativePath(t *testing.T) {
	for _, invalid := range []string{
		"../escape",
		filepath.Join("directory", "..", "..", "escape"),
		internalDirName + "/config.json",
		"file\x00name",
	} {
		if err := validateRelativePath(invalid); err == nil {
			t.Errorf("validateRelativePath(%q) succeeded", invalid)
		}
	}
	for _, valid := range []string{
		"file",
		"project/.env",
		".passfs-file",
		"files/.passfs/secret",
	} {
		if err := validateRelativePath(valid); err != nil {
			t.Errorf("validateRelativePath(%q): %v", valid, err)
		}
	}
}

func FuzzValidateRelativePathDoesNotEscapeVolume(f *testing.F) {
	for _, seed := range []string{
		"",
		".",
		"file",
		"directory/file",
		"../escape",
		"/absolute",
		"directory/../../escape",
		"file\x00name",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, relative string) {
		if validateRelativePath(relative) != nil {
			return
		}
		root := filepath.Join(string(os.PathSeparator), "passfs-fuzz-vault")
		joined := filepath.Join(root, filepath.Clean(relative))
		if !PathWithin(root, joined) {
			t.Fatalf("accepted path %q escapes volume as %q", relative, joined)
		}
	})
}
