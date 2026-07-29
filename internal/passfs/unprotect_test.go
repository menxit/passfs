package passfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type unprotectFixture struct {
	volume     *Volume
	prompter   *recordingPrompter
	sourcePath string
	storage    string
	cipherPath string
	plaintext  []byte
}

func newUnprotectFixture(
	t *testing.T,
	name string,
	registered bool,
) unprotectFixture {
	t.Helper()
	const passphrase = "unprotect test password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	prompter := &recordingPrompter{fallback: passphrase}
	volume.prompter = prompter

	projectDirectory := t.TempDir()
	sourcePath := filepath.Join(projectDirectory, name)
	storage := testStoragePath(t, sourcePath)
	plaintext := []byte("TOKEN=unprotected\n")
	createTestFile(t, volume, storage, plaintext)
	cipherPath, err := volume.encryptedPath(storage)
	if err != nil {
		t.Fatal(err)
	}
	if registered {
		targetPath, err := MountedPath(t.TempDir(), sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureProtectedLink(sourcePath, targetPath); err != nil {
			t.Fatal(err)
		}
		if err := volume.setLinkTarget(storage, targetPath); err != nil {
			t.Fatal(err)
		}
	}
	return unprotectFixture{
		volume:     volume,
		prompter:   prompter,
		sourcePath: sourcePath,
		storage:    storage,
		cipherPath: cipherPath,
		plaintext:  plaintext,
	}
}

func TestUnprotectAllReplacesLinkAndDeletesCiphertext(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	promptsBefore := fixture.prompter.requestCount()

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if len(report.Failed) != 0 || len(report.Warnings) != 0 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if len(report.Unprotected) != 1 ||
		report.Unprotected[0] != fixture.sourcePath {
		t.Fatalf("unprotected paths = %#v", report.Unprotected)
	}
	info, err := os.Lstat(fixture.sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("source mode = %v, want regular file", info.Mode())
	}
	if data, err := os.ReadFile(fixture.sourcePath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, fixture.plaintext) {
		t.Fatalf("plaintext = %q, want %q", data, fixture.plaintext)
	}
	if _, err := os.Stat(fixture.cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext remains: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(fixture.cipherPath)); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("empty encrypted directory remains: %v", err)
	}
	if records := fixture.volume.linkRecords(); len(records) != 0 {
		t.Fatalf("metadata records remain: %#v", records)
	}
	if got := fixture.prompter.requestCount() - promptsBefore; got != 1 {
		t.Fatalf("batch authorization prompts = %d, want 1", got)
	}
}

func TestUnprotectAllAuthenticationFailureChangesNothing(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	fixture.volume.prompter = &recordingPrompter{fallback: "wrong password"}

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if !errors.Is(report.Err, ErrAuthentication) {
		t.Fatalf("unprotect error = %v, want ErrAuthentication", report.Err)
	}
	info, err := os.Lstat(fixture.sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("protected link was replaced after failed authentication: %v", info.Mode())
	}
	if _, err := os.Stat(fixture.cipherPath); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
}

func TestUnprotectAllEmptyVolumeDoesNotAuthorize(t *testing.T) {
	volume, _ := initializeTestVolume(t, "empty volume password", 1024*1024)
	prompter := &recordingPrompter{fallback: "empty volume password"}
	volume.prompter = prompter

	report := volume.UnprotectAll(t.Context(), nil)
	if report.Err != nil || len(report.Unprotected) != 0 ||
		len(report.Failed) != 0 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if got := prompter.requestCount(); got != 0 {
		t.Fatalf("empty volume authorization prompts = %d, want 0", got)
	}
}

func TestUnprotectAllAuthorizesOnceForMultipleFiles(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	secondSource := filepath.Join(filepath.Dir(fixture.sourcePath), "config.json")
	secondStorage := testStoragePath(t, secondSource)
	secondPlaintext := []byte(`{"token":"second"}`)
	createTestFile(t, fixture.volume, secondStorage, secondPlaintext)
	secondTarget, err := MountedPath(t.TempDir(), secondSource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(secondSource, secondTarget); err != nil {
		t.Fatal(err)
	}
	if err := fixture.volume.setLinkTarget(secondStorage, secondTarget); err != nil {
		t.Fatal(err)
	}
	promptsBefore := fixture.prompter.requestCount()

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if len(report.Unprotected) != 2 || len(report.Failed) != 0 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if got := fixture.prompter.requestCount() - promptsBefore; got != 1 {
		t.Fatalf("batch authorization prompts = %d, want 1", got)
	}
}

func TestUnprotectAllPreservesCiphertextOnPlaintextConflict(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	if err := os.Remove(fixture.sourcePath); err != nil {
		t.Fatal(err)
	}
	conflicting := []byte("TOKEN=different\n")
	if err := os.WriteFile(fixture.sourcePath, conflicting, 0o600); err != nil {
		t.Fatal(err)
	}

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if len(report.Unprotected) != 0 || len(report.Failed) != 1 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if data, err := os.ReadFile(fixture.sourcePath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, conflicting) {
		t.Fatalf("conflicting plaintext was changed: %q", data)
	}
	if _, err := os.Stat(fixture.cipherPath); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
}

func TestUnprotectAllContinuesAfterPlaintextConflict(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	if err := os.Remove(fixture.sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		fixture.sourcePath,
		[]byte("TOKEN=different\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	secondSource := filepath.Join(filepath.Dir(fixture.sourcePath), "config.json")
	secondStorage := testStoragePath(t, secondSource)
	secondPlaintext := []byte(`{"token":"second"}`)
	createTestFile(t, fixture.volume, secondStorage, secondPlaintext)
	secondCipherPath, err := fixture.volume.encryptedPath(secondStorage)
	if err != nil {
		t.Fatal(err)
	}
	secondTarget, err := MountedPath(t.TempDir(), secondSource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(secondSource, secondTarget); err != nil {
		t.Fatal(err)
	}
	if err := fixture.volume.setLinkTarget(secondStorage, secondTarget); err != nil {
		t.Fatal(err)
	}

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if len(report.Unprotected) != 1 ||
		report.Unprotected[0] != secondSource ||
		len(report.Failed) != 1 ||
		report.Failed[0].Path != fixture.sourcePath {
		t.Fatalf("unprotect report = %#v", report)
	}
	if data, err := os.ReadFile(secondSource); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, secondPlaintext) {
		t.Fatalf("second plaintext = %q, want %q", data, secondPlaintext)
	}
	if _, err := os.Stat(secondCipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second ciphertext remains: %v", err)
	}
	if _, err := os.Stat(fixture.cipherPath); err != nil {
		t.Fatalf("conflicting ciphertext was not preserved: %v", err)
	}
}

func TestUnprotectAllResumesMatchingPlaintext(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	if err := os.Remove(fixture.sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.sourcePath, fixture.plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if len(report.Unprotected) != 1 || len(report.Failed) != 0 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if _, err := os.Stat(fixture.cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext remains after resumed operation: %v", err)
	}
}

func TestUnprotectAllMaterializesUnregisteredFileAtMissingPath(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env.swp", false)
	if _, err := os.Lstat(fixture.sourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source unexpectedly exists: %v", err)
	}

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if len(report.Unprotected) != 1 || len(report.Failed) != 0 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if data, err := os.ReadFile(fixture.sourcePath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, fixture.plaintext) {
		t.Fatalf("plaintext = %q, want %q", data, fixture.plaintext)
	}
}

func TestUnprotectAllDoesNotRestoreMissingRegisteredLink(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	if err := os.Remove(fixture.sourcePath); err != nil {
		t.Fatal(err)
	}

	report := fixture.volume.UnprotectAll(t.Context(), nil)
	if len(report.Unprotected) != 0 || len(report.Failed) != 1 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if _, err := os.Lstat(fixture.sourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source was recreated: %v", err)
	}
	if _, err := os.Stat(fixture.cipherPath); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
}

func TestUnprotectAllRefusesInternalDestination(t *testing.T) {
	fixture := newUnprotectFixture(t, ".env", true)
	forbidden := []string{filepath.Dir(fixture.sourcePath)}

	report := fixture.volume.UnprotectAll(t.Context(), forbidden)
	if len(report.Unprotected) != 0 || len(report.Failed) != 1 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if _, err := os.Stat(fixture.cipherPath); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
}
