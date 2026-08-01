package passfs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func addLinkedTestFile(
	t *testing.T,
	volume *Volume,
	mountPoint string,
	sourcePath string,
	data []byte,
) string {
	t.Helper()
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	storage, _ := objectStoragePath(objectID)
	createTestFile(t, volume, storage, data)
	target, err := mountedObjectPath(mountPoint, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(sourcePath, target); err != nil {
		t.Fatal(err)
	}
	if err := volume.setLinkSource(storage, sourcePath); err != nil {
		t.Fatal(err)
	}
	return storage
}

func TestUnprotectAllReplacesLinksAndDeletesObjects(t *testing.T) {
	volume, sourcePath, storage, _ := initializeLinkedTestFile(t)
	report := volume.UnprotectAll(context.Background(), nil)
	if report.Err != nil || len(report.Failed) != 0 ||
		len(report.Unprotected) != 1 || report.Unprotected[0] != sourcePath {
		t.Fatalf("unprotect report = %#v", report)
	}
	info, err := os.Lstat(sourcePath)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("plaintext destination: %v, %#v", err, info)
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(data, []byte("TOKEN=encrypted\n")) {
		t.Fatalf("plaintext = %q, %v", data, err)
	}
	cipherPath, _ := volume.encryptedPath(storage)
	if _, err := os.Lstat(cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext after unprotect: %v", err)
	}
}

func TestUnprotectFileOnlyMaterializesRequestedObject(t *testing.T) {
	volume, firstSource, _, mountPoint := initializeLinkedTestFile(t)
	secondSource := filepath.Join(filepath.Dir(firstSource), "config.json")
	secondStorage := addLinkedTestFile(
		t,
		volume,
		mountPoint,
		secondSource,
		[]byte("{\"token\":\"second\"}\n"),
	)
	report := volume.UnprotectFile(context.Background(), secondSource, nil)
	if report.Err != nil || len(report.Failed) != 0 ||
		len(report.Unprotected) != 1 || report.Unprotected[0] != secondSource {
		t.Fatalf("unprotect report = %#v", report)
	}
	if info, err := os.Lstat(firstSource); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("first link changed: %v, %#v", err, info)
	}
	if info, err := os.Lstat(secondSource); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("second plaintext: %v, %#v", err, info)
	}
	cipherPath, _ := volume.encryptedPath(secondStorage)
	if _, err := os.Lstat(cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second ciphertext remains: %v", err)
	}
}

func TestUnprotectAllAuthorizesOnce(t *testing.T) {
	const passphrase = "unprotect batch password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	prompter := &recordingPrompter{fallback: passphrase}
	volume.prompter = prompter
	mountPoint := t.TempDir()
	project := t.TempDir()
	addLinkedTestFile(t, volume, mountPoint, filepath.Join(project, ".env"), []byte("one\n"))
	addLinkedTestFile(t, volume, mountPoint, filepath.Join(project, "config.json"), []byte("two\n"))
	promptsBefore := prompter.requestCount()
	report := volume.UnprotectAll(context.Background(), nil)
	if report.Err != nil || len(report.Failed) != 0 || len(report.Unprotected) != 2 {
		t.Fatalf("unprotect report = %#v", report)
	}
	if got := prompter.requestCount(); got != promptsBefore+1 {
		t.Fatalf("authorization prompts = %d, want %d", got, promptsBefore+1)
	}
}

func TestUnprotectPreservesCiphertextOnPlaintextConflict(t *testing.T) {
	volume, sourcePath, storage, _ := initializeLinkedTestFile(t)
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("different\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := volume.UnprotectFile(context.Background(), sourcePath, nil)
	if len(report.Failed) != 1 || len(report.Unprotected) != 0 {
		t.Fatalf("unprotect report = %#v", report)
	}
	cipherPath, _ := volume.encryptedPath(storage)
	if _, err := os.Lstat(cipherPath); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(data, []byte("different\n")) {
		t.Fatalf("conflicting plaintext changed: %q, %v", data, err)
	}
}

func TestUnprotectResumesMatchingMaterializedPlaintext(t *testing.T) {
	volume, sourcePath, storage, _ := initializeLinkedTestFile(t)
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("TOKEN=encrypted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := volume.UnprotectFile(context.Background(), sourcePath, nil)
	if report.Err != nil || len(report.Failed) != 0 || len(report.Unprotected) != 1 {
		t.Fatalf("unprotect report = %#v", report)
	}
	cipherPath, _ := volume.encryptedPath(storage)
	if _, err := os.Lstat(cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("matching materialized ciphertext remains: %v", err)
	}
}

func TestUnprotectRejectsInternalDestination(t *testing.T) {
	volume, sourcePath, storage, _ := initializeLinkedTestFile(t)
	report := volume.UnprotectFile(
		context.Background(),
		sourcePath,
		[]string{filepath.Dir(sourcePath)},
	)
	if len(report.Failed) != 1 || len(report.Unprotected) != 0 {
		t.Fatalf("unprotect report = %#v", report)
	}
	cipherPath, _ := volume.encryptedPath(storage)
	if _, err := os.Lstat(cipherPath); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
}
