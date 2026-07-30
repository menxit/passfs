package passfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func synchronizeLinksOnce(volume *Volume, mountPoint string) map[string]error {
	return synchronizeLinksOnceTracked(volume, mountPoint, nil)
}

func testStoragePath(t *testing.T, absolutePath string) string {
	t.Helper()
	if !filepath.IsAbs(absolutePath) {
		t.Fatalf("test path %q is not absolute", absolutePath)
	}
	relative := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(absolutePath)), "/")
	return filepath.Join("files", filepath.FromSlash(relative))
}

func initializeLinkedTestFile(
	t *testing.T,
) (volume *Volume, sourcePath, storagePath, mountPoint string) {
	t.Helper()
	volume, _ = initializeTestVolume(t, "link synchronization password", 1024*1024)
	projectDirectory := t.TempDir()
	sourcePath = filepath.Join(projectDirectory, ".env")
	storagePath = testStoragePath(t, sourcePath)
	mountPoint = t.TempDir()
	createTestFile(t, volume, storagePath, []byte("TOKEN=encrypted\n"))
	targetPath, err := MountedPath(mountPoint, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(sourcePath, targetPath); err != nil {
		t.Fatal(err)
	}
	if err := volume.setLinkTarget(storagePath, targetPath); err != nil {
		t.Fatal(err)
	}
	return volume, sourcePath, storagePath, mountPoint
}

func assertNoLinkSyncIssues(t *testing.T, issues map[string]error) {
	t.Helper()
	if len(issues) != 0 {
		t.Fatalf("link synchronization issues: %v", issues)
	}
}

func TestLinkSynchronizerDoesNotPublishUnregisteredMountedFile(t *testing.T) {
	volume, _ := initializeTestVolume(t, "unregistered file password", 1024*1024)
	projectDirectory := t.TempDir()
	sourcePath := filepath.Join(projectDirectory, ".env.swp")
	storagePath := testStoragePath(t, sourcePath)
	mountPoint := t.TempDir()
	createTestFile(t, volume, storagePath, nil)
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))

	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if link.exists {
		t.Fatalf("unregistered mounted file was published: %#v", link)
	}
	records := volume.linkRecords()
	if len(records) != 1 ||
		records[0].relative != storagePath ||
		records[0].linkTarget != "" {
		t.Fatalf("link records = %#v", records)
	}
}

func TestDeletingProtectedLinkDeletesEncryptedFile(t *testing.T) {
	volume, sourcePath, storagePath, mountPoint := initializeLinkedTestFile(t)
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))

	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))

	cipherPath, err := volume.encryptedPath(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("encrypted file still exists or returned an unexpected error: %v", err)
	}
	if records := volume.linkRecords(); len(records) != 0 {
		t.Fatalf("link records remain after deletion: %#v", records)
	}
}

func TestMissingLinkAtReloadPreservesCiphertext(t *testing.T) {
	volume, sourcePath, storagePath, mountPoint := initializeLinkedTestFile(t)
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadVolume(
		volume.root,
		&recordingPrompter{fallback: "link synchronization password"},
		1024*1024,
		0,
	)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	synchronizer, err := NewLinkSynchronizer(reloaded, mountPoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	synchronizer.Synchronize()
	defer synchronizer.Close()
	cipherPath, err := reloaded.encryptedPath(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cipherPath); err != nil {
		t.Fatalf("reloaded volume did not preserve the ciphertext: %v", err)
	}
	records := reloaded.linkRecords()
	if len(records) != 1 || !records[0].protected {
		t.Fatalf("preserved link records = %#v", records)
	}
}

func TestReloadReconcilesCiphertextRemovedOutsidePassfs(t *testing.T) {
	volume, sourcePath, storagePath, mountPoint := initializeLinkedTestFile(t)
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))
	cipherPath, err := volume.encryptedPath(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cipherPath); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadVolume(
		volume.root,
		&recordingPrompter{fallback: "link synchronization password"},
		1024*1024,
		0,
	)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(reloaded, mountPoint))
	if _, err := os.Lstat(sourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling protected link remains: %v", err)
	}
	if records := reloaded.linkRecords(); len(records) != 0 {
		t.Fatalf("stale records remain: %#v", records)
	}
}

func TestReloadRecoversCiphertextMissingFromMetadata(t *testing.T) {
	volume, sourcePath, storagePath, mountPoint := initializeLinkedTestFile(t)
	volume.metadataMu.Lock()
	delete(volume.metadata.Files, metadataKey(storagePath))
	if err := saveMetadata(volume.root, volume.metadata); err != nil {
		volume.metadataMu.Unlock()
		t.Fatal(err)
	}
	volume.metadataMu.Unlock()

	reloaded, err := LoadVolume(
		volume.root,
		&recordingPrompter{fallback: "link synchronization password"},
		1024*1024,
		0,
	)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(reloaded, mountPoint))
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !link.isSymlink {
		t.Fatal("registered link disappeared while metadata was reconciled")
	}
	records := reloaded.linkRecords()
	if len(records) != 1 || !records[0].protected {
		t.Fatalf("reconciled records = %#v", records)
	}
}

func TestReplacingProtectedLinkPreservesEncryptedFile(t *testing.T) {
	volume, sourcePath, storagePath, mountPoint := initializeLinkedTestFile(t)
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("TOKEN=accidental-plaintext\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	issues := synchronizeLinksOnce(volume, mountPoint)
	if len(issues) != 1 {
		t.Fatalf("link synchronization issues = %v, want one conflict", issues)
	}
	cipherPath, err := volume.encryptedPath(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cipherPath); err != nil {
		t.Fatalf("encrypted file was not preserved: %v", err)
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "TOKEN=accidental-plaintext\n"; got != want {
		t.Fatalf("replacement file = %q, want %q", got, want)
	}
}

func TestRemovingEncryptedFileRemovesItsLink(t *testing.T) {
	volume, sourcePath, storagePath, mountPoint := initializeLinkedTestFile(t)
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))
	if err := volume.removeProtectedFile(storagePath); err != nil {
		t.Fatalf("removeProtectedFile: %v", err)
	}

	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))
	if _, err := os.Lstat(sourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("project-side link still exists or returned an unexpected error: %v", err)
	}
}

func TestChangingMountPointUpdatesOwnedLink(t *testing.T) {
	volume, sourcePath, _, firstMountPoint := initializeLinkedTestFile(t)
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, firstMountPoint))

	secondMountPoint := t.TempDir()
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, secondMountPoint))
	secondTarget, err := MountedPath(secondMountPoint, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !link.isSymlink || link.target != secondTarget {
		t.Fatalf("updated link = %#v, want target %q", link, secondTarget)
	}
}

func TestBackgroundLinkSynchronizerAppliesDeletion(t *testing.T) {
	volume, sourcePath, storagePath, mountPoint := initializeLinkedTestFile(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	synchronizer, err := NewLinkSynchronizer(volume, mountPoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	synchronizer.Synchronize()
	go func() {
		defer close(done)
		synchronizer.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitForTestCondition(t, 3*time.Second, func() bool {
		link, err := inspectProtectedLink(sourcePath)
		return err == nil && link.isSymlink
	})
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	cipherPath, err := volume.encryptedPath(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	waitForTestCondition(t, 3*time.Second, func() bool {
		_, err := os.Lstat(cipherPath)
		return errors.Is(err, os.ErrNotExist)
	})
}

func waitForTestCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
