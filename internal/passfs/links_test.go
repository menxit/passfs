package passfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testStoragePath remains available for v1 migration fixtures.
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
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectDirectory := filepath.Join(home, "project")
	if err := os.MkdirAll(projectDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	sourcePath = filepath.Join(projectDirectory, ".env")
	resolvedSource, err := ResolvePathEntry(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	sourcePath = resolvedSource
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	storagePath, _ = objectStoragePath(objectID)
	mountPoint = t.TempDir()
	createTestFile(t, volume, storagePath, []byte("TOKEN=encrypted\n"))
	targetPath, err := mountedObjectPath(mountPoint, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(sourcePath, targetPath); err != nil {
		t.Fatal(err)
	}
	if err := volume.setLinkSource(storagePath, sourcePath); err != nil {
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

func newGlobalTestSynchronizer(
	t *testing.T,
	volume *Volume,
	mountPoint string,
) *LinkSynchronizer {
	t.Helper()
	synchronizer, err := NewLinkSynchronizer(volume, mountPoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	synchronizer.EnableGlobalMoveSearch()
	if err := synchronizer.Prepare(); err != nil {
		synchronizer.Close()
		t.Fatal(err)
	}
	t.Cleanup(synchronizer.Close)
	return synchronizer
}

func TestOpaqueLinkRenameKeepsCiphertextAndTargetStable(t *testing.T) {
	volume, sourcePath, storage, mountPoint := initializeLinkedTestFile(t)
	synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
	target, err := os.Readlink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	cipherPath, err := volume.encryptedPath(storage)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(filepath.Dir(sourcePath), "renamed.env")
	if err := os.Rename(sourcePath, destination); err != nil {
		t.Fatal(err)
	}
	if retry := synchronizer.Synchronize(); retry {
		t.Fatal("rename reconciliation unexpectedly requested a retry")
	}
	afterTarget, err := os.Readlink(destination)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != afterTarget || !bytes.Equal(before, after) {
		t.Fatal("project rename changed immutable target or ciphertext")
	}
	records := volume.linkRecords()
	if len(records) != 1 || records[0].sourcePath != destination {
		t.Fatalf("records after rename = %#v", records)
	}
}

func TestOfflineParentMoveUpdatesOnlyLinkIndex(t *testing.T) {
	volume, sourcePath, storage, mountPoint := initializeLinkedTestFile(t)
	oldParent := filepath.Dir(sourcePath)
	newParent := filepath.Join(filepath.Dir(oldParent), "project-moved")
	if err := os.Rename(oldParent, newParent); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(newParent, filepath.Base(sourcePath))

	synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
	if retry := synchronizer.Synchronize(); retry {
		t.Fatal("offline move reconciliation unexpectedly requested a retry")
	}
	records := volume.linkRecords()
	if len(records) != 1 || records[0].relative != storage ||
		records[0].sourcePath != destination {
		t.Fatalf("records after offline parent move = %#v", records)
	}
	if link, err := inspectProtectedLink(destination); err != nil ||
		!link.isSymlink || !targetMatchesStorage(link.target, storage) {
		t.Fatalf("moved link = %#v, %v", link, err)
	}
}

func TestDeletedProtectedLinkDeletesObjectAfterGlobalConfirmation(t *testing.T) {
	volume, sourcePath, storage, mountPoint := initializeLinkedTestFile(t)
	synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if retry := synchronizer.Synchronize(); !retry {
		t.Fatal("link deletion was not given a race-settling retry")
	}
	time.Sleep(trackedLinkDeletionGrace + 20*time.Millisecond)
	if retry := synchronizer.Synchronize(); retry {
		t.Fatal("settled deletion unexpectedly requested another retry")
	}
	cipherPath, _ := volume.encryptedPath(storage)
	if _, err := os.Lstat(cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext after link deletion: %v", err)
	}
	if records := volume.linkRecords(); len(records) != 0 {
		t.Fatalf("records after deletion = %#v", records)
	}
}

func TestRegularReplacementPreservesObjectAsOrphan(t *testing.T) {
	volume, sourcePath, storage, mountPoint := initializeLinkedTestFile(t)
	synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	synchronizer.Synchronize()
	cipherPath, _ := volume.encryptedPath(storage)
	if _, err := os.Lstat(cipherPath); err != nil {
		t.Fatalf("replacement removed ciphertext: %v", err)
	}
	records := volume.linkRecords()
	if len(records) != 1 || records[0].orphanedAt == 0 {
		t.Fatalf("replacement records = %#v", records)
	}
}

func TestChangingMountPointRetargetsOpaqueLink(t *testing.T) {
	volume, sourcePath, storage, _ := initializeLinkedTestFile(t)
	newMountPoint := t.TempDir()
	synchronizer := newGlobalTestSynchronizer(t, volume, newMountPoint)
	if retry := synchronizer.Synchronize(); retry {
		t.Fatal("mount point update unexpectedly requested a retry")
	}
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := mountedPathForStorage(newMountPoint, storage)
	if err != nil {
		t.Fatal(err)
	}
	if !link.isSymlink || link.target != expected {
		t.Fatalf("retargeted link = %#v, want %s", link, expected)
	}
}

func TestPendingUnregisteredObjectIsNotCollected(t *testing.T) {
	volume, _ := initializeTestVolume(t, "pending object password", 1024*1024)
	t.Setenv("HOME", t.TempDir())
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	storage, _ := objectStoragePath(objectID)
	createTestFile(t, volume, storage, []byte("pending\n"))
	synchronizer := newGlobalTestSynchronizer(t, volume, t.TempDir())
	if retry := synchronizer.Synchronize(); !retry {
		t.Fatal("pending object did not request a registration retry")
	}
	cipherPath, _ := volume.encryptedPath(storage)
	if _, err := os.Lstat(cipherPath); err != nil {
		t.Fatalf("pending object was collected: %v", err)
	}
}

func TestLegacyMetadataMigratesCiphertextWithoutReencrypting(t *testing.T) {
	volume, _ := initializeTestVolume(t, "migration password", 1024*1024)
	sourcePath := filepath.Join(t.TempDir(), ".env")
	legacyStorage := testStoragePath(t, sourcePath)
	createTestFile(t, volume, legacyStorage, []byte("TOKEN=legacy\n"))
	legacyCipher, _ := volume.encryptedPath(legacyStorage)
	before, err := os.ReadFile(legacyCipher)
	if err != nil {
		t.Fatal(err)
	}
	mountPoint := t.TempDir()
	legacyTarget, err := MountedPath(mountPoint, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(sourcePath, legacyTarget); err != nil {
		t.Fatal(err)
	}
	meta := volume.fileMeta(legacyStorage, nil)
	legacy := Metadata{
		Version: legacyMetadataFormatVersion,
		Files:   map[string]FileMeta{metadataKey(legacyStorage): meta},
		Links:   map[string]string{metadataKey(legacyStorage): legacyTarget},
	}
	if err := saveMetadata(volume.root, legacy); err != nil {
		t.Fatal(err)
	}

	migrated, err := LoadVolume(
		volume.root,
		&recordingPrompter{fallback: "migration password"},
		1024*1024,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	records := migrated.linkRecords()
	if len(records) != 1 || records[0].sourcePath != sourcePath {
		t.Fatalf("migrated records = %#v", records)
	}
	newCipher, err := migrated.encryptedPath(records[0].relative)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(newCipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("migration rewrote ciphertext")
	}
	link, err := inspectProtectedLink(sourcePath)
	if err != nil || !link.isSymlink ||
		!targetMatchesStorage(link.target, records[0].relative) {
		t.Fatalf("migrated link = %#v, %v", link, err)
	}
}
