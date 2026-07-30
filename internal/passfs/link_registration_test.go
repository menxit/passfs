package passfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegisterProtectedLinkInVaultMergesWithRunningVolume(t *testing.T) {
	volume, _ := initializeTestVolume(
		t,
		"native adapter registration password",
		1024*1024,
	)
	sourcePath := filepath.Join(t.TempDir(), ".env")
	storage := testStoragePath(t, sourcePath)
	createTestFile(t, volume, storage, []byte("TOKEN=encrypted\n"))

	mountPoint := t.TempDir()
	targetPath, err := MountedPath(mountPoint, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(sourcePath, targetPath); err != nil {
		t.Fatal(err)
	}
	if err := RegisterProtectedLinkInVault(
		volume.root,
		mountPoint,
		sourcePath,
		targetPath,
	); err != nil {
		t.Fatalf("RegisterProtectedLinkInVault: %v", err)
	}

	meta := volume.fileMeta(storage, nil)
	meta.Mode = 0o640
	if err := volume.setFileMeta(storage, meta); err != nil {
		t.Fatalf("update stale running volume metadata: %v", err)
	}

	records := volume.linkRecords()
	if len(records) != 1 ||
		records[0].relative != storage ||
		records[0].linkTarget != filepath.Clean(targetPath) {
		t.Fatalf("running volume records = %#v", records)
	}
	reloaded, err := LoadVolume(
		volume.root,
		&recordingPrompter{
			fallback: "native adapter registration password",
		},
		1024*1024,
		0,
	)
	if err != nil {
		t.Fatalf("reload volume: %v", err)
	}
	reloadedRecords := reloaded.linkRecords()
	if len(reloadedRecords) != 1 ||
		reloadedRecords[0].linkTarget != filepath.Clean(targetPath) {
		t.Fatalf("reloaded volume records = %#v", reloadedRecords)
	}
}

func TestRegisterProtectedLinkInVaultRejectsUnexpectedLink(t *testing.T) {
	volume, _ := initializeTestVolume(
		t,
		"native adapter validation password",
		1024*1024,
	)
	sourcePath := filepath.Join(t.TempDir(), ".env")
	storage := testStoragePath(t, sourcePath)
	createTestFile(t, volume, storage, nil)
	mountPoint := t.TempDir()
	targetPath, err := MountedPath(mountPoint, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath+".other", sourcePath); err != nil {
		t.Fatal(err)
	}

	if err := RegisterProtectedLinkInVault(
		volume.root,
		mountPoint,
		sourcePath,
		targetPath,
	); err == nil {
		t.Fatal("RegisterProtectedLinkInVault accepted an unexpected link")
	}
	if records := volume.linkRecords(); len(records) != 1 ||
		records[0].linkTarget != "" {
		t.Fatalf("unexpected link was registered: %#v", records)
	}
}
