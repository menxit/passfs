package passfs

import (
	"os"
	"path/filepath"
	"testing"
)

func testOpaqueObject(t *testing.T, volume *Volume, mountPoint string) (string, string) {
	t.Helper()
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	storage, _ := objectStoragePath(objectID)
	createTestFile(t, volume, storage, []byte("TOKEN=encrypted\n"))
	target, err := mountedObjectPath(mountPoint, objectID)
	if err != nil {
		t.Fatal(err)
	}
	return storage, target
}

func TestRegisterProtectedLinkInVaultMergesWithRunningVolume(t *testing.T) {
	volume, _ := initializeTestVolume(t, "registration password", 1024*1024)
	mountPoint := t.TempDir()
	storage, targetPath := testOpaqueObject(t, volume, mountPoint)
	sourcePath := filepath.Join(t.TempDir(), ".env")
	sourcePath, err := ResolvePathEntry(sourcePath)
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
		t.Fatal(err)
	}

	meta := volume.fileMeta(storage, nil)
	meta.Mode = 0o640
	if err := volume.setFileMeta(storage, meta); err != nil {
		t.Fatal(err)
	}
	records := volume.linkRecords()
	if len(records) != 1 || records[0].relative != storage ||
		records[0].sourcePath != sourcePath || records[0].orphanedAt != 0 {
		t.Fatalf("running volume records = %#v", records)
	}
}

func TestRegisterProtectedLinkInVaultRejectsUnexpectedLink(t *testing.T) {
	volume, _ := initializeTestVolume(t, "registration validation password", 1024*1024)
	mountPoint := t.TempDir()
	_, targetPath := testOpaqueObject(t, volume, mountPoint)
	sourcePath := filepath.Join(t.TempDir(), ".env")
	sourcePath, err := ResolvePathEntry(sourcePath)
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
		t.Fatal("unexpected link was registered")
	}
	if records := volume.linkRecords(); len(records) != 1 ||
		records[0].sourcePath != "" {
		t.Fatalf("records after rejected registration = %#v", records)
	}
}

func TestCanReplaceProtectedTargetRequiresExactObjectRegistration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	volume, _ := initializeTestVolume(t, "replacement password", 1024*1024)
	mountPoint := t.TempDir()
	storage, targetPath := testOpaqueObject(t, volume, mountPoint)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte("TOKEN=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(home, "project", ".env")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedLink(sourcePath, targetPath); err != nil {
		t.Fatal(err)
	}
	if err := volume.setLinkSource(storage, sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("TOKEN=new\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	replaceable, err := CanReplaceDisplacedProtectedTarget(
		volume.root,
		mountPoint,
		sourcePath,
		targetPath,
		1024*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !replaceable {
		t.Fatal("registered object replacement was not recognized")
	}
	otherTarget := filepath.Join(mountPoint, objectNamespaceDirectory, "00000000-0000-4000-8000-000000000000")
	if err := os.WriteFile(otherTarget, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if replaceable, _ := CanReplaceDisplacedProtectedTarget(
		volume.root,
		mountPoint,
		sourcePath,
		otherTarget,
		1024*1024,
	); replaceable {
		t.Fatal("unregistered object was considered replaceable")
	}
}
