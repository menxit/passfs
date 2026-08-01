package passfs

import (
	"os"
	"testing"
	"time"
)

func TestRecoveryRestoreRecreatesOnlyMissingProtectedLink(t *testing.T) {
	volume, source, storage, mountPoint := initializeLinkedTestFile(t)
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := volume.markLinkRecovery(
		storage, RecoveryTrash, "test deletion", time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	items, err := RecoveryItems(volume.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].State != RecoveryTrash || items[0].Path != source {
		t.Fatalf("recovery items = %#v", items)
	}
	if err := RestoreRecoveryLink(volume.root, mountPoint, items[0].ObjectID); err != nil {
		t.Fatal(err)
	}
	link, err := inspectProtectedLink(source)
	if err != nil || !link.isSymlink || !targetMatchesStorage(link.target, storage) {
		t.Fatalf("restored link = %#v, %v", link, err)
	}
	items, err = RecoveryItems(volume.root)
	if err != nil || len(items) != 0 {
		t.Fatalf("recovery after restore = %#v, %v", items, err)
	}
}

func TestRecoveryRestoreNeverOverwritesConflict(t *testing.T) {
	volume, source, storage, mountPoint := initializeLinkedTestFile(t)
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := volume.markLinkRecovery(
		storage, RecoveryConflict, "test replacement", time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	if err := RestoreRecoveryLink(volume.root, mountPoint, source); err == nil {
		t.Fatal("RestoreRecoveryLink overwrote a conflicting regular file")
	}
	data, err := os.ReadFile(source)
	if err != nil || string(data) != "replacement\n" {
		t.Fatalf("replacement = %q, %v", data, err)
	}
	ciphertext, _ := volume.encryptedPath(storage)
	if _, err := os.Stat(ciphertext); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
}
