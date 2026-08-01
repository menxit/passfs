package passfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupCreateVerifyRestoreRoundTrip(t *testing.T) {
	const passphrase = "backup round trip password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	for _, plaintext := range [][]byte{
		[]byte("TOKEN=first\n"),
		[]byte("TOKEN=second\n"),
	} {
		objectID, err := newObjectID()
		if err != nil {
			t.Fatal(err)
		}
		storage, _ := objectStoragePath(objectID)
		createTestFile(t, volume, storage, plaintext)
	}

	backup := filepath.Join(t.TempDir(), "passfs-backup")
	manifest, err := CreateBackup(volume.root, backup)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.VolumeID != volume.VolumeID() {
		t.Fatalf("backup volume = %s, want %s", manifest.VolumeID, volume.VolumeID())
	}
	report, err := VerifyBackup(
		context.Background(),
		backup,
		&recordingPrompter{fallback: passphrase},
		1024*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Files != 2 || report.Bytes != uint64(len("TOKEN=first\n")+len("TOKEN=second\n")) {
		t.Fatalf("verification report = %#v", report)
	}

	restored := filepath.Join(t.TempDir(), "restored-vault")
	if _, err := RestoreBackup(backup, restored); err != nil {
		t.Fatal(err)
	}
	restoredReport, err := VerifyVault(
		context.Background(),
		restored,
		&recordingPrompter{fallback: passphrase},
		1024*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	if restoredReport != report {
		t.Fatalf("restored report = %#v, want %#v", restoredReport, report)
	}
}

func TestBackupVerifyRejectsCiphertextCorruption(t *testing.T) {
	const passphrase = "backup corruption password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	storage, _ := objectStoragePath(objectID)
	createTestFile(t, volume, storage, []byte("TOKEN=valid\n"))
	backup := filepath.Join(t.TempDir(), "passfs-backup")
	if _, err := CreateBackup(volume.root, backup); err != nil {
		t.Fatal(err)
	}
	ciphertext := filepath.Join(
		backup,
		backupVaultName,
		storage+encryptedSuffix,
	)
	file, err := os.OpenFile(ciphertext, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBackup(
		context.Background(),
		backup,
		&recordingPrompter{fallback: passphrase},
		1024*1024,
	); err == nil {
		t.Fatal("VerifyBackup accepted corrupted ciphertext")
	}
}

func TestVaultVerifyReportsMissingCiphertextWithoutErasingMetadata(t *testing.T) {
	const passphrase = "missing ciphertext password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	objectID, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	storage, _ := objectStoragePath(objectID)
	createTestFile(t, volume, storage, []byte("TOKEN=missing\n"))
	ciphertext, _ := volume.encryptedPath(storage)
	if err := os.Remove(ciphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVault(
		context.Background(),
		volume.root,
		&recordingPrompter{fallback: passphrase},
		1024*1024,
	); err == nil {
		t.Fatal("VerifyVault accepted missing ciphertext")
	}
	metadata, err := loadMetadata(volume.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := metadata.Files[metadataKey(storage)]; !exists {
		t.Fatal("vault verification erased metadata for missing ciphertext")
	}
}
