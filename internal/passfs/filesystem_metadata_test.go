package passfs

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFileSystemRejectsHostMetadataWithoutAuthorization(t *testing.T) {
	volume, prompter := initializeTestVolume(
		t,
		"filesystem metadata test password",
		1024,
	)
	fileSystem := NewFileSystem(volume)

	if _, errno := fileSystem.Lookup(t.Context(), ".fseventsd"); errno != syscall.ENOENT {
		t.Fatalf("Lookup(.fseventsd) = %v, want ENOENT", errno)
	}
	if _, errno := fileSystem.MakeDirectory(
		t.Context(),
		"",
		".fseventsd",
		0o700,
	); errno != syscall.EPERM {
		t.Fatalf("MakeDirectory(.fseventsd) = %v, want EPERM", errno)
	}
	if _, handle, errno := fileSystem.Create(
		t.Context(),
		"",
		".DS_Store",
		syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR,
		0o600,
	); errno != syscall.EPERM {
		if handle != nil {
			_ = handle.Close(context.Background())
		}
		t.Fatalf("Create(.DS_Store) = %v, want EPERM", errno)
	}
	if got := prompter.requestCount(); got != 0 {
		t.Fatalf("host metadata caused %d authorization prompt(s)", got)
	}
}

func TestFileSystemHidesExistingHostMetadata(t *testing.T) {
	volume, _ := initializeTestVolume(
		t,
		"filesystem metadata visibility password",
		1024,
	)
	createTestFile(
		t,
		volume,
		filepath.Join("files", ".fseventsd", "fseventsd-uuid"),
		[]byte("synthetic-id"),
	)
	fileSystem := NewFileSystem(volume)

	entries, errno := fileSystem.ReadDirectory(t.Context(), "")
	if errno != 0 {
		t.Fatalf("ReadDirectory(root) = %v", errno)
	}
	for _, entry := range entries {
		if entry.Name == ".fseventsd" {
			t.Fatal("ReadDirectory exposed .fseventsd")
		}
	}

	metadata, err := loadMetadata(volume.root)
	if err != nil {
		t.Fatalf("loadMetadata: %v", err)
	}
	if _, exists := metadata.Files[metadataKey(
		filepath.Join("files", ".fseventsd", "fseventsd-uuid"),
	)]; exists {
		t.Fatal("reconciliation retained host metadata")
	}
}
