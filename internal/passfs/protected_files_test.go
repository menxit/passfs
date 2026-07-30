package passfs

import (
	"errors"
	"os"
	"testing"
)

func TestProtectedFilesListsOnlyActiveProtectedLinks(t *testing.T) {
	volume, sourcePath, storagePath, _ := initializeLinkedTestFile(t)

	files, err := ProtectedFiles(volume.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != sourcePath {
		t.Fatalf("ProtectedFiles = %#v, want active link %q", files, sourcePath)
	}

	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	files, err = ProtectedFiles(volume.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("ProtectedFiles after link deletion = %#v, want none", files)
	}

	cipherPath, err := volume.encryptedPath(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(cipherPath); err != nil {
		t.Fatalf("ciphertext was not preserved: %v", err)
	}
}

func TestProtectedFilesHidesReplacedProtectedLink(t *testing.T) {
	volume, sourcePath, _, _ := initializeLinkedTestFile(t)
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, err := ProtectedFiles(volume.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("ProtectedFiles with replaced link = %#v, want none", files)
	}

	if _, err := os.Lstat(sourcePath); errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement file was removed")
	}
}
