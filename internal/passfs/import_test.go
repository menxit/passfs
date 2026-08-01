package passfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestImportFileReplacesSourceAtomicallyWithLink(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "project", ".env")
	targetPath := filepath.Join(root, "mount", "project", ".env")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("TOKEN=secret\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o640); err != nil {
		t.Fatal(err)
	}

	result, err := importFile(sourcePath, targetPath, 1024)
	if err != nil {
		t.Fatalf("importFile: %v", err)
	}
	if !result.Imported || !result.LinkCreated || result.TargetPath != targetPath {
		t.Fatalf("import result = %#v", result)
	}
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !link.isSymlink || link.target != targetPath {
		t.Fatalf("source link = %#v, want target %q", link, targetPath)
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(plaintext) {
		t.Fatalf("target contents = %q, want %q", data, plaintext)
	}
	entries, err := os.ReadDir(filepath.Dir(sourcePath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".passfs-") {
			t.Fatalf("temporary import entry remains: %s", entry.Name())
		}
	}
}

func TestImportFileRestoresMissingLinkForExistingTarget(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "project", ".env")
	targetPath := filepath.Join(root, "mount", "project", ".env")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte("ciphertext-placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := importFile(sourcePath, targetPath, 1024)
	if err != nil {
		t.Fatalf("importFile: %v", err)
	}
	if result.Imported || !result.LinkCreated {
		t.Fatalf("import result = %#v", result)
	}
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !link.isSymlink || link.target != targetPath {
		t.Fatalf("restored link = %#v", link)
	}
}

func TestImportFileDoesNotOverwriteSourceWhenTargetExists(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mount", ".env")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("new plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte("existing target"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := importFile(sourcePath, targetPath, 1024); err == nil {
		t.Fatal("importFile overwrote a source/target conflict")
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "new plaintext"; got != want {
		t.Fatalf("source contents = %q, want %q", got, want)
	}
}

func TestImportFileRecoversInterruptedEmptyTarget(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mount", ".env")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("TOKEN=new-plaintext\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := importFile(sourcePath, targetPath, 1024)
	if err != nil {
		t.Fatalf("importFile: %v", err)
	}
	if !result.Imported || !result.LinkCreated {
		t.Fatalf("import result = %#v", result)
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != string(plaintext) {
		t.Fatalf("target contents = %q, want %q", got, plaintext)
	}
}

func TestValidateExistingImportTargetAllowsInterruptedEmptyTarget(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mount", ".env")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("TOKEN=new-plaintext\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Lstat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExistingImportTarget(
		sourcePath,
		targetPath,
		targetInfo,
		1024,
	); err != nil {
		t.Fatalf("validateExistingImportTarget: %v", err)
	}
}

func TestValidateExistingImportTargetRejectsAmbiguousEmptyFiles(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mount", ".env")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Lstat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExistingImportTarget(
		sourcePath,
		targetPath,
		targetInfo,
		1024,
	); err == nil || !strings.Contains(
		err.Error(),
		"is not the passfs protected link",
	) {
		t.Fatalf("validateExistingImportTarget error = %v", err)
	}
}

func TestValidateExistingImportTargetRejectsTargetWithData(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mount", ".env")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("new plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte("existing protected data"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Lstat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExistingImportTarget(
		sourcePath,
		targetPath,
		targetInfo,
		1024,
	); err == nil || !strings.Contains(
		err.Error(),
		"is not the passfs protected link",
	) {
		t.Fatalf("validateExistingImportTarget error = %v", err)
	}
}

func TestImportFilePreservesExistingEmptyTargetForEmptySource(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mount", ".env")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := importFile(sourcePath, targetPath, 1024); err == nil {
		t.Fatal("importFile replaced an ambiguous existing empty target")
	}
	if info, err := os.Lstat(targetPath); err != nil || info.Size() != 0 {
		t.Fatalf("empty target was changed: info=%v err=%v", info, err)
	}
	if info, err := os.Lstat(sourcePath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("empty source was changed: info=%v err=%v", info, err)
	}
}

func TestImportFileRejectsHardLinkedSource(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	if err := os.WriteFile(sourcePath, []byte("TOKEN=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(sourcePath, filepath.Join(root, "second-link")); err != nil {
		t.Fatal(err)
	}

	_, err := importFile(sourcePath, filepath.Join(root, "mount", ".env"), 1024)
	if err == nil || !strings.Contains(err.Error(), "multiple hard links") {
		t.Fatalf("importFile error = %v", err)
	}
}

func TestImportFileRejectsFIFOWithoutOpeningIt(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "secret.pipe")
	if err := syscall.Mkfifo(sourcePath, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := importFile(sourcePath, filepath.Join(root, "mount", "secret.pipe"), 1024)
	if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("importFile FIFO error = %v", err)
	}
}

func TestImportFileRejectsOversizedSourceWithoutCreatingTarget(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mount", ".env")
	if err := os.WriteFile(sourcePath, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := importFile(sourcePath, targetPath, 4); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("importFile error = %v, want ErrFileTooLarge", err)
	}
	if _, err := os.Lstat(targetPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target exists or returned unexpected error: %v", err)
	}
	if info, err := os.Lstat(sourcePath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("source was changed: %v, %v", info, err)
	}
}

func TestSameFileVersionDetectsInPlaceModification(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := os.Lstat(path); err != nil || !sameFileVersion(expected, current) {
		t.Fatalf("unchanged file was not recognized: %v", err)
	}

	changedTime := expected.ModTime().Add(time.Second)
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	current, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if sameFileVersion(expected, current) {
		t.Fatal("in-place modification was not detected")
	}
}

func TestEnsureProtectedLinkCreatesAbsoluteLink(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "project", ".env")
	targetPath := filepath.Join(root, "mnt", "project", ".env")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}

	created, err := EnsureProtectedLink(sourcePath, targetPath)
	if err != nil {
		t.Fatalf("EnsureProtectedLink: %v", err)
	}
	if !created {
		t.Fatal("EnsureProtectedLink did not report a newly created link")
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symbolic link", sourcePath)
	}
	linkTarget, err := os.Readlink(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if linkTarget != targetPath {
		t.Fatalf("link target = %q, want %q", linkTarget, targetPath)
	}
}

func TestEnsureProtectedLinkAcceptsExistingMatchingLink(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "project", ".env")
	targetPath := filepath.Join(root, "mnt", "project", ".env")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatal(err)
	}
	relativeTarget, err := filepath.Rel(filepath.Dir(sourcePath), targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relativeTarget, sourcePath); err != nil {
		t.Fatal(err)
	}

	created, err := EnsureProtectedLink(sourcePath, targetPath)
	if err != nil {
		t.Fatalf("EnsureProtectedLink: %v", err)
	}
	if created {
		t.Fatal("EnsureProtectedLink reported an existing link as newly created")
	}
}

func TestEnsureProtectedLinkDoesNotReplaceExistingFile(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mnt", ".env")
	if err := os.WriteFile(sourcePath, []byte("TOKEN=plaintext\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	created, err := EnsureProtectedLink(sourcePath, targetPath)
	if err == nil || !strings.Contains(err.Error(), "is not the passfs protected link") {
		t.Fatalf("EnsureProtectedLink error = %v", err)
	}
	if created {
		t.Fatal("EnsureProtectedLink reported creating a link")
	}
	data, readErr := os.ReadFile(sourcePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, want := string(data), "TOKEN=plaintext\n"; got != want {
		t.Fatalf("existing file = %q, want %q", got, want)
	}
}

func TestEnsureProtectedLinkDoesNotReplaceDifferentLink(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, ".env")
	targetPath := filepath.Join(root, "mnt", ".env")
	otherTarget := filepath.Join(root, "other", ".env")
	if err := os.Symlink(otherTarget, sourcePath); err != nil {
		t.Fatal(err)
	}

	created, err := EnsureProtectedLink(sourcePath, targetPath)
	if err == nil || !strings.Contains(err.Error(), "instead of the passfs target") {
		t.Fatalf("EnsureProtectedLink error = %v", err)
	}
	if created {
		t.Fatal("EnsureProtectedLink reported creating a link")
	}
	linkTarget, readErr := os.Readlink(sourcePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if linkTarget != otherTarget {
		t.Fatalf("existing link target = %q, want %q", linkTarget, otherTarget)
	}
}
