//go:build darwin

package passfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPassFSDialogIconPathFindsOuterAppFromCLIHelper(t *testing.T) {
	root := t.TempDir()
	icon := filepath.Join(
		root,
		"PassFS.app",
		"Contents",
		"Resources",
		"PassFS.icns",
	)
	if err := os.MkdirAll(filepath.Dir(icon), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(icon, []byte("icon"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(
		root,
		"PassFS.app",
		"Contents",
		"Helpers",
		"passfs",
	)
	got := passFSDialogIconPathForExecutable(executable)
	if got != icon {
		t.Fatalf("icon path = %q, want %q", got, icon)
	}
}

func TestPassFSDialogIconPathReturnsEmptyOutsideApp(t *testing.T) {
	got := passFSDialogIconPathForExecutable(
		filepath.Join(t.TempDir(), "passfs"),
	)
	if got != "" {
		t.Fatalf("icon path = %q, want empty", got)
	}
}
