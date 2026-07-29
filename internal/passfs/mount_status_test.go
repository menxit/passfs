package passfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalMountPointResolvesParentWithoutMount(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Fatal(err)
	}

	got, err := canonicalMountPoint(filepath.Join(aliasParent, "mnt"))
	if err != nil {
		t.Fatalf("canonicalMountPoint: %v", err)
	}
	resolvedRealParent, err := filepath.EvalSymlinks(realParent)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolvedRealParent, "mnt")
	if got != want {
		t.Fatalf("canonical mount point = %q, want %q", got, want)
	}
}
