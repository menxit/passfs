package passfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultPathsUseDotConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	settingsPath, err := DefaultSettingsPath()
	if err != nil {
		t.Fatalf("DefaultSettingsPath: %v", err)
	}
	wantBase := filepath.Join(home, ".config", "passfs")
	if want := filepath.Join(wantBase, "config.json"); settingsPath != want {
		t.Fatalf("settings path = %q, want %q", settingsPath, want)
	}

	vaultPath, err := DefaultVaultPath()
	if err != nil {
		t.Fatalf("DefaultVaultPath: %v", err)
	}
	if want := filepath.Join(wantBase, "vault"); vaultPath != want {
		t.Fatalf("vault path = %q, want %q", vaultPath, want)
	}

	mountPoint, err := DefaultMountPoint()
	if err != nil {
		t.Fatalf("DefaultMountPoint: %v", err)
	}
	if want := filepath.Join(wantBase, "mnt"); mountPoint != want {
		t.Fatalf("mount point = %q, want %q", mountPoint, want)
	}
}

func TestSettingsRoundTripHasNoProjects(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "config", "config.json")
	settings, err := NewSettings(
		path,
		filepath.Join(base, "vault"),
		filepath.Join(base, "mnt"),
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("NewSettings: %v", err)
	}
	settings.TouchID = true
	settings.Adapter = "fskit"
	if err := settings.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "projects") {
		t.Fatalf("settings still contain projects: %s", data)
	}

	loaded, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if loaded.Version != settingsVersion {
		t.Fatalf("version = %d, want %d", loaded.Version, settingsVersion)
	}
	if loaded.Vault != settings.Vault || loaded.MountPoint != settings.MountPoint {
		t.Fatalf("loaded settings = %#v, want %#v", loaded, settings)
	}
	if !loaded.TouchID {
		t.Fatal("Touch ID setting was not preserved")
	}
	if loaded.Adapter != "fskit" {
		t.Fatalf("adapter = %q, want fskit", loaded.Adapter)
	}
	if duration, err := loaded.UnlockDuration(); err != nil || duration != 5*time.Minute {
		t.Fatalf("unlock duration = %s, %v", duration, err)
	}
}

func TestAbsolutePathMappings(t *testing.T) {
	absolute := filepath.Join(string(os.PathSeparator), "Users", "menxit", "Development", "project", ".env")
	storage := filepath.Join("files", "Users", "menxit", "Development", "project", ".env")
	original, err := OriginalPath(storage)
	if err != nil {
		t.Fatalf("OriginalPath: %v", err)
	}
	if original != absolute {
		t.Fatalf("original path = %q, want %q", original, absolute)
	}

	mountPoint := filepath.Join(string(os.PathSeparator), "home", "menxit", ".config", "passfs", "mnt")
	mounted, err := MountedPath(mountPoint, absolute)
	if err != nil {
		t.Fatalf("MountedPath: %v", err)
	}
	wantMounted := filepath.Join(mountPoint, "Users", "menxit", "Development", "project", ".env")
	if mounted != wantMounted {
		t.Fatalf("mounted path = %q, want %q", mounted, wantMounted)
	}
}

func TestVaultAndMountPointCannotContainEachOther(t *testing.T) {
	base := t.TempDir()
	if _, err := NewSettings(
		filepath.Join(base, "config.json"),
		filepath.Join(base, "vault"),
		filepath.Join(base, "vault", "mnt"),
		0,
	); err == nil {
		t.Fatal("NewSettings accepted a mount point inside the vault")
	}
}

func TestVaultAndMountPointCannotOverlapThroughSymlink(t *testing.T) {
	base := t.TempDir()
	vault := filepath.Join(base, "vault")
	if err := os.Mkdir(vault, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "vault-alias")
	if err := os.Symlink(vault, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSettings(
		filepath.Join(base, "config.json"),
		vault,
		filepath.Join(alias, "mnt"),
		0,
	); err == nil {
		t.Fatal("NewSettings accepted a mount point inside a symlinked vault")
	}
}

func TestSettingsRejectTrailingData(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "config.json")
	data := []byte(`{
  "version": 2,
  "vault": "/tmp/passfs-vault",
  "mountPoint": "/tmp/passfs-mount",
  "unlockFor": "0s"
}
unexpected`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(path); err == nil {
		t.Fatal("LoadSettings accepted trailing non-JSON data")
	}
}
