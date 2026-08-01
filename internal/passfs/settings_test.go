package passfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultPathsUsePassFSHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	settingsPath, err := DefaultSettingsPath()
	if err != nil {
		t.Fatalf("DefaultSettingsPath: %v", err)
	}
	wantBase := filepath.Join(home, ".passfs")
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

func TestDefaultSettingsPathUsesLegacyHomeUntilMigrated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacy := filepath.Join(home, ".config", "passfs", "config.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := DefaultSettingsPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != legacy {
		t.Fatalf("settings path = %q, want legacy path %q", got, legacy)
	}
}

func TestMigrateLegacyHomeMovesAndRewritesDefaultPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacyRoot := filepath.Join(home, ".config", "passfs")
	legacySettings, err := NewSettings(
		filepath.Join(legacyRoot, "config.json"),
		filepath.Join(legacyRoot, "vault"),
		filepath.Join(legacyRoot, "mnt"),
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	legacySettings.TouchID = true
	legacySettings.Adapter = "fskit"
	if err := legacySettings.Save(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(legacyRoot, "vault", "marker")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := MigrateLegacyHome()
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("legacy home was not migrated")
	}
	currentRoot := filepath.Join(home, ".passfs")
	current, err := LoadSettings(filepath.Join(currentRoot, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if current.Vault != filepath.Join(currentRoot, "vault") {
		t.Fatalf("vault = %q", current.Vault)
	}
	if current.MountPoint != filepath.Join(currentRoot, "mnt") {
		t.Fatalf("mount point = %q", current.MountPoint)
	}
	if !current.TouchID || current.Adapter != "fskit" {
		t.Fatalf("settings not preserved: %#v", current)
	}
	if _, err := os.Stat(filepath.Join(currentRoot, "vault", "marker")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy root still exists: %v", err)
	}
}

func TestMigrateLegacyHomePreservesExternalPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacyRoot := filepath.Join(home, ".config", "passfs")
	external := filepath.Join(home, "PassFS Data")
	settings, err := NewSettings(
		filepath.Join(legacyRoot, "config.json"),
		filepath.Join(external, "vault"),
		filepath.Join(external, "mnt"),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyHome(); err != nil {
		t.Fatal(err)
	}
	current, err := LoadSettings(filepath.Join(home, ".passfs", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if current.Vault != filepath.Join(external, "vault") ||
		current.MountPoint != filepath.Join(external, "mnt") {
		t.Fatalf("external paths changed: %#v", current)
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
	if scope, err := loaded.AuthorizationScope(); err != nil || scope != UnlockFile {
		t.Fatalf("unlock scope = %q, %v; want file", scope, err)
	}
}

func TestSettingsSetVaultValidatesAndPersists(t *testing.T) {
	base := t.TempDir()
	settings, err := NewSettings(
		filepath.Join(base, "config.json"),
		filepath.Join(base, "old-vault"),
		filepath.Join(base, "mnt"),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	newVault := filepath.Join(base, "restored-vault")
	if err := settings.SetVault(newVault); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSettings(settings.Path())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Vault != newVault {
		t.Fatalf("vault = %q, want %q", loaded.Vault, newVault)
	}
	if err := loaded.SetVault(filepath.Join(loaded.MountPoint, "vault")); err == nil {
		t.Fatal("SetVault accepted a vault inside the mount point")
	}
}

func TestSettingsWithoutScopeUseSafeCompatibleDefault(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "config.json")
	data := []byte(`{
  "version": 2,
  "vault": "` + filepath.Join(base, "vault") + `",
  "mountPoint": "` + filepath.Join(base, "mnt") + `",
  "unlockFor": "5m"
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if scope, err := settings.AuthorizationScope(); err != nil || scope != UnlockFile {
		t.Fatalf("legacy scope = %q, %v; want file", scope, err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migrated), `"version": 3`) {
		t.Fatalf("settings were not migrated to v3: %s", migrated)
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
