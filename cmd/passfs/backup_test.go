package main

import (
	"errors"
	"path/filepath"
	"testing"

	"passfs/internal/passfs"
)

func TestActivateVaultSelectionPersistsWhileFilesystemIsStopped(t *testing.T) {
	settings, restoredVault := testBackupSettings(t)
	if err := activateVaultSelection(
		settings,
		restoredVault,
		false,
		func(*passfs.Settings) error {
			t.Fatal("stopped filesystem was unexpectedly restarted")
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	loaded, err := passfs.LoadSettings(settings.Path())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Vault != restoredVault {
		t.Fatalf("active vault = %q, want %q", loaded.Vault, restoredVault)
	}
}

func TestActivateVaultSelectionRollsBackAfterRestartFailure(t *testing.T) {
	settings, restoredVault := testBackupSettings(t)
	originalVault := settings.Vault
	restarts := 0
	err := activateVaultSelection(
		settings,
		restoredVault,
		true,
		func(current *passfs.Settings) error {
			restarts++
			if restarts == 1 {
				if current.Vault != restoredVault {
					t.Fatalf("first restart vault = %q", current.Vault)
				}
				return errors.New("test mount failure")
			}
			if current.Vault != originalVault {
				t.Fatalf("rollback restart vault = %q", current.Vault)
			}
			return nil
		},
	)
	if err == nil || restarts != 2 {
		t.Fatalf("activation error = %v, restarts = %d", err, restarts)
	}
	loaded, loadErr := passfs.LoadSettings(settings.Path())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if loaded.Vault != originalVault {
		t.Fatalf("vault after rollback = %q, want %q", loaded.Vault, originalVault)
	}
}

func testBackupSettings(t *testing.T) (*passfs.Settings, string) {
	t.Helper()
	root := t.TempDir()
	settings, err := passfs.NewSettings(
		filepath.Join(root, "config.json"),
		filepath.Join(root, "current-vault"),
		filepath.Join(root, "mnt"),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}
	return settings, filepath.Join(root, "restored-vault")
}
