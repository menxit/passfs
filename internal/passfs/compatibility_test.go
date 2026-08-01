package passfs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestEditorAtomicSavePatternsEnterExplicitConflictRecovery(t *testing.T) {
	patterns := []struct {
		name string
		save func(t *testing.T, source string)
	}{
		{
			name: "VS_Code_rename_over_symlink",
			save: func(t *testing.T, source string) {
				t.Helper()
				temporary := source + ".tmp"
				if err := os.WriteFile(temporary, []byte("TOKEN=vscode\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(temporary, source); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "JetBrains_safe_write_backup_then_replace",
			save: func(t *testing.T, source string) {
				t.Helper()
				if err := os.Rename(source, source+"___jb_old___"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source, []byte("TOKEN=jetbrains\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "Xcode_atomic_exchange_style",
			save: func(t *testing.T, source string) {
				t.Helper()
				temporary := filepath.Join(filepath.Dir(source), ".dat.nosync.tmp")
				if err := os.WriteFile(temporary, []byte("TOKEN=xcode\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(temporary, source); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "Vim_writebackup_then_replace",
			save: func(t *testing.T, source string) {
				t.Helper()
				if err := os.Rename(source, source+"~"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source, []byte("TOKEN=vim\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, pattern := range patterns {
		t.Run(pattern.name, func(t *testing.T) {
			volume, source, storage, mountPoint := initializeLinkedTestFile(t)
			synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
			pattern.save(t, source)
			synchronizer.Synchronize()
			items, err := RecoveryItems(volume.root)
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 || items[0].State != RecoveryConflict || items[0].Path != source {
				t.Fatalf("recovery items = %#v", items)
			}
			ciphertext, _ := volume.encryptedPath(storage)
			if _, err := os.Stat(ciphertext); err != nil {
				t.Fatalf("atomic save removed ciphertext: %v", err)
			}
		})
	}
}

func TestGitCleanMovesDeletedIgnoredSecretToRecovery(t *testing.T) {
	git := requireExecutable(t, "git")
	volume, source, storage, mountPoint := initializeLinkedTestFile(t)
	project := filepath.Dir(source)
	runCompatibilityCommand(t, project, git, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(project, ".gitignore"), []byte(".env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
	runCompatibilityCommand(t, project, git, "clean", "-fdx", "--quiet")
	if retry := synchronizer.Synchronize(); !retry {
		t.Fatal("git clean deletion did not enter the race-settling window")
	}
	time.Sleep(trackedLinkDeletionGrace + 20*time.Millisecond)
	synchronizer.Synchronize()
	assertRecoveryState(t, volume, source, storage, RecoveryTrash)
}

func TestGitCheckoutReplacementEntersConflictRecovery(t *testing.T) {
	git := requireExecutable(t, "git")
	volume, source, storage, mountPoint := initializeLinkedTestFile(t)
	project := filepath.Dir(source)
	target, err := os.Readlink(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("TOKEN=tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCompatibilityCommand(t, project, git, "init", "--quiet")
	runCompatibilityCommand(t, project, git, "add", ".env")
	runCompatibilityCommand(
		t, project, git,
		"-c", "user.name=PassFS Test",
		"-c", "user.email=passfs@example.invalid",
		"commit", "--quiet", "-m", "fixture",
	)
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, source); err != nil {
		t.Fatal(err)
	}
	synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
	runCompatibilityCommand(t, project, git, "checkout", "--", ".env")
	synchronizer.Synchronize()
	assertRecoveryState(t, volume, source, storage, RecoveryConflict)
}

func TestRsyncDeleteMovesProtectedLinkToRecovery(t *testing.T) {
	rsync := requireExecutable(t, "rsync")
	volume, source, storage, mountPoint := initializeLinkedTestFile(t)
	project := filepath.Dir(source)
	emptySource := t.TempDir()
	synchronizer := newGlobalTestSynchronizer(t, volume, mountPoint)
	runCompatibilityCommand(
		t,
		project,
		rsync,
		"-a", "--delete", emptySource+string(os.PathSeparator), project+string(os.PathSeparator),
	)
	if retry := synchronizer.Synchronize(); !retry {
		t.Fatal("rsync deletion did not enter the race-settling window")
	}
	time.Sleep(trackedLinkDeletionGrace + 20*time.Millisecond)
	synchronizer.Synchronize()
	assertRecoveryState(t, volume, source, storage, RecoveryTrash)
}

func TestShellAndDotenvReadOnlyOpenContract(t *testing.T) {
	const passphrase = "read compatibility password"
	volume, _ := initializeTestVolume(t, passphrase, 1024*1024)
	plaintext := []byte("TOKEN=readable\nEMPTY=\n")
	createTestFile(t, volume, "dotenv.env", plaintext)

	for _, consumer := range []string{"POSIX_shell_source", "dotenv_read", "Docker_bind_consumer"} {
		t.Run(consumer, func(t *testing.T) {
			handle, err := volume.openFile(context.Background(), "dotenv.env", syscall.O_RDONLY)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close(context.Background())
			if got := readOpenFile(t, handle); string(got) != string(plaintext) {
				t.Fatalf("plaintext = %q, want %q", got, plaintext)
			}
		})
	}
}

func requireExecutable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed: %v", name, err)
	}
	return path
}

func runCompatibilityCommand(
	t *testing.T,
	directory,
	executable string,
	args ...string,
) {
	t.Helper()
	command := exec.Command(executable, args...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", executable, args, err, output)
	}
}

func assertRecoveryState(
	t *testing.T,
	volume *Volume,
	source,
	storage string,
	state RecoveryState,
) {
	t.Helper()
	items, err := RecoveryItems(volume.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].State != state || items[0].Path != source {
		t.Fatalf("recovery items = %#v", items)
	}
	ciphertext, _ := volume.encryptedPath(storage)
	if _, err := os.Stat(ciphertext); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect ciphertext: %v", err)
	} else if errors.Is(err, os.ErrNotExist) {
		t.Fatal("compatibility operation removed ciphertext")
	}
}
