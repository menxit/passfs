package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"passfs/internal/passfs"
)

func TestUsageAdvertisesSingleFileUnprotectAndLLMDocs(t *testing.T) {
	var usage bytes.Buffer
	printUsage(&usage)
	for _, expected := range []string{
		"passfs unprotect [options] [FILE]",
		"https://getpassfs.com/llms.txt",
	} {
		if !strings.Contains(usage.String(), expected) {
			t.Fatalf("usage %q does not contain %q", usage.String(), expected)
		}
	}
}

func TestEncryptWithoutMountExplainsHowToRecover(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	settings, err := passfs.NewSettings(
		configPath,
		filepath.Join(root, "vault"),
		filepath.Join(root, "mnt"),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = runEncrypt(
		[]string{"--config", configPath, filepath.Join(root, ".env")},
		&stdout,
		&stderr,
	)
	if err == nil {
		t.Fatal("runEncrypt succeeded without a mounted filesystem")
	}
	for _, expected := range []string{"not mounted", "passfs mount", "retry"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not contain %q", err, expected)
		}
	}
}

func TestConfigChangePrintsReloadCommand(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	settings, err := passfs.NewSettings(
		configPath,
		filepath.Join(root, "vault"),
		filepath.Join(root, "mnt"),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runConfig(
		[]string{"--config", configPath, "--unlock-for", "1m"},
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("runConfig: %v", err)
	}
	if !strings.Contains(stdout.String(), "passfs reload") {
		t.Fatalf("config output does not show reload command: %q", stdout.String())
	}
	loaded, err := passfs.LoadSettings(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if duration, err := loaded.UnlockDuration(); err != nil || duration != time.Minute {
		t.Fatalf("unlock duration = %s, %v", duration, err)
	}
}

func TestUnprotectConfirmationRequiresExactToken(t *testing.T) {
	if err := readUnprotectConfirmation(strings.NewReader("UNPROTECT\n")); err != nil {
		t.Fatalf("valid confirmation: %v", err)
	}
	if err := readUnprotectConfirmation(strings.NewReader("UNPROTECT")); err != nil {
		t.Fatalf("valid confirmation at end of input: %v", err)
	}
	for _, input := range []string{"unprotect\n", "yes\n", "\n"} {
		if err := readUnprotectConfirmation(strings.NewReader(input)); !errors.Is(
			err,
			passfs.ErrPromptCancelled,
		) {
			t.Fatalf("confirmation %q returned %v", input, err)
		}
	}
}

func TestUnprotectWarningExplainsPlaintextAndDeletion(t *testing.T) {
	var warning bytes.Buffer
	printUnprotectWarning(&warning, "")
	for _, expected := range []string{
		"WARNING",
		"All protected links",
		"plaintext",
		"permanently deleted",
		"UNPROTECT",
	} {
		if !strings.Contains(warning.String(), expected) {
			t.Fatalf("warning %q does not contain %q", warning.String(), expected)
		}
	}
}

func TestSingleFileUnprotectWarningNamesFile(t *testing.T) {
	var warning bytes.Buffer
	printUnprotectWarning(&warning, "/tmp/project/.env")
	for _, expected := range []string{
		"/tmp/project/.env",
		"regular plaintext file",
		"permanently deleted",
		"UNPROTECT",
	} {
		if !strings.Contains(warning.String(), expected) {
			t.Fatalf("warning %q does not contain %q", warning.String(), expected)
		}
	}
	if strings.Contains(warning.String(), "All protected links") {
		t.Fatalf("single-file warning describes a global operation: %q", warning.String())
	}
}

func TestUnprotectHelpDistinguishesSingleFileAndAll(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := runUnprotect([]string{"-h"}, &stdout, &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("runUnprotect(-h) error = %v, want flag.ErrHelp", err)
	}
	for _, expected := range []string{
		"passfs unprotect [options] [FILE]",
		"only from that file",
		"every passfs file",
	} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("help %q does not contain %q", stderr.String(), expected)
		}
	}
}

func TestInspectMountReportsOrdinaryDirectoryAsUnmounted(t *testing.T) {
	state, err := inspectMount(t.TempDir())
	if err != nil {
		t.Fatalf("inspectMount: %v", err)
	}
	if state.mounted || state.passfs || state.healthy || state.accessErr != nil {
		t.Fatalf("mount state = %#v", state)
	}
}

func TestPathsOverlapResolvesSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	internal := filepath.Join(root, "internal")
	if err := os.MkdirAll(internal, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(internal, alias); err != nil {
		t.Fatal(err)
	}

	overlaps, err := pathsOverlap(internal, filepath.Join(alias, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !overlaps {
		t.Fatal("symlinked parent bypassed internal-path detection")
	}

	external := filepath.Join(root, "external", "secret")
	overlaps, err = pathsOverlap(internal, external)
	if err != nil {
		t.Fatal(err)
	}
	if overlaps {
		t.Fatal("external missing path was classified as internal")
	}

	externalDirectory := filepath.Join(root, "project")
	if err := os.Mkdir(externalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	protectedLink := filepath.Join(externalDirectory, ".env")
	if err := os.Symlink(filepath.Join(internal, "mnt", ".env"), protectedLink); err != nil {
		t.Fatal(err)
	}
	overlaps, err = pathsOverlap(internal, protectedLink)
	if err != nil {
		t.Fatal(err)
	}
	if overlaps {
		t.Fatal("the final protected symlink was incorrectly classified as internal")
	}
}

func TestResolveExecutablePathFollowsInstalledSymlink(t *testing.T) {
	root := t.TempDir()
	appExecutable := filepath.Join(
		root,
		"Applications",
		"PassFS.app",
		"Contents",
		"MacOS",
		"passfs",
	)
	if err := os.MkdirAll(filepath.Dir(appExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appExecutable, []byte("passfs"), 0o700); err != nil {
		t.Fatal(err)
	}
	commandPath := filepath.Join(root, "bin", "passfs")
	if err := os.MkdirAll(filepath.Dir(commandPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(appExecutable, commandPath); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveExecutablePath(commandPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := filepath.EvalSymlinks(appExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != expected {
		t.Fatalf("resolved executable = %s, want %s", resolved, expected)
	}
}
