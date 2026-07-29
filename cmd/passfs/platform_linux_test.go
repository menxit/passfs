//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxSetupSelectsDetectedPackageManager(t *testing.T) {
	command, err := linuxPackageInstallCommandWithLookup(
		"fuse3",
		func(name string) (string, error) {
			if name == "pacman" {
				return "/usr/bin/pacman", nil
			}
			return "", errors.New("not found")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if command != "sudo pacman -S fuse3" {
		t.Fatalf("install command = %q", command)
	}
}

func TestLinuxFUSEErrorIncludesDetectedInstallCommand(t *testing.T) {
	binaryDirectory := t.TempDir()
	writeExecutable(t, filepath.Join(binaryDirectory, "apt-get"))
	t.Setenv("PATH", binaryDirectory)

	err := platformFUSEError(platformCapability{
		detail: "fusermount3 or fusermount is unavailable",
	})
	if !strings.Contains(err.Error(), "sudo apt-get install fuse3") {
		t.Fatalf("error does not contain detected install command:\n%s", err)
	}
}

func TestLinuxFUSEErrorDoesNotSuggestReinstallForMissingDevice(t *testing.T) {
	binaryDirectory := t.TempDir()
	writeExecutable(t, filepath.Join(binaryDirectory, "apt-get"))
	writeExecutable(t, filepath.Join(binaryDirectory, "fusermount3"))
	t.Setenv("PATH", binaryDirectory)

	err := platformFUSEError(platformCapability{
		detail: "/dev/fuse is unavailable",
	})
	for _, expected := range []string{
		"do not reinstall fuse3",
		"--device /dev/fuse --cap-add SYS_ADMIN",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error does not contain %q:\n%s", expected, err)
		}
	}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}
