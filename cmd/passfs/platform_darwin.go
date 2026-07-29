//go:build darwin

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

const macFUSEURL = "https://macfuse.io/"

var macFUSEMountHelpers = []string{
	"/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse",
	"/Library/Filesystems/osxfuse.fs/Contents/Resources/mount_osxfuse",
}

func platformFUSECapability() platformCapability {
	for _, helper := range macFUSEMountHelpers {
		info, err := os.Stat(helper)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return platformCapability{
				name:   "macFUSE",
				ready:  true,
				detail: "mount helper available",
			}
		}
	}
	return platformCapability{
		name:   "macFUSE",
		detail: "not installed or its mount helper is unavailable",
	}
}

func platformPromptCapability() platformCapability {
	if _, err := os.Stat("/usr/bin/osascript"); err != nil {
		return platformCapability{
			name:   "Prompt",
			detail: "the macOS dialog service is unavailable",
		}
	}
	return platformCapability{
		name:   "Prompt",
		ready:  true,
		detail: "Touch ID when configured, otherwise a macOS password dialog",
	}
}

func platformFUSEError(_ platformCapability) error {
	return actionableError{
		"macFUSE is required before passfs can mount its filesystem",
		"start the guided setup with:",
		"  passfs setup",
		"then retry:",
		"  passfs mount",
	}
}

func guidePlatformFUSESetup(writer io.Writer, openBrowser bool) error {
	writeSetupLines(
		writer,
		"Install the latest signed macFUSE package from:",
		"  "+macFUSEURL,
		"",
		"Complete any approval requested by macOS, restart if requested, then run:",
		"  passfs doctor",
		"  passfs mount",
	)
	if !openBrowser {
		return nil
	}
	if err := exec.Command("/usr/bin/open", macFUSEURL).Start(); err != nil {
		return fmt.Errorf("open the macFUSE download page: %w", err)
	}
	fmt.Fprintln(writer, "Opened the official macFUSE download page.")
	return nil
}

func guidePlatformPromptSetup(io.Writer) error {
	return nil
}

func platformMountWaitError(err error, logHint string) error {
	return actionableError{
		err.Error(),
		"macFUSE is installed but the filesystem did not become ready",
		"complete any approval requested in System Settings and restart macOS if requested",
		"then verify and retry with:",
		"  passfs doctor",
		"  passfs mount",
		"service log: " + logHint,
	}
}
