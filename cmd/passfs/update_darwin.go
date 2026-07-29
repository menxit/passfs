//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"passfs/internal/updater"
)

const passfsAppleTeamID = "3943PK2P39"

func installPlatformUpdate(
	ctx context.Context,
	client *updater.Client,
	release updater.Release,
	writer io.Writer,
) (platformUpdateResult, error) {
	downloads, err := userDownloadsDirectory()
	if err != nil {
		return platformUpdateResult{}, err
	}
	if err := os.MkdirAll(downloads, 0o700); err != nil {
		return platformUpdateResult{}, err
	}
	temporary, err := os.CreateTemp(downloads, ".PassFS-update-*.pkg")
	if err != nil {
		return platformUpdateResult{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	const asset = "PassFS-macos-universal.pkg"
	fmt.Fprintln(writer, "Downloading the signed macOS installer...")
	downloadErr := client.Download(ctx, release, asset, temporary)
	closeErr := temporary.Close()
	if err := errors.Join(downloadErr, closeErr); err != nil {
		return platformUpdateResult{}, err
	}
	if err := verifyMacOSPackage(temporaryPath); err != nil {
		return platformUpdateResult{}, err
	}

	destination := filepath.Join(
		downloads,
		"PassFS-"+release.Version+".pkg",
	)
	if err := os.Rename(temporaryPath, destination); err != nil {
		return platformUpdateResult{}, err
	}
	if err := exec.Command("/usr/bin/open", destination).Start(); err != nil {
		return platformUpdateResult{}, fmt.Errorf("open macOS Installer: %w", err)
	}
	fmt.Fprintf(writer, "Verified PassFS %s and opened macOS Installer.\n", release.Version)
	fmt.Fprintln(writer, "Installer will reload the passfs service after the upgrade.")
	return platformUpdateResult{}, nil
}

func userDownloadsDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Downloads"), nil
}

func verifyMacOSPackage(path string) error {
	signatureOutput, err := exec.Command(
		"/usr/sbin/pkgutil",
		"--check-signature",
		path,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"verify installer signature: %w: %s",
			err,
			bytes.TrimSpace(signatureOutput),
		)
	}
	if !strings.Contains(string(signatureOutput), passfsAppleTeamID) {
		return errors.New("installer is not signed by the expected passfs Apple team")
	}
	gatekeeperOutput, err := exec.Command(
		"/usr/sbin/spctl",
		"--assess",
		"--type",
		"install",
		"--verbose=2",
		path,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"verify installer with Gatekeeper: %w: %s",
			err,
			bytes.TrimSpace(gatekeeperOutput),
		)
	}
	return nil
}

func notifyPlatformUpdate(available string) (bool, error) {
	const script = `on run argv
display notification ("Version " & item 1 & " is ready. Run passfs update.") with title "PassFS update available"
end run`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"/usr/bin/osascript",
		"-e",
		script,
		available,
	)
	if err := command.Run(); err != nil {
		return false, err
	}
	return true, nil
}
