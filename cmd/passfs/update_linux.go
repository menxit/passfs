//go:build linux

package main

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"passfs/internal/updater"
)

const maxLinuxBinaryBytes = 128 * 1024 * 1024

func installPlatformUpdate(
	ctx context.Context,
	client *updater.Client,
	release updater.Release,
	writer io.Writer,
) (platformUpdateResult, error) {
	architecture, err := linuxReleaseArchitecture()
	if err != nil {
		return platformUpdateResult{}, err
	}
	asset := "passfs-linux-" + architecture + ".gz"
	archive, err := os.CreateTemp("", ".passfs-update-*.gz")
	if err != nil {
		return platformUpdateResult{}, err
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)

	fmt.Fprintf(writer, "Downloading passfs %s for Linux %s...\n", release.Version, architecture)
	downloadErr := client.Download(ctx, release, asset, archive)
	closeErr := archive.Close()
	if err := errors.Join(downloadErr, closeErr); err != nil {
		return platformUpdateResult{}, err
	}

	executable, err := currentExecutable()
	if err != nil {
		return platformUpdateResult{}, err
	}
	staged, err := os.CreateTemp(filepath.Dir(executable), ".passfs-update-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return platformUpdateResult{}, actionableError{
				"the current passfs installation is not writable: " + executable,
				"update it with the installation method originally used, or run:",
				"  curl -fsSL https://menxit.github.io/passfs/passfs | bash",
			}
		}
		return platformUpdateResult{}, err
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)

	if err := extractLinuxUpdate(archivePath, staged); err != nil {
		staged.Close()
		return platformUpdateResult{}, err
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return platformUpdateResult{}, err
	}
	if err := staged.Chmod(0o755); err != nil {
		staged.Close()
		return platformUpdateResult{}, err
	}
	if err := staged.Close(); err != nil {
		return platformUpdateResult{}, err
	}
	if err := verifyLinuxUpdateVersion(stagedPath, release.Version); err != nil {
		return platformUpdateResult{}, err
	}
	if err := os.Rename(stagedPath, executable); err != nil {
		return platformUpdateResult{}, fmt.Errorf("replace passfs executable: %w", err)
	}
	fmt.Fprintf(writer, "Updated passfs to %s\n", release.Version)
	return platformUpdateResult{
		installed:  true,
		reload:     true,
		executable: executable,
	}, nil
}

func linuxReleaseArchitecture() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported Linux architecture %s", runtime.GOARCH)
	}
}

func extractLinuxUpdate(archivePath string, destination io.Writer) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("open passfs update archive: %w", err)
	}
	defer compressed.Close()
	count, err := io.Copy(destination, io.LimitReader(compressed, maxLinuxBinaryBytes+1))
	if err != nil {
		return fmt.Errorf("extract passfs update: %w", err)
	}
	if count > maxLinuxBinaryBytes {
		return errors.New("passfs update binary is too large")
	}
	return nil
}

func verifyLinuxUpdateVersion(path, expected string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("verify downloaded passfs executable: %w", err)
	}
	if strings.TrimSpace(string(output)) != "passfs "+expected {
		return fmt.Errorf(
			"downloaded executable reported unexpected version %q",
			strings.TrimSpace(string(output)),
		)
	}
	return nil
}

func notifyPlatformUpdate(available string) (bool, error) {
	if !linuxDesktopSession() {
		return false, nil
	}
	notifySend, err := exec.LookPath("notify-send")
	if err != nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		notifySend,
		"--app-name=passfs",
		"--icon=software-update-available",
		"PassFS update available",
		"Version "+available+" is ready. Run passfs update.",
	)
	if err := command.Run(); err != nil {
		return false, err
	}
	return true, nil
}

func linuxDesktopSession() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
