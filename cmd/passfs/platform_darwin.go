//go:build darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"passfs/internal/passfs"
)

const macFUSEURL = "https://macfuse.io/"

var macFUSEMountHelpers = []string{
	"/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse",
	"/Library/Filesystems/osxfuse.fs/Contents/Resources/mount_osxfuse",
}

func launchPlatformApp() (bool, error) {
	executable, err := currentExecutable()
	if err != nil {
		return false, nil
	}
	appPath, err := passFSAppPathForExecutable(executable)
	if err != nil {
		return false, nil
	}
	appExecutable := filepath.Join(
		appPath,
		"Contents",
		"MacOS",
		"PassFS",
	)
	info, err := os.Stat(appExecutable)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		if err == nil {
			err = errors.New("application executable is not runnable")
		}
		return false, fmt.Errorf("launch PassFS: %w", err)
	}
	if output, err := exec.Command(
		"/usr/bin/open",
		"-a",
		appPath,
		"passfs://manage",
	).CombinedOutput(); err != nil {
		return false, fmt.Errorf(
			"launch PassFS: %w: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}
	return true, nil
}

func passFSAppPathForExecutable(executable string) (string, error) {
	contents, err := passFSContentsPathForExecutable(executable)
	if err != nil {
		return "", err
	}
	return filepath.Dir(contents), nil
}

func passFSContentsPathForExecutable(executable string) (string, error) {
	directory := filepath.Dir(executable)
	for range 8 {
		if filepath.Base(directory) == "Contents" &&
			filepath.Ext(filepath.Dir(directory)) == ".app" {
			return filepath.Clean(directory), nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return "", errors.New("PassFS.app bundle could not be located")
}

func platformFilesystemAdapters() []filesystemAdapter {
	return []filesystemAdapter{
		fsKitFilesystemAdapter{},
		fuseFilesystemAdapter{},
	}
}

func platformAutomaticFilesystemAdapters(
	adapters []filesystemAdapter,
) []filesystemAdapter {
	major, err := macOSMajorVersion()
	if err != nil {
		return adapters
	}
	return darwinAutomaticFilesystemAdapters(major, adapters)
}

func darwinAutomaticFilesystemAdapters(
	major int,
	adapters []filesystemAdapter,
) []filesystemAdapter {
	if major < 26 {
		return adapters
	}
	if adapter := filesystemAdapterNamed(adapters, adapterFSKit); adapter != nil {
		return []filesystemAdapter{adapter}
	}
	return adapters
}

func preparePlatformFilesystemForInit(
	_ *passfs.Settings,
	requested string,
	writer io.Writer,
) error {
	if requested == adapterFUSE {
		return nil
	}
	major, err := macOSMajorVersion()
	if err != nil || major < 26 {
		return nil
	}
	extensionPath, extensionErr := embeddedFSKitExtensionPath()
	if extensionErr == nil {
		_, extensionErr = os.Stat(extensionPath)
	}
	if extensionErr != nil {
		return actionableError{
			"the PassFS File System Extension is not installed",
			"install the signed PassFS package, then rerun:",
			"  passfs init",
		}
	}
	fmt.Fprintln(writer, "Filesystem: Apple FSKit (default)")
	return nil
}

func openFSKitExtensionSetup() error {
	executable, err := currentExecutable()
	if err != nil {
		return fmt.Errorf("locate PassFS.app: %w", err)
	}
	appPath, err := passFSAppPathForExecutable(executable)
	if err != nil {
		return fmt.Errorf("locate PassFS.app: %w", err)
	}
	output, err := exec.Command(
		"/usr/bin/open",
		"-a",
		appPath,
		"passfs://setup/fskit",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"open the PassFS File System Extension control: %w: %s",
			err,
			string(output),
		)
	}
	return nil
}

func platformFilesystemApprovalRequired(
	adapterName string,
	logPath string,
	offset int64,
) bool {
	if adapterName != adapterFSKit {
		return false
	}
	file, err := os.Open(logPath)
	if err != nil {
		return false
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr == nil && info.Size() < offset {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return false
	}
	output, err := io.ReadAll(io.LimitReader(file, 256*1024))
	return err == nil && fsKitModuleDisabledOutput(output)
}

func fsKitModuleDisabledOutput(output []byte) bool {
	lower := bytes.ToLower(output)
	return bytes.Contains(
		lower,
		[]byte("module "+fsKitExtensionBundleID+" is disabled"),
	)
}

func completePlatformFilesystemApproval(
	settings *passfs.Settings,
	adapterName string,
	openSettings bool,
	writer io.Writer,
) error {
	if adapterName != adapterFSKit {
		return fmt.Errorf(
			"filesystem adapter %q does not require macOS approval",
			adapterName,
		)
	}
	writeSetupLines(
		writer,
		"One-time macOS approval required:",
		"PassFS will open File System Extensions in System Settings.",
		"Turn on passfs in the list.",
		"This command will continue and mount automatically.",
	)
	if !openSettings {
		return actionableError{
			"the PassFS File System Extension requires approval",
			"rerun without --no-open to open the guided setup:",
			"  passfs init",
		}
	}
	if err := openFSKitExtensionSetup(); err != nil {
		return err
	}
	fmt.Fprintln(writer, "Waiting for macOS approval...")
	if err := waitForMountState(
		settings.MountPoint,
		true,
		10*time.Minute,
	); err != nil {
		return actionableError{
			err.Error(),
			"PassFS is still waiting for File System Extension approval",
			"leave the guided window open, enable PassFS, and retry:",
			"  passfs init",
		}
	}
	fmt.Fprintln(writer, "Filesystem: Apple FSKit enabled and mounted.")
	return nil
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
		"install macFUSE, then rerun:",
		"  passfs init",
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

func guidePlatformFilesystemSetup(writer io.Writer, openSettings bool) error {
	if major, err := macOSMajorVersion(); err == nil && major < 26 {
		return guidePlatformFUSESetup(writer, openSettings)
	}
	writeSetupLines(
		writer,
		"PassFS includes a native Apple FSKit adapter on macOS 26 or later.",
		"Install PassFS.app, then enable passfs under File System Extensions",
		"in System Settings.",
		"",
		"This adapter does not require macFUSE or reduced system security.",
		"After enabling it, run:",
		"  passfs doctor",
		"  passfs mount --adapter fskit",
		"",
		"On older macOS releases, macFUSE remains available as a fallback:",
		"  "+macFUSEURL,
	)
	if !openSettings {
		return nil
	}
	if err := openFSKitExtensionSetup(); err != nil {
		return err
	}
	fmt.Fprintln(writer, "Opened the PassFS extension control.")
	return nil
}

func embeddedFSKitExtensionPath() (string, error) {
	executable, err := currentExecutable()
	if err != nil {
		return "", err
	}
	return embeddedFSKitExtensionPathForExecutable(executable)
}

func embeddedFSKitExtensionPathForExecutable(
	executable string,
) (string, error) {
	contents, err := passFSContentsPathForExecutable(executable)
	if err != nil {
		return "", err
	}
	return filepath.Join(
		contents,
		"Extensions",
		"PassFSFileSystem.appex",
	), nil
}

func guidePlatformPromptSetup(io.Writer) error {
	return nil
}

func platformMountWaitError(err error, logHint string) error {
	return actionableError{
		err.Error(),
		"macFUSE is installed but the filesystem did not become ready",
		"complete any approval requested in System Settings and restart macOS if requested",
		"then retry with:",
		"  passfs init",
		"service log: " + logHint,
	}
}
