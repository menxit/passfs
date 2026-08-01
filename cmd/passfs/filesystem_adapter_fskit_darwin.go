//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"passfs/internal/passfs"
)

const fsKitExtensionBundleID = "com.menxit.passfs.filesystem"

const liveFSSettingsPath = "/Library/Application Support/livefsd/settings.plist"

const (
	mountLifecycleSafetyInterval   = time.Hour
	mountLifecycleFallbackInterval = time.Minute
)

type fsKitFilesystemAdapter struct{}

func (fsKitFilesystemAdapter) Name() string {
	return adapterFSKit
}

func (fsKitFilesystemAdapter) Capability() platformCapability {
	if major, err := macOSMajorVersion(); err != nil || major < 26 {
		detail := "requires macOS 26 or later"
		if err != nil {
			detail = "could not determine the macOS version"
		}
		return platformCapability{name: "FSKit", detail: detail}
	}
	if info, err := os.Stat("/sbin/mount"); err != nil ||
		info.IsDir() ||
		info.Mode()&0o111 == 0 {
		return platformCapability{
			name:   "FSKit",
			detail: "the macOS mount tool is unavailable",
		}
	}

	extensionPath, err := embeddedFSKitExtensionPath()
	if err != nil {
		return platformCapability{
			name:   "FSKit",
			detail: "the PassFS File System Extension is not installed",
		}
	}
	if !fsKitExtensionInstalled(extensionPath) {
		return platformCapability{
			name:   "FSKit",
			detail: "the PassFS File System Extension is not installed",
		}
	}
	return platformCapability{
		name:   "FSKit",
		ready:  true,
		detail: "PassFS File System Extension included; approval is checked when mounting",
	}
}

func (fsKitFilesystemAdapter) ValidateSettings(*passfs.Settings) error {
	return nil
}

func (fsKitFilesystemAdapter) SupportsProcessSessions() bool {
	return false
}

func (fsKitFilesystemAdapter) RegisterProtectedLink(
	settings *passfs.Settings,
	sourcePath string,
	targetPath string,
) error {
	return passfs.RegisterProtectedLinkInVault(
		settings.Vault,
		settings.MountPoint,
		sourcePath,
		targetPath,
	)
}

func (fsKitFilesystemAdapter) UnavailableError(
	capability platformCapability,
) error {
	return actionableError{
		"the native FSKit adapter is unavailable: " + capability.detail,
		"install and open PassFS.app, then enable its File System Extension",
		"using the Apple extension control shown by PassFS",
		"then rerun:",
		"  passfs init",
	}
}

func (fsKitFilesystemAdapter) MountWaitError(
	err error,
	logHint string,
	mountPoint string,
) error {
	if liveFSHasMountRegistration(mountPoint) {
		return actionableError{
			err.Error(),
			"macOS retained a stale FSKit mount registration for " +
				terminalPath(mountPoint),
			"restart your Mac to reset the FSKit mount state, then rerun:",
			"  passfs init",
			"service log: " + logHint,
		}
	}
	return actionableError{
		err.Error(),
		"the native FSKit filesystem did not become ready",
		"verify that the PassFS File System Extension is enabled, then rerun:",
		"  passfs init",
		"service log: " + logHint,
	}
}

func liveFSHasMountRegistration(mountPoint string) bool {
	output, err := exec.Command(
		"/usr/bin/plutil",
		"-extract",
		"mounts",
		"json",
		"-o",
		"-",
		liveFSSettingsPath,
	).Output()
	return err == nil &&
		liveFSMountRegistrationsContain(output, mountPoint)
}

func liveFSMountRegistrationsContain(
	output []byte,
	mountPoint string,
) bool {
	var registrations []struct {
		MountedOn string `json:"mountedOn"`
	}
	if err := json.Unmarshal(output, &registrations); err != nil {
		return false
	}
	mountPoint = filepath.Clean(mountPoint)
	for _, registration := range registrations {
		if filepath.Clean(registration.MountedOn) == mountPoint {
			return true
		}
	}
	return false
}

func (fsKitFilesystemAdapter) Serve(
	settings *passfs.Settings,
	maxFileSize int64,
	debug bool,
	stderr io.Writer,
) error {
	serviceContext, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	prepared, err := prepareFilesystemService(
		serviceContext,
		settings,
		maxFileSize,
		stderr,
	)
	if err != nil {
		return err
	}
	linkSynchronizer := prepared.synchronizer
	logger := prepared.logger
	unlockFor := prepared.unlockFor
	defer linkSynchronizer.Close()
	authorization := "touchid"
	if !settings.TouchID {
		authorization = "passphrase"
		broker, err := passfs.StartFSKitPassphraseBroker(
			settings.Vault,
			prepared.prompter,
		)
		if err != nil {
			return fmt.Errorf("start FSKit passphrase broker: %w", err)
		}
		defer broker.Close()
	}
	options := []string{
		"nobrowse",
		"max-file-size=" + strconv.FormatInt(maxFileSize, 10),
		"unlock-duration-ns=" + strconv.FormatInt(int64(unlockFor), 10),
		"authorization=" + authorization,
	}
	if debug {
		options = append(options, "debug")
	}
	command := exec.Command(
		"/sbin/mount",
		"-t",
		"passfs",
		"-o",
		strings.Join(options, ","),
		settings.Vault,
		settings.MountPoint,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		return fmt.Errorf(
			"mount passfs at %s with FSKit: %w: %s",
			terminalPath(settings.MountPoint),
			err,
			detail,
		)
	}
	if err := waitForMountState(
		settings.MountPoint,
		true,
		serviceWaitTimeout,
	); err != nil {
		return err
	}
	linkSyncDone := make(chan struct{})
	go func() {
		defer close(linkSyncDone)
		linkSynchronizer.Run(serviceContext)
	}()
	defer func() {
		cancelService()
		<-linkSyncDone
	}()

	startUpdateMonitor(serviceContext, logger)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	for {
		watcher, watchErr := newMountLifecycleWatcher(settings.MountPoint)
		interval := mountLifecycleSafetyInterval
		var changed <-chan error
		if watchErr == nil {
			changed = watcher.change
		} else {
			interval = mountLifecycleFallbackInterval
			logger.Printf(
				"watch mount lifecycle; using periodic status checks: %v",
				watchErr,
			)
		}
		timer := time.NewTimer(interval)
		select {
		case <-signals:
			timer.Stop()
			if watcher != nil {
				_ = watcher.close()
			}
			if err := passfs.UnmountPath(settings.MountPoint); err != nil {
				return fmt.Errorf("unmount native passfs filesystem: %w", err)
			}
			return nil
		case err := <-changed:
			if err != nil {
				logger.Printf("watch mount lifecycle: %v", err)
			}
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if watcher != nil {
			_ = watcher.close()
		}
		mounted, adapter, err := passfs.MountAdapterStatus(settings.MountPoint)
		if err != nil {
			return err
		}
		if !mounted {
			return nil
		}
		if adapter == passfs.MountAdapterUnknown {
			return fmt.Errorf(
				"%s was replaced by another filesystem",
				terminalPath(settings.MountPoint),
			)
		}
	}
}

func fsKitExtensionInstalled(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func macOSMajorVersion() (int, error) {
	output, err := exec.Command(
		"/usr/bin/sw_vers",
		"-productVersion",
	).Output()
	if err != nil {
		return 0, err
	}
	return parseMacOSMajorVersion(string(output))
}

func parseMacOSMajorVersion(version string) (int, error) {
	component := strings.SplitN(strings.TrimSpace(version), ".", 2)[0]
	major, err := strconv.Atoi(component)
	if err != nil {
		return 0, fmt.Errorf("parse macOS version %q: %w", component, err)
	}
	return major, nil
}
