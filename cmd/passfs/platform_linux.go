//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
	"passfs/internal/passfs"
)

func launchPlatformApp() (bool, error) {
	return false, nil
}

func platformFilesystemAdapters() []filesystemAdapter {
	return []filesystemAdapter{fuseFilesystemAdapter{}}
}

func platformAutomaticFilesystemAdapters(
	adapters []filesystemAdapter,
) []filesystemAdapter {
	return adapters
}

func preparePlatformFilesystemForInit(
	_ *passfs.Settings,
	_ string,
	_ io.Writer,
) error {
	return nil
}

func platformFilesystemApprovalRequired(string, string, int64) bool {
	return false
}

func completePlatformFilesystemApproval(
	_ *passfs.Settings,
	adapterName string,
	_ bool,
	_ io.Writer,
) error {
	return fmt.Errorf(
		"filesystem approval is not supported for adapter %q on Linux",
		adapterName,
	)
}

func platformFUSECapability() platformCapability {
	info, err := os.Stat("/dev/fuse")
	if err != nil {
		return platformCapability{
			name:   "FUSE",
			detail: "/dev/fuse is unavailable",
		}
	}
	if info.Mode()&os.ModeDevice == 0 {
		return platformCapability{
			name:   "FUSE",
			detail: "/dev/fuse is not a device",
		}
	}
	if err := unix.Access("/dev/fuse", unix.R_OK|unix.W_OK); err != nil {
		return platformCapability{
			name:   "FUSE",
			detail: "/dev/fuse is not accessible to this user",
		}
	}
	if _, err := linuxFUSEMountHelper(); err != nil {
		return platformCapability{
			name:   "FUSE",
			detail: "fusermount3 or fusermount is unavailable",
		}
	}
	return platformCapability{
		name:   "FUSE",
		ready:  true,
		detail: "/dev/fuse and the mount helper are available",
	}
}

func linuxFUSEMountHelper() (string, error) {
	for _, candidate := range []string{"fusermount3", "fusermount"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", exec.ErrNotFound
}

func platformPromptCapability() platformCapability {
	if helper := passfs.LinuxGraphicalPromptHelper(); helper != "" {
		return platformCapability{
			name:   "Prompt",
			ready:  true,
			detail: "desktop dialog via " + helper + ", terminal UI fallback available",
		}
	}
	if passfs.LinuxGraphicalSession() {
		return platformCapability{
			name:   "Prompt",
			detail: "desktop detected but zenity, kdialog, yad, or qarma is missing",
		}
	}
	return platformCapability{
		name:   "Prompt",
		ready:  true,
		detail: "terminal UI selected for this non-graphical session",
	}
}

func platformFUSEError(capability platformCapability) error {
	if _, err := linuxFUSEMountHelper(); err != nil {
		installCommand, commandErr := linuxPackageInstallCommand("fuse3")
		if commandErr == nil {
			return actionableError{
				"FUSE is required before passfs can mount its filesystem: " + capability.detail,
				"install it with the detected package manager:",
				"  " + installCommand,
				"then rerun:",
				"  passfs init",
			}
		}
		return actionableError{
			"FUSE is required before passfs can mount its filesystem: " + capability.detail,
			"install the fuse3 package for this distribution, then rerun:",
			"  passfs init",
		}
	}
	return actionableError{
		"FUSE userspace tools are installed, but passfs cannot use the device: " + capability.detail,
		"do not reinstall fuse3; make /dev/fuse accessible to this process",
		"for Docker, start the container with:",
		"  --device /dev/fuse --cap-add SYS_ADMIN",
		"then rerun:",
		"  passfs init",
	}
}

func guidePlatformFUSESetup(writer io.Writer, _ bool) error {
	if _, err := linuxFUSEMountHelper(); err != nil {
		installCommand, commandErr := linuxPackageInstallCommand("fuse3")
		if commandErr != nil {
			return actionableError{
				"could not detect a supported Linux package manager",
				"install the fuse3 package for this distribution, then run:",
				"  passfs doctor",
				"  passfs mount",
			}
		}
		writeSetupLines(
			writer,
			"Install FUSE with the detected package manager:",
			"  "+installCommand,
		)
	} else {
		writeSetupLines(
			writer,
			"FUSE userspace tools are installed, but /dev/fuse is unavailable or inaccessible.",
			"On a Linux host, load the fuse kernel module and check /dev/fuse permissions.",
			"In a container, explicitly expose /dev/fuse and the required FUSE capabilities.",
		)
	}
	if err := guidePlatformPromptSetup(writer); err != nil {
		return err
	}
	writeSetupLines(
		writer,
		"",
		"Then run:",
		"  passfs doctor",
		"  passfs mount",
	)
	return nil
}

func guidePlatformFilesystemSetup(writer io.Writer, open bool) error {
	return guidePlatformFUSESetup(writer, open)
}

func guidePlatformPromptSetup(writer io.Writer) error {
	if prompt := platformPromptCapability(); prompt.ready {
		return nil
	}
	dialogCommand, err := linuxPackageInstallCommand("zenity")
	fmt.Fprintln(writer)
	if err == nil {
		fmt.Fprintln(writer, "Install the graphical password dialog with:")
		fmt.Fprintln(writer, "  "+dialogCommand)
		return nil
	}
	fmt.Fprintln(writer, "Install zenity or kdialog for graphical password dialogs.")
	return nil
}

func platformMountWaitError(err error, logHint string) error {
	return actionableError{
		err.Error(),
		"the Linux FUSE filesystem did not become ready",
		"verify the kernel device and permissions, then retry:",
		"  passfs init",
		"service log: " + logHint,
	}
}

func linuxPackageInstallCommand(packageName string) (string, error) {
	return linuxPackageInstallCommandWithLookup(packageName, exec.LookPath)
}

func linuxPackageInstallCommandWithLookup(
	packageName string,
	lookPath func(string) (string, error),
) (string, error) {
	type packageManager struct {
		binary    string
		arguments string
	}
	for _, manager := range []packageManager{
		{binary: "apt-get", arguments: "sudo apt-get install "},
		{binary: "dnf", arguments: "sudo dnf install "},
		{binary: "yum", arguments: "sudo yum install "},
		{binary: "zypper", arguments: "sudo zypper install "},
		{binary: "pacman", arguments: "sudo pacman -S "},
		{binary: "apk", arguments: "sudo apk add "},
	} {
		if _, err := lookPath(manager.binary); err == nil {
			return manager.arguments + packageName, nil
		}
	}
	return "", exec.ErrNotFound
}
