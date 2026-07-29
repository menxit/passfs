//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"passfs/internal/passfs"
)

const systemdUnitName = "passfs.service"

func installAndStartService(executable, configPath string) error {
	unitPath, err := serviceDefinitionPath()
	if err != nil {
		return err
	}
	data, err := systemdUnitDefinition(executable, configPath)
	if err != nil {
		return err
	}
	if err := passfs.WriteFileAtomic(unitPath, data, 0o600); err != nil {
		return fmt.Errorf("write systemd user unit: %w", err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if err := runSystemctl("enable", systemdUnitName); err != nil {
		return err
	}
	if err := importGraphicalEnvironment(); err != nil {
		return err
	}
	return runSystemctl("restart", systemdUnitName)
}

func stopAndRemoveService() error {
	unitPath, err := serviceDefinitionPath()
	if err != nil {
		return err
	}
	stopErr := runSystemctl("disable", "--now", systemdUnitName)
	removeErr := os.Remove(unitPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	reloadErr := runSystemctl("daemon-reload")
	return errors.Join(stopErr, removeErr, reloadErr)
}

func stopService() error {
	status, err := queryService()
	if err != nil {
		return err
	}
	if !status.Running {
		return nil
	}
	return runSystemctl("stop", systemdUnitName)
}

func queryService() (serviceStatus, error) {
	unitPath, err := serviceDefinitionPath()
	if err != nil {
		return serviceStatus{}, err
	}
	_, statErr := os.Stat(unitPath)
	installed := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return serviceStatus{}, statErr
	}

	command := exec.Command("systemctl", "--user", "is-active", "--quiet", systemdUnitName)
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return serviceStatus{Installed: installed}, nil
		}
		return serviceStatus{}, err
	}
	return serviceStatus{Installed: installed, Running: true}, nil
}

func serviceDefinitionPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user", systemdUnitName), nil
}

func serviceLogHint(configPath string) string {
	return "`journalctl --user -u passfs.service`"
}

func runSystemctl(arguments ...string) error {
	commandArguments := append([]string{"--user"}, arguments...)
	command := exec.Command("systemctl", commandArguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v: %w: %s", arguments, err, bytes.TrimSpace(output))
	}
	return nil
}

func importGraphicalEnvironment() error {
	var names []string
	for _, name := range []string{
		"DISPLAY",
		"WAYLAND_DISPLAY",
		"XAUTHORITY",
		"DBUS_SESSION_BUS_ADDRESS",
		"XDG_CURRENT_DESKTOP",
	} {
		if os.Getenv(name) != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	arguments := append([]string{"import-environment"}, names...)
	return runSystemctl(arguments...)
}

func systemdUnitDefinition(executable, configPath string) ([]byte, error) {
	execStart, err := systemdQuote(executable)
	if err != nil {
		return nil, err
	}
	config, err := systemdQuote(configPath)
	if err != nil {
		return nil, err
	}
	unit := `[Unit]
Description=passfs encrypted filesystem
After=graphical-session.target

[Service]
Type=simple
ExecStart=` + execStart + ` serve --config ` + config + `
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`
	return []byte(unit), nil
}

func systemdQuote(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("systemd argument contains unsupported control characters")
	}
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`, nil
}
