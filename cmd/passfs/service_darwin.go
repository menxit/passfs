//go:build darwin

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"passfs/internal/passfs"
)

const launchAgentLabel = "com.menxit.passfs"
const launchAgentTransitionTimeout = 5 * time.Second

func installAndStartService(
	executable,
	configPath,
	adapterName string,
) error {
	plistPath, err := serviceDefinitionPath()
	if err != nil {
		return err
	}
	logPath := filepath.Join(filepath.Dir(configPath), "passfs.log")
	data, err := launchAgentDefinition(
		executable,
		configPath,
		adapterName,
		logPath,
	)
	if err != nil {
		return err
	}
	if err := passfs.WriteFileAtomic(plistPath, data, 0o600); err != nil {
		return fmt.Errorf("write launch agent: %w", err)
	}

	domain := launchAgentDomain()
	status, err := queryService()
	if err != nil {
		return err
	}
	if status.Running {
		if err := runLaunchctl(
			"bootout",
			domain+"/"+launchAgentLabel,
		); err != nil {
			current, queryErr := queryService()
			if queryErr != nil || current.Running {
				return err
			}
		}
		if err := waitForServiceRunning(
			false,
			launchAgentTransitionTimeout,
		); err != nil {
			return err
		}
	}
	if err := runLaunchctl("bootstrap", domain, plistPath); err != nil {
		// Two startup requests can briefly overlap after an application
		// upgrade. If the other request loaded this same LaunchAgent first,
		// bootstrap reports EIO even though the desired service is ready.
		current, queryErr := queryService()
		if queryErr == nil && current.Running {
			return nil
		}
		return err
	}
	return waitForServiceRunning(true, launchAgentTransitionTimeout)
}

func stopAndRemoveService() error {
	plistPath, err := serviceDefinitionPath()
	if err != nil {
		return err
	}
	status, statusErr := queryService()
	var stopErr error
	if statusErr == nil && status.Running {
		stopErr = runLaunchctl("bootout", launchAgentDomain()+"/"+launchAgentLabel)
	}
	removeErr := os.Remove(plistPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(stopErr, removeErr)
}

func stopService() error {
	status, err := queryService()
	if err != nil {
		return err
	}
	if !status.Running {
		return nil
	}
	return runLaunchctl("bootout", launchAgentDomain()+"/"+launchAgentLabel)
}

func queryService() (serviceStatus, error) {
	plistPath, err := serviceDefinitionPath()
	if err != nil {
		return serviceStatus{}, err
	}
	_, statErr := os.Stat(plistPath)
	installed := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return serviceStatus{}, statErr
	}

	_, commandErr := runServiceCommand(
		"/bin/launchctl",
		"print",
		launchAgentDomain()+"/"+launchAgentLabel,
	)
	if commandErr != nil {
		var exitError *exec.ExitError
		if errors.As(commandErr, &exitError) {
			return serviceStatus{Installed: installed}, nil
		}
		return serviceStatus{}, commandErr
	}
	return serviceStatus{Installed: installed, Running: true}, nil
}

func serviceDefinitionPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist"), nil
}

func serviceLogHint(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "passfs.log")
}

func launchAgentDomain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

func waitForServiceRunning(wantRunning bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := queryService()
		if err != nil {
			return err
		}
		if status.Running == wantRunning {
			return nil
		}
		if time.Now().After(deadline) {
			state := "start"
			if !wantRunning {
				state = "stop"
			}
			return fmt.Errorf(
				"timed out waiting for the passfs LaunchAgent to %s",
				state,
			)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func runLaunchctl(arguments ...string) error {
	output, err := runServiceCommand("/bin/launchctl", arguments...)
	if err != nil {
		return fmt.Errorf("launchctl %v: %w: %s", arguments, err, bytes.TrimSpace(output))
	}
	return nil
}

func launchAgentDefinition(
	executable,
	configPath,
	adapterName,
	logPath string,
) ([]byte, error) {
	var document bytes.Buffer
	document.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	document.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	document.WriteString(`<plist version="1.0"><dict>` + "\n")
	writePlistString(&document, "Label", launchAgentLabel)
	document.WriteString("<key>ProgramArguments</key><array>\n")
	for _, argument := range []string{
		executable,
		"serve",
		"--config",
		configPath,
		"--adapter",
		adapterName,
	} {
		document.WriteString("<string>")
		if err := xml.EscapeText(&document, []byte(argument)); err != nil {
			return nil, err
		}
		document.WriteString("</string>\n")
	}
	document.WriteString("</array>\n")
	document.WriteString("<key>RunAtLoad</key><true/>\n")
	document.WriteString("<key>KeepAlive</key><true/>\n")
	document.WriteString("<key>ThrottleInterval</key><integer>2</integer>\n")
	writePlistString(&document, "WorkingDirectory", filepath.Dir(configPath))
	writePlistString(&document, "StandardOutPath", logPath)
	writePlistString(&document, "StandardErrorPath", logPath)
	document.WriteString("</dict></plist>\n")
	return document.Bytes(), nil
}

func writePlistString(document *bytes.Buffer, key, value string) {
	document.WriteString("<key>")
	_ = xml.EscapeText(document, []byte(key))
	document.WriteString("</key><string>")
	_ = xml.EscapeText(document, []byte(value))
	document.WriteString("</string>\n")
}
