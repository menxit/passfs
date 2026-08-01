//go:build darwin

package main

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"strings"
)

type gatekeeperAssessment struct {
	Accepted bool   `json:"accepted"`
	Detail   string `json:"detail"`
}

func runGatekeeperAssessment(arguments []string, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("invalid Gatekeeper assessment request")
	}
	executable, err := currentExecutable()
	if err != nil {
		return err
	}
	appPath, err := passFSAppPathForExecutable(executable)
	if err != nil {
		return err
	}
	output, assessmentErr := exec.Command(
		"/usr/sbin/spctl",
		"--assess",
		"--type",
		"execute",
		"--verbose=4",
		appPath,
	).CombinedOutput()
	detail := strings.TrimSpace(string(output))
	if detail == "" && assessmentErr != nil {
		detail = assessmentErr.Error()
	}
	if detail == "" {
		detail = "no assessment details"
	}
	return writeJSON(stdout, gatekeeperAssessment{
		Accepted: assessmentErr == nil,
		Detail:   string(bytes.ToValidUTF8([]byte(detail), []byte("?"))),
	})
}
