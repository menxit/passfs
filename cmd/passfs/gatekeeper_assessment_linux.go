//go:build linux

package main

import (
	"errors"
	"io"
)

func runGatekeeperAssessment([]string, io.Writer) error {
	return errors.New("Gatekeeper assessment is only available on macOS")
}
