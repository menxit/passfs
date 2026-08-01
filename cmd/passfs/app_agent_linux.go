//go:build linux

package main

import (
	"errors"
	"io"
)

func runPlatformAppAgent(io.Writer) error {
	return errors.New("the PassFS app control agent is only available on macOS")
}
