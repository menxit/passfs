//go:build linux

package main

import (
	"errors"
	"io"
)

func runTouchID([]string, io.Writer, io.Writer) error {
	return errors.New("touch ID is available only on macOS")
}
