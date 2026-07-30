//go:build linux

package main

import (
	"errors"
	"io"
)

func runTouchIDHelper([]string, io.Writer, io.Writer) error {
	return errors.New("touch ID is only available on macOS")
}
