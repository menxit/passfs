//go:build linux

package main

import "passfs/internal/passfs"

func newServicePrompter(*passfs.Settings) (passfs.Prompter, error) {
	return passfs.NewNativePrompter()
}
