//go:build darwin

package main

import "passfs/internal/passfs"

func newServicePrompter(settings *passfs.Settings) (passfs.Prompter, error) {
	if settings.TouchID {
		return passfs.NewTouchIDServicePrompter(settings.Vault)
	}
	return passfs.NewNativePrompter()
}
