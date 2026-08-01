//go:build darwin

package main

import "passfs/internal/passfs"

func uiTouchIDEnabled(settings *passfs.Settings) bool {
	if !settings.TouchID {
		return false
	}
	configured, err := passfs.TouchIDConfigured(settings.Vault)
	return err == nil && configured
}
