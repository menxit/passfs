//go:build linux

package main

import "passfs/internal/passfs"

func uiTouchIDEnabled(*passfs.Settings) bool {
	return false
}
