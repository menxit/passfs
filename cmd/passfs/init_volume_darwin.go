//go:build darwin

package main

import (
	"context"

	"passfs/internal/passfs"
)

func initVolumeWithPlatformDefaults(
	ctx context.Context,
	vault string,
	prompter passfs.Prompter,
	disableTouchID bool,
) (enabled bool, warning error, err error) {
	if disableTouchID {
		return false, nil, passfs.InitVolume(ctx, vault, prompter)
	}
	return passfs.InitVolumePreferTouchID(ctx, vault, prompter)
}
