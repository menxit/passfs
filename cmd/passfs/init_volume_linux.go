//go:build linux

package main

import (
	"context"

	"passfs/internal/passfs"
)

func initVolumeWithPlatformDefaults(
	ctx context.Context,
	vault string,
	prompter passfs.Prompter,
	_ bool,
) (enabled bool, warning error, err error) {
	return false, nil, passfs.InitVolume(ctx, vault, prompter)
}
