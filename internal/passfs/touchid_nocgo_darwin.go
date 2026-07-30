//go:build darwin && !cgo

package passfs

import (
	"context"

	"filippo.io/age"
)

func InitVolumePreferTouchID(
	ctx context.Context,
	cipherDir string,
	prompter Prompter,
) (enabled bool, warning error, err error) {
	return false, ErrTouchIDUnsupportedBuild, InitVolume(ctx, cipherDir, prompter)
}

func NewTouchIDPrompter(string) (Prompter, error) {
	return nil, ErrTouchIDUnsupportedBuild
}

func EnableTouchID(context.Context, string, Prompter) error {
	return ErrTouchIDUnsupportedBuild
}

func DisableTouchID(string) error {
	return ErrTouchIDUnsupportedBuild
}

func TouchIDConfigured(string) (bool, error) {
	return false, ErrTouchIDUnsupportedBuild
}

func VerifyTouchID(context.Context, string) error {
	return ErrTouchIDUnsupportedBuild
}

func PrepareTouchIDUI() error {
	return ErrTouchIDUnsupportedBuild
}

func ValidateTouchIDHelperParent(int) error {
	return ErrTouchIDUnsupportedBuild
}

func TouchIDIdentity(string, string) (*age.X25519Identity, error) {
	return nil, ErrTouchIDUnsupportedBuild
}
