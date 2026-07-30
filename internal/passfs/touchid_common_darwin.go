//go:build darwin

package passfs

import (
	"errors"
	"time"
)

const touchIDPromptTimeout = 45 * time.Second

var (
	ErrTouchIDTimeout          = errors.New("touch ID authorization timed out")
	ErrTouchIDUnsupportedBuild = errors.New(
		"this passfs build cannot use Touch ID; macOS requires a signed app bundle with Keychain entitlements",
	)
)
