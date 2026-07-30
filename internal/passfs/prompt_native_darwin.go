//go:build darwin

package passfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type NativePrompter struct {
	mu sync.Mutex
}

func NewNativePrompter() (Prompter, error) {
	if _, err := exec.LookPath("/usr/bin/osascript"); err != nil {
		return nil, errors.New("osascript is required for background passphrase prompts")
	}
	return &NativePrompter{}, nil
}

func (p *NativePrompter) Prompt(ctx context.Context, request PromptRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	const script = `on run argv
set requestText to item 1 of argv
set iconPath to item 2 of argv
set promptText to "Enter your PassFS passphrase to authorize this operation." & return & return & requestText & return & return & "Your passphrase is processed only on this Mac and is never stored or transmitted."
try
	set response to display dialog promptText default answer "" with hidden answer buttons {"Cancel", "Authorize"} default button "Authorize" cancel button "Cancel" with title "PassFS Security" with icon POSIX file iconPath
	return text returned of response
on error number -128
	error number -128
end try
end run`
	command := exec.CommandContext(
		ctx,
		"/usr/bin/osascript",
		"-e",
		script,
		DescribePrompt(request),
		passFSDialogIconPath(),
	)
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) &&
			(strings.Contains(string(exitError.Stderr), "-128") ||
				strings.Contains(strings.ToLower(string(exitError.Stderr)), "canceled")) {
			return "", ErrPromptCancelled
		}
		return "", fmt.Errorf("show passphrase dialog: %w", err)
	}
	passphrase := strings.TrimRight(string(output), "\r\n")
	if passphrase == "" {
		return "", ErrPromptCancelled
	}
	return passphrase, nil
}

func passFSDialogIconPath() string {
	executable, err := os.Executable()
	if err == nil {
		if icon := passFSDialogIconPathForExecutable(executable); icon != "" {
			return icon
		}
	}
	return "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/LockedIcon.icns"
}

func passFSDialogIconPathForExecutable(executable string) string {
	directory := filepath.Dir(executable)
	for range 10 {
		if filepath.Base(directory) == "Contents" {
			candidate := filepath.Join(directory, "Resources", "PassFS.icns")
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return filepath.Clean(candidate)
			}
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return ""
}
