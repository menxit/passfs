//go:build darwin

package passfs

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
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
set promptText to item 1 of argv
try
	set response to display dialog promptText default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel" with title "passfs"
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
