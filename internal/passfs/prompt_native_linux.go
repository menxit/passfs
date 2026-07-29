//go:build linux

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
	return &NativePrompter{}, nil
}

func LinuxGraphicalSession() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

func LinuxGraphicalPromptHelper() string {
	helper, _ := findLinuxGraphicalPromptHelper(exec.LookPath)
	return helper
}

func findLinuxGraphicalPromptHelper(
	lookPath func(string) (string, error),
) (string, error) {
	for _, candidate := range []string{"zenity", "kdialog", "yad", "qarma"} {
		if path, err := lookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", exec.ErrNotFound
}

func (p *NativePrompter) Prompt(
	ctx context.Context,
	request PromptRequest,
) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var graphicalErr error
	if LinuxGraphicalSession() {
		if helper := LinuxGraphicalPromptHelper(); helper != "" {
			passphrase, err := promptLinuxGraphical(ctx, helper, request)
			if err == nil || errors.Is(err, ErrPromptCancelled) {
				return passphrase, err
			}
			graphicalErr = err
		}
	}

	requestPID := request.PID
	if requestPID == 0 {
		requestPID = uint32(os.Getpid())
	}
	terminal, path, err := openProcessTerminal(requestPID)
	if err == nil {
		defer terminal.Close()
		return promptLinuxTerminal(ctx, terminal, request)
	}

	detail := fmt.Errorf(
		"no interactive terminal is attached to process %d: %w",
		requestPID,
		err,
	)
	if LinuxGraphicalSession() && LinuxGraphicalPromptHelper() == "" {
		detail = fmt.Errorf(
			"desktop password dialog unavailable; install zenity or kdialog: %w",
			detail,
		)
	}
	if graphicalErr != nil {
		detail = errors.Join(graphicalErr, detail)
	}
	if path != "" {
		detail = fmt.Errorf("open terminal %s: %w", path, detail)
	}
	return "", detail
}

func promptLinuxGraphical(
	ctx context.Context,
	helper string,
	request PromptRequest,
) (string, error) {
	name := filepath.Base(helper)
	description := DescribePrompt(request)
	var arguments []string
	switch name {
	case "kdialog":
		arguments = []string{"--title", "passfs", "--password", description}
	case "zenity", "yad", "qarma":
		arguments = []string{
			"--password",
			"--title=passfs",
			"--text=" + description,
		}
	default:
		return "", fmt.Errorf("unsupported graphical prompt helper %q", name)
	}

	command := exec.CommandContext(ctx, helper, arguments...)
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 &&
			len(strings.TrimSpace(string(exitError.Stderr))) == 0 {
			return "", ErrPromptCancelled
		}
		return "", fmt.Errorf("show password dialog with %s: %w", name, err)
	}
	passphrase := strings.TrimRight(string(output), "\r\n")
	if passphrase == "" {
		return "", ErrPromptCancelled
	}
	return passphrase, nil
}
