//go:build darwin

package passfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
)

const maxTouchIDHelperOutput = 1024

type TouchIDHelperPrompter struct {
	executable string
	vault      string
	timeout    time.Duration
	mu         sync.Mutex
}

func NewTouchIDServicePrompter(vault string) (Prompter, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve passfs executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, fmt.Errorf("resolve passfs executable links: %w", err)
	}
	return &TouchIDHelperPrompter{
		executable: executable,
		vault:      vault,
		timeout:    touchIDPromptTimeout,
	}, nil
}

func (p *TouchIDHelperPrompter) Prompt(
	context.Context,
	PromptRequest,
) (string, error) {
	return "", errors.New("touch ID provides an age identity, not a passphrase")
}

func (p *TouchIDHelperPrompter) PromptIdentity(
	ctx context.Context,
	request PromptRequest,
) (*age.X25519Identity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	timeout := p.timeout
	if timeout <= 0 {
		timeout = touchIDPromptTimeout
	}
	promptContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(
		promptContext,
		p.executable,
		"__touchid-helper",
		"--vault",
		p.vault,
		"--reason",
		describeTouchIDReason(request),
	)
	command.WaitDelay = 2 * time.Second
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(promptContext.Err(), context.DeadlineExceeded) {
			return nil, ErrTouchIDTimeout
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			return nil, fmt.Errorf("touch ID helper: %w", err)
		}
		return nil, fmt.Errorf("touch ID helper: %w: %s", err, message)
	}

	secret := stdout.Bytes()
	defer wipe(secret)
	if len(secret) == 0 || len(secret) > maxTouchIDHelperOutput {
		return nil, errors.New("touch ID helper returned an invalid identity")
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(secret)))
	if err != nil {
		return nil, errors.New("touch ID helper returned an invalid identity")
	}
	return identity, nil
}

var _ Prompter = (*TouchIDHelperPrompter)(nil)
var _ IdentityPrompter = (*TouchIDHelperPrompter)(nil)
