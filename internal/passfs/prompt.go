package passfs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"

	"filippo.io/age"
	"golang.org/x/term"
)

var ErrPromptCancelled = errors.New("authorization cancelled")

type PromptRequest struct {
	Path        string
	Operation   string
	PID         uint32
	Description string
}

type Prompter interface {
	Prompt(context.Context, PromptRequest) (string, error)
}

type IdentityPrompter interface {
	PromptIdentity(context.Context, PromptRequest) (*age.X25519Identity, error)
}

func NewPrompter(mode, pinentryPath string) (Prompter, error) {
	switch mode {
	case "native":
		return NewNativePrompter()
	case "auto":
		if native, err := NewNativePrompter(); err == nil {
			return native, nil
		}
		if binary := findPinentry(pinentryPath); binary != "" {
			return &PinentryPrompter{Binary: binary}, nil
		}
		return &TTYPrompter{}, nil
	case "pinentry":
		binary := findPinentry(pinentryPath)
		if binary == "" {
			return nil, errors.New("pinentry not found; install it or pass --pinentry PATH")
		}
		return &PinentryPrompter{Binary: binary}, nil
	case "tty":
		return &TTYPrompter{}, nil
	default:
		return nil, fmt.Errorf("unknown prompt backend %q", mode)
	}
}

func findPinentry(explicit string) string {
	if explicit != "" {
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit
		}
		return ""
	}
	for _, candidate := range []string{
		"pinentry",
		"pinentry-mac",
		"/opt/homebrew/bin/pinentry",
		"/opt/local/bin/pinentry-mac",
		"/usr/bin/pinentry",
	} {
		if strings.ContainsRune(candidate, os.PathSeparator) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
			continue
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved
		}
	}
	return ""
}

type TTYPrompter struct {
	mu sync.Mutex
}

func (p *TTYPrompter) Prompt(ctx context.Context, request PromptRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open /dev/tty: %w", err)
	}
	defer tty.Close()

	description := DescribePrompt(request)
	if _, err := fmt.Fprintf(tty, "%s\nPassphrase: ", description); err != nil {
		return "", err
	}
	password, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if len(password) == 0 {
		return "", ErrPromptCancelled
	}
	return string(password), nil
}

type PinentryPrompter struct {
	Binary string
	mu     sync.Mutex
}

func (p *PinentryPrompter) Prompt(ctx context.Context, request PromptRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	command := exec.CommandContext(ctx, p.Binary)
	stdin, err := command.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return "", err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return "", fmt.Errorf("start pinentry: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	if _, err := readAssuanResponse(scanner); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return "", fmt.Errorf("pinentry greeting: %w", err)
	}

	for _, pinentryCommand := range []string{
		"SETTITLE " + assuanEscape("passfs"),
		"SETDESC " + assuanEscape(DescribePrompt(request)),
		"SETPROMPT " + assuanEscape("Passphrase:"),
	} {
		if _, err := sendAssuanCommand(stdin, scanner, pinentryCommand); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return "", err
		}
	}

	password, err := sendAssuanCommand(stdin, scanner, "GETPIN")
	if err != nil {
		_, _ = io.WriteString(stdin, "BYE\n")
		_ = stdin.Close()
		_ = command.Wait()
		return "", ErrPromptCancelled
	}
	_, _ = io.WriteString(stdin, "BYE\n")
	_ = stdin.Close()
	_ = command.Wait()
	if password == "" {
		return "", ErrPromptCancelled
	}
	return password, nil
}

func DescribePrompt(request PromptRequest) string {
	if request.Description != "" {
		return request.Description
	}
	actor := "passfs"
	if request.PID != 0 {
		actor = processDisplayName(request.PID)
	}
	action := promptAction(request.Operation)
	if request.Path == "" {
		return actor + " wants to " + action
	}
	return actor + " wants to " + action + " " + request.Path
}

func promptAction(operation string) string {
	switch strings.TrimSpace(strings.ToLower(operation)) {
	case "create", "encrypt":
		return "encrypt"
	case "read":
		return "read"
	case "read/write":
		return "read and modify"
	case "truncate", "write":
		return "modify"
	case "edit":
		return "edit"
	default:
		operation = strings.TrimSpace(operation)
		if operation == "" {
			return "access a protected file"
		}
		return operation
	}
}

func sendAssuanCommand(stdin io.Writer, scanner *bufio.Scanner, command string) (string, error) {
	if _, err := io.WriteString(stdin, command+"\n"); err != nil {
		return "", err
	}
	return readAssuanResponse(scanner)
}

func readAssuanResponse(scanner *bufio.Scanner) (string, error) {
	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "OK" || strings.HasPrefix(line, "OK "):
			decoded, err := url.PathUnescape(data.String())
			if err != nil {
				return "", err
			}
			return decoded, nil
		case strings.HasPrefix(line, "D "):
			data.WriteString(strings.TrimPrefix(line, "D "))
		case strings.HasPrefix(line, "ERR "):
			return "", errors.New(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", io.ErrUnexpectedEOF
}

func assuanEscape(value string) string {
	replacer := strings.NewReplacer("%", "%25", "\n", "%0A", "\r", "%0D")
	return replacer.Replace(value)
}
