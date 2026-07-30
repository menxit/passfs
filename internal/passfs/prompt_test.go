package passfs

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestReadAssuanResponse(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader("S QUALITY 100\nD p%40ss%25word\nOK\n"))
	value, err := readAssuanResponse(scanner)
	if err != nil {
		t.Fatalf("readAssuanResponse: %v", err)
	}
	if value != "p@ss%word" {
		t.Fatalf("value = %q", value)
	}
}

func TestAssuanEscape(t *testing.T) {
	if got, want := assuanEscape("line 1\n100%"), "line 1%0A100%25"; got != want {
		t.Fatalf("assuanEscape = %q, want %q", got, want)
	}
}

func TestPromptDescriptionNamesRequestingSoftware(t *testing.T) {
	pid := uint32(os.Getpid())
	got := DescribePrompt(PromptRequest{
		Path:      "/project/.env",
		Operation: "read",
		PID:       pid,
	})
	want := processDisplayName(pid) + " wants to read /project/.env"
	if got != want {
		t.Fatalf("DescribePrompt = %q, want %q", got, want)
	}
}

func TestPromptDescriptionUsesConciseOperationNames(t *testing.T) {
	tests := []struct {
		operation string
		want      string
	}{
		{operation: "create", want: "passfs wants to encrypt /project/.env"},
		{operation: "read/write", want: "passfs wants to read and modify /project/.env"},
		{operation: "truncate", want: "passfs wants to modify /project/.env"},
	}
	for _, test := range tests {
		got := DescribePrompt(PromptRequest{
			Path:      "/project/.env",
			Operation: test.operation,
		})
		if got != test.want {
			t.Errorf("DescribePrompt(%q) = %q, want %q", test.operation, got, test.want)
		}
	}
}

func TestPromptExplicitDescriptionIsPreserved(t *testing.T) {
	const description = "Choose the passphrase for the new passfs volume"
	if got := DescribePrompt(PromptRequest{Description: description}); got != description {
		t.Fatalf("DescribePrompt = %q, want %q", got, description)
	}
}

func TestBiometricReasonIsARequestedLocalizedAction(t *testing.T) {
	request := PromptRequest{
		Path:      "/Users/example/.env",
		Operation: "read/write",
	}
	if got, want := DescribeBiometricReason(
		request,
		"it-IT",
	), "aprire e modificare il file protetto /Users/example/.env"; got != want {
		t.Fatalf("Italian biometric reason = %q, want %q", got, want)
	}
	if got, want := DescribeBiometricReason(
		request,
		"en-US",
	), "open and modify the protected file /Users/example/.env"; got != want {
		t.Fatalf("English biometric reason = %q, want %q", got, want)
	}
}

func TestSanitizeProcessName(t *testing.T) {
	if got, want := sanitizeProcessName("/usr/bin/no\x1b[31mde\n"), "no[31mde"; got != want {
		t.Fatalf("sanitizeProcessName = %q, want %q", got, want)
	}
	if got, want := sanitizeProcessName(
		"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
	), "Visual Studio Code"; got != want {
		t.Fatalf("sanitizeProcessName app = %q, want %q", got, want)
	}
}
