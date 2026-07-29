//go:build linux

package passfs

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestFindLinuxGraphicalPromptHelperUsesFirstAvailable(t *testing.T) {
	helper, err := findLinuxGraphicalPromptHelper(func(name string) (string, error) {
		if name == "kdialog" {
			return "/usr/bin/kdialog", nil
		}
		return "", errors.New("missing")
	})
	if err != nil {
		t.Fatal(err)
	}
	if helper != "/usr/bin/kdialog" {
		t.Fatalf("helper = %q", helper)
	}
}

func TestAllowedTerminalPaths(t *testing.T) {
	for _, path := range []string{"/dev/tty", "/dev/pts/4", "/dev/tty2"} {
		if !isAllowedTerminalPath(path) {
			t.Fatalf("expected terminal path %q to be allowed", path)
		}
	}
	for _, path := range []string{"/tmp/tty", "/dev/null", "../../dev/pts/4"} {
		if isAllowedTerminalPath(path) {
			t.Fatalf("unexpected terminal path %q was allowed", path)
		}
	}
}

func TestLinuxParentPIDReadsProc(t *testing.T) {
	parent, err := linuxParentPID(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if parent == 0 {
		t.Fatal("current process has no parent")
	}
}

func TestTerminalPromptMasksInputAndSanitizesControls(t *testing.T) {
	var screen strings.Builder
	if err := drawTerminalPrompt(&screen, PromptRequest{
		Description: "Read /project/\x1b[31m.env",
	}, 7, "", 120, 40); err != nil {
		t.Fatal(err)
	}
	output := screen.String()
	for _, expected := range []string{
		"PASSFS AUTHORIZATION",
		"*******",
		"Read /project/?[31m.env",
		"Esc: cancel",
		"\x1b[44;97m\x1b[2J",
		"\x1b[40;1H",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("terminal screen does not contain %q:\n%q", expected, output)
		}
	}
}

func TestTerminalPromptUsesRequestedDimensions(t *testing.T) {
	var screen strings.Builder
	if err := drawTerminalPrompt(
		&screen,
		PromptRequest{Description: "Test prompt"},
		100,
		"",
		32,
		12,
	); err != nil {
		t.Fatal(err)
	}
	output := screen.String()
	if !strings.Contains(output, "\x1b[12;1H") {
		t.Fatalf("footer was not written on the last terminal row:\n%q", output)
	}
	if !strings.Contains(output, "[...*************************]") {
		t.Fatalf("password field was not fitted to terminal width:\n%q", output)
	}
}
