package passfs

import (
	"bufio"
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

func TestPromptDescriptionIncludesPID(t *testing.T) {
	got := DescribePrompt(PromptRequest{
		Path:      "/project/.env",
		Operation: "read",
		PID:       1234,
	})
	for _, expected := range []string{"read", "/project/.env", "1234"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("prompt %q does not include %q", got, expected)
		}
	}
}
