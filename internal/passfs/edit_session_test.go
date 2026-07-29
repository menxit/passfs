package passfs

import "testing"

func TestParseEditSessionCommand(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		value     string
		operation string
	}{
		{value: editSessionBegin + token, operation: "begin"},
		{value: editSessionEnd + token, operation: "end"},
	} {
		operation, parsedToken, err := parseEditSessionCommand([]byte(test.value))
		if err != nil {
			t.Fatalf("parseEditSessionCommand(%q): %v", test.value, err)
		}
		if operation != test.operation || parsedToken != token {
			t.Fatalf(
				"parseEditSessionCommand(%q) = %q, %q",
				test.value,
				operation,
				parsedToken,
			)
		}
	}
}

func TestParseEditSessionCommandRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{
		"",
		"begin:",
		"unknown:0123456789abcdef0123456789abcdef",
		"begin:not-hexadecimal-token-value!!",
		"end:0123456789abcdef",
	} {
		if _, _, err := parseEditSessionCommand([]byte(value)); err == nil {
			t.Fatalf("parseEditSessionCommand(%q) succeeded", value)
		}
	}
}

func TestStableInodeIsDeterministicAndPathSpecific(t *testing.T) {
	first := stableInode("files/Users/menxit/project/.env")
	if first < 2 {
		t.Fatalf("stable inode = %d", first)
	}
	if repeated := stableInode("files/Users/menxit/project/.env"); repeated != first {
		t.Fatalf("stable inode changed from %d to %d", first, repeated)
	}
	if other := stableInode("files/Users/menxit/project/other.env"); other == first {
		t.Fatalf("different paths received inode %d", first)
	}
}
