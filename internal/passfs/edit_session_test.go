package passfs

import "testing"

func TestParseSessionCommand(t *testing.T) {
	const sessionID = "0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		value     string
		operation string
	}{
		{value: sessionBegin + sessionID, operation: "begin"},
		{value: sessionEnd + sessionID, operation: "end"},
	} {
		operation, parsedToken, err := parseSessionCommand([]byte(test.value))
		if err != nil {
			t.Fatalf("parseSessionCommand(%q): %v", test.value, err)
		}
		if operation != test.operation || parsedToken != sessionID {
			t.Fatalf(
				"parseSessionCommand(%q) = %q, %q",
				test.value,
				operation,
				parsedToken,
			)
		}
	}
}

func TestParseSessionCommandRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{
		"",
		"begin:",
		"unknown:0123456789abcdef0123456789abcdef",
		"begin:not-hexadecimal-token-value!!",
		"end:0123456789abcdef",
	} {
		if _, _, err := parseSessionCommand([]byte(value)); err == nil {
			t.Fatalf("parseSessionCommand(%q) succeeded", value)
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
