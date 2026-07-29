package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passfs", "update.json")
	expected := State{
		CheckedAt:    time.Date(2026, 7, 29, 18, 0, 0, 0, time.UTC),
		Available:    "1.2.3",
		LastNotified: "1.2.3",
	}
	if err := SaveState(path, expected); err != nil {
		t.Fatal(err)
	}
	actual, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual.CheckedAt != expected.CheckedAt ||
		actual.Available != expected.Available ||
		actual.LastNotified != expected.LastNotified {
		t.Fatalf("state = %#v, want %#v", actual, expected)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("update state mode = %o, want 600", info.Mode().Perm())
	}
}
