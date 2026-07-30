package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"passfs/internal/updater"
)

func TestCachedUpdateStatusReportsOnlyNewerVersion(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "update.json")
	if err := updater.SaveState(statePath, updater.State{
		CheckedAt: time.Now(),
		Available: "0.3.1",
	}); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		current string
		want    string
	}{
		{current: "0.1.0", want: "0.3.1"},
		{current: "0.3.1", want: ""},
		{current: "0.4.0", want: ""},
	} {
		var output bytes.Buffer
		if err := writeCachedUpdateStatus(
			statePath,
			test.current,
			&output,
		); err != nil {
			t.Fatalf("current %s: %v", test.current, err)
		}
		var status cachedUpdateStatus
		if err := json.Unmarshal(output.Bytes(), &status); err != nil {
			t.Fatalf("current %s: decode %q: %v", test.current, output.String(), err)
		}
		if status.Available != test.want {
			t.Fatalf(
				"current %s: available = %q, want %q",
				test.current,
				status.Available,
				test.want,
			)
		}
	}
}

func TestCachedUpdateStatusTreatsMissingOrInvalidStateAsUnavailable(
	t *testing.T,
) {
	for _, statePath := range []string{
		filepath.Join(t.TempDir(), "missing.json"),
		filepath.Join(t.TempDir(), "invalid.json"),
	} {
		if filepath.Base(statePath) == "invalid.json" {
			if err := updater.SaveState(statePath, updater.State{
				Available: "not-a-version",
			}); err != nil {
				t.Fatal(err)
			}
		}
		var output bytes.Buffer
		if err := writeCachedUpdateStatus(
			statePath,
			"0.1.0",
			&output,
		); err != nil {
			t.Fatal(err)
		}
		if output.String() != "{}\n" {
			t.Fatalf("status = %q, want empty JSON object", output.String())
		}
	}
}
