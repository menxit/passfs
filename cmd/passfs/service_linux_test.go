//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestSystemdUnitRunsForegroundServer(t *testing.T) {
	data, err := systemdUnitDefinition(
		"/home/menxit/bin/passfs",
		"/home/menxit/.config/passfs/config.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	for _, expected := range []string{
		`ExecStart="/home/menxit/bin/passfs" serve --config "/home/menxit/.config/passfs/config.json"`,
		"Type=simple",
		"Restart=always",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, expected) {
			t.Fatalf("systemd unit does not contain %q:\n%s", expected, unit)
		}
	}
}
