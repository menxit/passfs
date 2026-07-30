//go:build darwin

package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestLaunchAgentRunsForegroundServer(t *testing.T) {
	data, err := launchAgentDefinition(
		"/Applications/passfs & tools/passfs",
		"/Users/menxit/.config/passfs/config.json",
		"fskit",
		"/Users/menxit/.config/passfs/passfs.log",
	)
	if err != nil {
		t.Fatal(err)
	}
	document := string(data)
	for _, expected := range []string{
		"<string>/Applications/passfs &amp; tools/passfs</string>",
		"<string>serve</string>",
		"<string>--config</string>",
		"<string>--adapter</string>",
		"<string>fskit</string>",
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key><true/>",
	} {
		if !strings.Contains(document, expected) {
			t.Fatalf("launch agent does not contain %q:\n%s", expected, document)
		}
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		if _, err := decoder.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("invalid launch agent XML: %v", err)
		}
	}
}
