package main

import (
	"io"

	"passfs/internal/passfs"
)

type platformCapability struct {
	name   string
	ready  bool
	detail string
}

func requirePlatformFUSE() error {
	capability := platformFUSECapability()
	if capability.ready {
		return nil
	}
	return platformFUSEError(capability)
}

func newDiagnosticPrompter(settings *passfs.Settings) (passfs.Prompter, error) {
	if settings != nil {
		return newServicePrompter(settings)
	}
	return passfs.NewNativePrompter()
}

func writeSetupLines(writer io.Writer, lines ...string) {
	for _, line := range lines {
		_, _ = io.WriteString(writer, line+"\n")
	}
}
