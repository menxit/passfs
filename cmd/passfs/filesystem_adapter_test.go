package main

import (
	"errors"
	"io"
	"testing"

	"passfs/internal/passfs"
)

type testFilesystemAdapter struct {
	name       string
	ready      bool
	validation error
}

func (adapter testFilesystemAdapter) Name() string {
	return adapter.name
}

func (adapter testFilesystemAdapter) Capability() platformCapability {
	return platformCapability{name: adapter.name, ready: adapter.ready}
}

func (adapter testFilesystemAdapter) ValidateSettings(*passfs.Settings) error {
	return adapter.validation
}

func (testFilesystemAdapter) SupportsProcessSessions() bool {
	return false
}

func (testFilesystemAdapter) RegisterProtectedLink(
	*passfs.Settings,
	string,
	string,
) error {
	return nil
}

func (testFilesystemAdapter) Serve(
	*passfs.Settings,
	int64,
	bool,
	io.Writer,
) error {
	return nil
}

func (adapter testFilesystemAdapter) UnavailableError(platformCapability) error {
	return errors.New(adapter.name + " unavailable")
}

func (adapter testFilesystemAdapter) MountWaitError(
	error,
	string,
	string,
) error {
	return errors.New(adapter.name + " mount failed")
}

func TestAutomaticAdapterPrefersFSKitWithoutTouchID(t *testing.T) {
	adapters := []filesystemAdapter{
		testFilesystemAdapter{name: adapterFSKit, ready: true},
		testFilesystemAdapter{name: adapterFUSE, ready: true},
	}
	selected, err := selectFilesystemAdapterFrom(
		adapterAuto,
		&passfs.Settings{TouchID: false},
		adapters,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Name() != adapterFSKit {
		t.Fatalf("selected adapter = %q, want FSKit", selected.Name())
	}
}

func TestAutomaticAdapterSkipsAnUnavailableAdapter(t *testing.T) {
	adapters := []filesystemAdapter{
		testFilesystemAdapter{name: adapterFSKit, ready: false},
		testFilesystemAdapter{name: adapterFUSE, ready: true},
	}
	selected, err := selectFilesystemAdapterFrom(
		adapterAuto,
		&passfs.Settings{TouchID: false},
		adapters,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Name() != adapterFUSE {
		t.Fatalf("selected adapter = %q, want FUSE", selected.Name())
	}
}
