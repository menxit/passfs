package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"passfs/internal/passfs"
)

type preparedFilesystemService struct {
	volume       *passfs.Volume
	synchronizer *passfs.LinkSynchronizer
	sleepMonitor io.Closer
	prompter     passfs.Prompter
	logger       *log.Logger
	unlockFor    time.Duration
	unlockScope  passfs.UnlockScope
}

func prepareFilesystemService(
	ctx context.Context,
	settings *passfs.Settings,
	maxFileSize int64,
	stderr io.Writer,
) (*preparedFilesystemService, error) {
	prompter, err := newServicePrompter(settings)
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		prompter = passfs.WithCancellation(prompter, ctx)
	}
	unlockFor, err := settings.UnlockDuration()
	if err != nil {
		return nil, err
	}
	unlockScope, err := settings.AuthorizationScope()
	if err != nil {
		return nil, err
	}
	volume, err := passfs.LoadVolumeWithScope(
		settings.Vault,
		prompter,
		maxFileSize,
		unlockFor,
		unlockScope,
	)
	if err != nil {
		return nil, err
	}
	sleepMonitor, err := newPlatformSystemSleepMonitor(volume)
	if err != nil {
		return nil, fmt.Errorf("monitor system sleep: %w", err)
	}
	logger := log.New(stderr, "", log.LstdFlags)
	synchronizer, err := passfs.NewLinkSynchronizer(
		volume,
		settings.MountPoint,
		logger,
	)
	if err != nil {
		_ = sleepMonitor.Close()
		return nil, fmt.Errorf("initialize protected link tracking: %w", err)
	}
	synchronizer.EnableGlobalMoveSearch()
	if err := synchronizer.Prepare(); err != nil {
		synchronizer.Close()
		_ = sleepMonitor.Close()
		return nil, fmt.Errorf("prepare protected link tracking: %w", err)
	}
	return &preparedFilesystemService{
		volume:       volume,
		synchronizer: synchronizer,
		sleepMonitor: sleepMonitor,
		prompter:     prompter,
		logger:       logger,
		unlockFor:    unlockFor,
		unlockScope:  unlockScope,
	}, nil
}

func (prepared *preparedFilesystemService) Close() {
	if prepared == nil {
		return
	}
	prepared.synchronizer.Close()
	_ = prepared.sleepMonitor.Close()
}

const (
	adapterAuto  = "auto"
	adapterFUSE  = passfs.MountAdapterFUSE
	adapterFSKit = passfs.MountAdapterFSKit
)

// filesystemAdapter owns the platform-specific mount lifecycle. The passfs
// storage engine remains behind fsapi and never depends on one of these
// frontends.
type filesystemAdapter interface {
	Name() string
	Capability() platformCapability
	ValidateSettings(*passfs.Settings) error
	SupportsProcessSessions() bool
	RegisterProtectedLink(*passfs.Settings, string, string) error
	Serve(*passfs.Settings, int64, bool, io.Writer) error
	UnavailableError(platformCapability) error
	MountWaitError(error, string, string) error
}

func activeFilesystemAdapter(mountPoint string) (filesystemAdapter, error) {
	mounted, name, err := passfs.MountAdapterStatus(mountPoint)
	if err != nil {
		return nil, fmt.Errorf("inspect passfs adapter: %w", err)
	}
	if !mounted || name == passfs.MountAdapterUnknown {
		return nil, fmt.Errorf("%s is not a mounted passfs filesystem", mountPoint)
	}
	if adapter := filesystemAdapterNamed(
		platformFilesystemAdapters(),
		name,
	); adapter != nil {
		return adapter, nil
	}
	return nil, fmt.Errorf("mounted passfs adapter %q is unsupported", name)
}

func requestedAdapter(settings *passfs.Settings) string {
	if settings == nil || strings.TrimSpace(settings.Adapter) == "" {
		return adapterAuto
	}
	return strings.ToLower(strings.TrimSpace(settings.Adapter))
}

func normalizeFilesystemAdapter(
	requested string,
	adapters []filesystemAdapter,
) (string, error) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	if requested == "" {
		return adapterAuto, nil
	}
	if requested == adapterAuto {
		return requested, nil
	}
	if filesystemAdapterNamed(adapters, requested) != nil {
		return requested, nil
	}
	names := make([]string, 0, len(adapters))
	for _, adapter := range adapters {
		names = append(names, adapter.Name())
	}
	return "", fmt.Errorf(
		"unknown filesystem adapter %q (available: auto, %s)",
		requested,
		strings.Join(names, ", "),
	)
}

func filesystemAdapterNamed(
	adapters []filesystemAdapter,
	name string,
) filesystemAdapter {
	for _, adapter := range adapters {
		if adapter.Name() == name {
			return adapter
		}
	}
	return nil
}

func selectFilesystemAdapter(
	requested string,
	settings *passfs.Settings,
) (filesystemAdapter, error) {
	adapters := platformFilesystemAdapters()
	normalized, err := normalizeFilesystemAdapter(requested, adapters)
	if err != nil {
		return nil, err
	}
	if normalized == adapterAuto {
		adapters = platformAutomaticFilesystemAdapters(adapters)
	}
	return selectFilesystemAdapterFrom(
		normalized,
		settings,
		adapters,
	)
}

func selectFilesystemAdapterFrom(
	requested string,
	settings *passfs.Settings,
	adapters []filesystemAdapter,
) (filesystemAdapter, error) {
	var err error
	requested, err = normalizeFilesystemAdapter(requested, adapters)
	if err != nil {
		return nil, err
	}
	if requested == adapterAuto {
		var validationErr error
		for _, adapter := range adapters {
			if !adapter.Capability().ready {
				continue
			}
			if err := adapter.ValidateSettings(settings); err != nil {
				if validationErr == nil {
					validationErr = err
				}
				continue
			}
			return adapter, nil
		}
		if validationErr != nil {
			return nil, validationErr
		}
		var details []string
		for _, adapter := range adapters {
			capability := adapter.Capability()
			details = append(
				details,
				fmt.Sprintf("%s: %s", capability.name, capability.detail),
			)
		}
		return nil, actionableError{
			"no supported filesystem adapter is ready",
			strings.Join(details, "\n"),
			"run \"passfs init\" to complete setup and mount the filesystem",
		}
	}
	adapter := filesystemAdapterNamed(adapters, requested)
	capability := adapter.Capability()
	if !capability.ready {
		return nil, adapter.UnavailableError(capability)
	}
	if err := adapter.ValidateSettings(settings); err != nil {
		return nil, err
	}
	return adapter, nil
}
