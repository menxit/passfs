package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"passfs/internal/fuseadapter"
	"passfs/internal/passfs"
)

type fuseFilesystemAdapter struct{}

func (fuseFilesystemAdapter) Name() string {
	return adapterFUSE
}

func (fuseFilesystemAdapter) Capability() platformCapability {
	return platformFUSECapability()
}

func (fuseFilesystemAdapter) ValidateSettings(*passfs.Settings) error {
	return nil
}

func (fuseFilesystemAdapter) SupportsProcessSessions() bool {
	return true
}

func (fuseFilesystemAdapter) RegisterProtectedLink(
	settings *passfs.Settings,
	sourcePath string,
	targetPath string,
) error {
	return passfs.RegisterProtectedLinkInVault(
		settings.Vault,
		settings.MountPoint,
		sourcePath,
		targetPath,
	)
}

func (fuseFilesystemAdapter) UnavailableError(
	capability platformCapability,
) error {
	return platformFUSEError(capability)
}

func (fuseFilesystemAdapter) MountWaitError(
	err error,
	logHint string,
	_ string,
) error {
	return platformMountWaitError(err, logHint)
}

func (fuseFilesystemAdapter) Serve(
	settings *passfs.Settings,
	maxFileSize int64,
	debug bool,
	stderr io.Writer,
) error {
	serviceContext, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	prepared, err := prepareFilesystemService(
		serviceContext,
		settings,
		maxFileSize,
		stderr,
	)
	if err != nil {
		return err
	}
	volume := prepared.volume
	linkSynchronizer := prepared.synchronizer
	logger := prepared.logger
	defer linkSynchronizer.Close()

	zero := time.Duration(0)
	server, err := fs.Mount(
		settings.MountPoint,
		fuseadapter.NewRootNode(passfs.NewFileSystem(volume)),
		&fs.Options{
			AttrTimeout:     &zero,
			EntryTimeout:    &zero,
			NegativeTimeout: &zero,
			UID:             uint32(os.Getuid()),
			GID:             uint32(os.Getgid()),
			MountOptions: fuse.MountOptions{
				Options:            passfs.PlatformMountOptions(),
				FsName:             "passfs",
				Name:               "passfs",
				DisableReadDirPlus: true,
				Debug:              debug,
				Logger:             logger,
			},
			Logger: logger,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"mount passfs at %s: %w",
			terminalPath(settings.MountPoint),
			err,
		)
	}

	go func() {
		linkSynchronizer.Run(serviceContext)
	}()
	startUpdateMonitor(serviceContext, logger)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	serverDone := make(chan struct{})
	go func() {
		server.Wait()
		close(serverDone)
	}()

	select {
	case <-serverDone:
	case <-signals:
		cancelService()
		unmountDone := make(chan error, 1)
		go func() {
			unmountDone <- server.Unmount()
		}()
		select {
		case err := <-unmountDone:
			if err != nil {
				logger.Printf("unmount: %v", err)
				if forceErr := passfs.UnmountPath(settings.MountPoint); forceErr != nil {
					logger.Printf("force unmount: %v", forceErr)
				}
			}
		case <-time.After(2 * time.Second):
			logger.Printf("filesystem unmount timed out; detaching the mount")
			if forceErr := passfs.UnmountPath(settings.MountPoint); forceErr != nil {
				logger.Printf("force unmount: %v", forceErr)
			}
		}
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			logger.Printf("filesystem shutdown timed out; exiting after detaching the mount")
		}
	}
	cancelService()
	linkSynchronizer.Close()
	if err := volume.FlushAccessTimes(); err != nil {
		logger.Printf("flush access metadata: %v", err)
	}
	volume.Lock()
	return nil
}
