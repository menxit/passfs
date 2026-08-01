package passfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var ErrLinkReconciliationInProgress = errors.New(
	"protected link reconciliation is still in progress",
)

const displacedTargetStabilityWindow = 200 * time.Millisecond

// RegisterProtectedLinkInVault records a project-side protected link without
// routing the control message through the mounted file system. Native
// sandboxed adapters use this after the CLI has verified the link itself.
func RegisterProtectedLinkInVault(
	vault string,
	mountPoint string,
	sourcePath string,
	targetPath string,
) error {
	root, err := filepath.Abs(vault)
	if err != nil {
		return err
	}
	source, err := ResolvePathEntry(sourcePath)
	if err != nil {
		return err
	}
	target, err := filepath.Abs(targetPath)
	if err != nil {
		return err
	}
	objectID, err := objectIDFromMountedPath(mountPoint, target)
	if err != nil {
		return err
	}
	expectedTarget, err := mountedObjectPath(mountPoint, objectID)
	if err != nil {
		return err
	}
	if filepath.Clean(target) != filepath.Clean(expectedTarget) {
		return fmt.Errorf(
			"protected target %s does not match mounted path %s",
			target,
			expectedTarget,
		)
	}
	link, err := inspectProtectedLink(source)
	if err != nil {
		return err
	}
	if !link.isSymlink || link.target != filepath.Clean(target) {
		return errors.New("project path is not the expected protected link")
	}

	storage, err := objectStoragePath(objectID)
	if err != nil {
		return err
	}
	if err := validateRelativePath(storage); err != nil {
		return err
	}
	key := metadataKey(storage)

	return withMetadataFileLock(root, func() error {
		metadata, err := readMetadata(root)
		if err != nil {
			return err
		}
		if _, protected := metadata.Files[key]; !protected {
			return os.ErrNotExist
		}
		metadata.Links[key] = filepath.Clean(source)
		delete(metadata.Orphaned, key)
		delete(metadata.LegacyTargets, key)
		return saveMetadata(root, metadata)
	})
}

// CanReplaceDisplacedProtectedTarget reports whether a regular file at the
// original pathname has replaced the exact protected link PassFS registered
// for that path. An explicit `passfs encrypt` can then safely remove the old
// mounted target before importing the replacement plaintext. Unrelated target
// conflicts remain untouched.
func CanReplaceDisplacedProtectedTarget(
	vault string,
	mountPoint string,
	sourcePath string,
	targetPath string,
	maxFileSize int64,
) (bool, error) {
	if maxFileSize <= 0 {
		return false, errors.New("maximum file size must be greater than zero")
	}
	root, err := filepath.Abs(vault)
	if err != nil {
		return false, err
	}
	source, err := ResolvePathEntry(sourcePath)
	if err != nil {
		return false, err
	}
	target, err := filepath.Abs(targetPath)
	if err != nil {
		return false, err
	}

	sourceFile, sourceInfo, err := openValidatedSource(source, maxFileSize)
	if err != nil {
		return false, err
	}
	if err := sourceFile.Close(); err != nil {
		return false, err
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect protected target: %w", err)
	}
	if !targetInfo.Mode().IsRegular() {
		return false, nil
	}

	objectID, err := objectIDFromMountedPath(mountPoint, target)
	if err != nil {
		return false, err
	}
	storage, err := objectStoragePath(objectID)
	if err != nil {
		return false, err
	}
	backingPath := filepath.Join(root, storage) + encryptedSuffix
	backingInfo, err := os.Lstat(backingPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, ErrLinkReconciliationInProgress
		}
		return false, fmt.Errorf("inspect encrypted backing file: %w", err)
	}
	if !backingInfo.Mode().IsRegular() {
		return false, nil
	}
	if fileHasMultipleLinks(backingInfo) {
		return false, ErrLinkReconciliationInProgress
	}
	key := metadataKey(storage)
	replaceable := false
	err = withMetadataFileLock(root, func() error {
		metadata, readErr := readMetadata(root)
		if readErr != nil {
			return readErr
		}
		_, protected := metadata.Files[key]
		registeredSource, registered := metadata.Links[key]
		replaceable = protected && registered &&
			filepath.Clean(registeredSource) == filepath.Clean(source)
		return nil
	})
	if err != nil || !replaceable {
		return replaceable, err
	}
	record := linkRecord{
		relative:   storage,
		sourcePath: filepath.Clean(source),
		protected:  true,
	}
	search := newMovedProtectedLinkSearchWithGlobalRoots(
		root,
		mountPoint,
		[]linkRecord{record},
		true,
	)
	movedPath, moveErr := search.find(source, target)
	if moveErr != nil {
		return false, moveErr
	}
	if movedPath != "" {
		return false, ErrLinkReconciliationInProgress
	}

	// Editors also replace symlinks with regular files during atomic saves.
	// A protected-link move briefly has the same shape while the synchronizer
	// retargets the symlink and retires its compatibility hard link. Only mark
	// the path as an editor replacement after every relevant inode has remained
	// unchanged for a short quiescence window.
	time.Sleep(displacedTargetStabilityWindow)
	currentSource, err := os.Lstat(source)
	if err != nil || !sameFileVersion(sourceInfo, currentSource) {
		return false, ErrLinkReconciliationInProgress
	}
	currentTarget, err := os.Lstat(target)
	if err != nil || !sameFileVersion(targetInfo, currentTarget) {
		return false, ErrLinkReconciliationInProgress
	}
	currentBacking, err := os.Lstat(backingPath)
	if err != nil || !sameFileVersion(backingInfo, currentBacking) ||
		fileHasMultipleLinks(currentBacking) {
		return false, ErrLinkReconciliationInProgress
	}
	movedPath, moveErr = search.find(source, target)
	if moveErr != nil {
		return false, moveErr
	}
	if movedPath != "" {
		return false, ErrLinkReconciliationInProgress
	}
	latestSource, sourceErr := os.Lstat(source)
	latestTarget, targetErr := os.Lstat(target)
	latestBacking, backingErr := os.Lstat(backingPath)
	if sourceErr != nil || targetErr != nil || backingErr != nil ||
		!sameFileVersion(sourceInfo, latestSource) ||
		!sameFileVersion(targetInfo, latestTarget) ||
		!sameFileVersion(backingInfo, latestBacking) ||
		fileHasMultipleLinks(latestBacking) {
		return false, ErrLinkReconciliationInProgress
	}
	if err := withMetadataFileLock(root, func() error {
		metadata, readErr := readMetadata(root)
		if readErr != nil {
			return readErr
		}
		if _, protected := metadata.Files[key]; !protected ||
			filepath.Clean(metadata.Links[key]) != filepath.Clean(source) {
			return ErrLinkReconciliationInProgress
		}
		return nil
	}); err != nil {
		return false, err
	}
	return true, nil
}

func fileHasMultipleLinks(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink > 1
}
