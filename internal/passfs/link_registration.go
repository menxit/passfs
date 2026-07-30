package passfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
	source, err := filepath.Abs(sourcePath)
	if err != nil {
		return err
	}
	target, err := filepath.Abs(targetPath)
	if err != nil {
		return err
	}
	expectedTarget, err := MountedPath(mountPoint, source)
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

	relative := strings.TrimPrefix(
		filepath.ToSlash(filepath.Clean(source)),
		"/",
	)
	storage := filepath.Join("files", filepath.FromSlash(relative))
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
		metadata.Links[key] = filepath.Clean(target)
		return saveMetadata(root, metadata)
	})
}
