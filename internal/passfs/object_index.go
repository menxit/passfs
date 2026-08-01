package passfs

import (
	"errors"
	"os"
	"path/filepath"
)

// protectedObjectForSource returns the immutable object currently owned by a
// project pathname. If allocate is true and no object is registered, it
// allocates a fresh target without publishing metadata; the filesystem create
// and subsequent link registration commit the object transactionally.
func protectedObjectForSource(
	vault string,
	mountPoint string,
	sourcePath string,
	allocate bool,
) (storage string, target string, err error) {
	root, err := filepath.Abs(vault)
	if err != nil {
		return "", "", err
	}
	source, err := ResolvePathEntry(sourcePath)
	if err != nil {
		return "", "", err
	}

	var metadata Metadata
	err = withMetadataFileLock(root, func() error {
		var readErr error
		metadata, readErr = readMetadata(root)
		return readErr
	})
	if err != nil {
		return "", "", err
	}
	for key, registeredSource := range metadata.Links {
		if filepath.Clean(registeredSource) != filepath.Clean(source) {
			continue
		}
		if _, protected := metadata.Files[key]; !protected {
			continue
		}
		objectID, objectErr := objectIDFromStoragePath(filepath.FromSlash(key))
		if objectErr != nil {
			return "", "", objectErr
		}
		target, objectErr = mountedObjectPath(mountPoint, objectID)
		return filepath.FromSlash(key), target, objectErr
	}

	link, linkErr := inspectProtectedLink(source)
	if linkErr != nil {
		return "", "", linkErr
	}
	if link.isSymlink {
		objectID, objectErr := objectIDFromMountedPath(mountPoint, link.target)
		if objectErr != nil {
			return "", "", objectErr
		}
		storage, _ = objectStoragePath(objectID)
		if _, protected := metadata.Files[metadataKey(storage)]; !protected {
			return "", "", os.ErrNotExist
		}
		return storage, link.target, nil
	}
	if !allocate {
		return "", "", os.ErrNotExist
	}
	objectID, err := newObjectID()
	if err != nil {
		return "", "", err
	}
	storage, _ = objectStoragePath(objectID)
	target, err = mountedObjectPath(mountPoint, objectID)
	return storage, target, err
}

// ProtectedTargetForPath returns the existing immutable mounted target for a
// protected project path.
func ProtectedTargetForPath(vault, mountPoint, sourcePath string) (string, error) {
	_, target, err := protectedObjectForSource(vault, mountPoint, sourcePath, false)
	if errors.Is(err, os.ErrNotExist) {
		return "", os.ErrNotExist
	}
	return target, err
}
