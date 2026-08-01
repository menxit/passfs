package passfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// migrateLegacyMetadata upgrades the pathname-derived v1 storage layout to
// immutable objects. The deterministic identifier makes every step
// idempotent: a retry can observe the old ciphertext, the new ciphertext, the
// old link target, or the new link target and still converge on the same v2
// metadata.
func migrateLegacyMetadata(root string, legacy Metadata) (Metadata, error) {
	if _, err := reconcileLegacyMetadata(root, &legacy); err != nil {
		return Metadata{}, err
	}
	public, err := loadPublicConfig(root)
	if err != nil {
		return Metadata{}, err
	}
	objectsRoot := filepath.Join(root, objectStorageDirectory)
	if err := os.MkdirAll(objectsRoot, 0o700); err != nil {
		return Metadata{}, fmt.Errorf("create protected object directory: %w", err)
	}

	migrated := Metadata{
		Version:       metadataFormatVersion,
		Files:         make(map[string]FileMeta, len(legacy.Files)),
		Links:         make(map[string]string, len(legacy.Links)),
		Orphaned:      make(map[string]int64),
		LegacyTargets: make(map[string]string),
	}
	now := time.Now().UnixNano()
	for legacyKey, meta := range legacy.Files {
		legacyStorage := filepath.FromSlash(legacyKey)
		objectID := legacyObjectID(public.VolumeID, legacyStorage)
		objectStorage, err := objectStoragePath(objectID)
		if err != nil {
			return Metadata{}, err
		}
		if err := moveLegacyCiphertext(root, legacyStorage, objectStorage); err != nil {
			return Metadata{}, err
		}
		newKey := metadataKey(objectStorage)
		if meta.Inode < 2 {
			meta.Inode = stableInode(newKey)
		}
		migrated.Files[newKey] = meta

		sourcePath, sourceErr := OriginalPath(legacyStorage)
		legacyTarget := filepath.Clean(legacy.Links[legacyKey])
		if sourceErr != nil || legacyTarget == "." || legacyTarget == "" {
			migrated.Orphaned[newKey] = now
			continue
		}
		mountPoint, ok := legacyMountPoint(sourcePath, legacyTarget)
		if !ok {
			migrated.Links[newKey] = filepath.Clean(sourcePath)
			migrated.Orphaned[newKey] = now
			migrated.LegacyTargets[newKey] = legacyTarget
			continue
		}
		newTarget, err := mountedObjectPath(mountPoint, objectID)
		if err != nil {
			return Metadata{}, err
		}
		link, err := inspectProtectedLink(sourcePath)
		if err != nil {
			return Metadata{}, err
		}
		switch {
		case link.isSymlink && link.target == filepath.Clean(newTarget):
			migrated.Links[newKey] = filepath.Clean(sourcePath)
		case link.isSymlink && link.target == legacyTarget:
			if err := replaceProtectedLink(sourcePath, newTarget, legacyTarget); err != nil {
				return Metadata{}, fmt.Errorf("retarget legacy protected link %s: %w", sourcePath, err)
			}
			migrated.Links[newKey] = filepath.Clean(sourcePath)
		default:
			// The link may have been moved while PassFS was stopped. Preserve the
			// former target so reconciliation can find and retarget it globally.
			migrated.Links[newKey] = filepath.Clean(sourcePath)
			migrated.Orphaned[newKey] = now
			migrated.LegacyTargets[newKey] = legacyTarget
		}
	}

	if err := saveMetadata(root, migrated); err != nil {
		return Metadata{}, err
	}
	pruneLegacyStorageTree(filepath.Join(root, "files"))
	return migrated, nil
}

// pruneLegacyStorageTree removes only empty v1 directories after every
// ciphertext has been moved. Unexpected files are deliberately retained.
func pruneLegacyStorageTree(root string) {
	directories := make([]string, 0)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	sort.Slice(directories, func(left, right int) bool {
		return len(directories[left]) > len(directories[right])
	})
	for _, directory := range directories {
		_ = os.Remove(directory)
	}
}

func moveLegacyCiphertext(root, legacyStorage, objectStorage string) error {
	oldPath := filepath.Join(root, filepath.Clean(legacyStorage)) + encryptedSuffix
	newPath := filepath.Join(root, filepath.Clean(objectStorage)) + encryptedSuffix
	oldInfo, oldErr := os.Lstat(oldPath)
	newInfo, newErr := os.Lstat(newPath)
	switch {
	case oldErr == nil && !oldInfo.Mode().IsRegular():
		return fmt.Errorf("legacy ciphertext %s is not a regular file", oldPath)
	case newErr == nil && !newInfo.Mode().IsRegular():
		return fmt.Errorf("protected object %s is not a regular file", newPath)
	case oldErr == nil && newErr == nil:
		if !os.SameFile(oldInfo, newInfo) {
			return fmt.Errorf("legacy and object ciphertext both exist for %s", legacyStorage)
		}
		if err := os.Remove(oldPath); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(oldPath))
	case oldErr == nil && errors.Is(newErr, os.ErrNotExist):
		if err := renameNoReplace(oldPath, newPath); err != nil {
			return err
		}
		return errors.Join(
			syncDirectory(filepath.Dir(oldPath)),
			syncDirectory(filepath.Dir(newPath)),
		)
	case errors.Is(oldErr, os.ErrNotExist) && newErr == nil:
		return nil
	case oldErr != nil && !errors.Is(oldErr, os.ErrNotExist):
		return oldErr
	case newErr != nil && !errors.Is(newErr, os.ErrNotExist):
		return newErr
	default:
		return fmt.Errorf("ciphertext is missing for legacy entry %s", legacyStorage)
	}
}

func legacyMountPoint(sourcePath, legacyTarget string) (string, bool) {
	source := filepath.Clean(sourcePath)
	target := filepath.Clean(legacyTarget)
	if !filepath.IsAbs(source) || !filepath.IsAbs(target) ||
		!strings.HasSuffix(target, source) {
		return "", false
	}
	mountPoint := strings.TrimSuffix(target, source)
	if mountPoint == "" {
		mountPoint = string(filepath.Separator)
	}
	return filepath.Clean(mountPoint), true
}

// reconcileMetadata repairs only the v2 object index. Project pathnames are
// deliberately absent from ciphertext paths, so rename reconciliation never
// needs to rename or cycle backing files.
func reconcileMetadata(root string, metadata *Metadata) (bool, error) {
	objectsRoot := filepath.Join(root, objectStorageDirectory)
	info, err := os.Lstat(objectsRoot)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("%s is not a directory", objectsRoot)
	}
	actual := make(map[string]FileMeta)
	entries, err := os.ReadDir(objectsRoot)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() ||
			!strings.HasSuffix(entry.Name(), encryptedSuffix) {
			continue
		}
		objectID, err := normalizeObjectID(strings.TrimSuffix(entry.Name(), encryptedSuffix))
		if err != nil {
			continue
		}
		storage, _ := objectStoragePath(objectID)
		key := metadataKey(storage)
		entryInfo, err := entry.Info()
		if err != nil {
			return false, err
		}
		actual[key] = FileMeta{
			Mode:  0o600,
			MTime: entryInfo.ModTime().UnixNano(),
			ATime: entryInfo.ModTime().UnixNano(),
			Inode: stableInode(key),
		}
	}

	changed := metadata.Version != metadataFormatVersion || metadata.DisplacedLinks != nil
	metadata.Version = metadataFormatVersion
	metadata.DisplacedLinks = nil
	if metadata.Files == nil {
		metadata.Files = make(map[string]FileMeta)
		changed = true
	}
	if metadata.Links == nil {
		metadata.Links = make(map[string]string)
		changed = true
	}
	if metadata.Orphaned == nil {
		metadata.Orphaned = make(map[string]int64)
		changed = true
	}
	if metadata.LegacyTargets == nil {
		metadata.LegacyTargets = make(map[string]string)
		changed = true
	}
	for key, meta := range metadata.Files {
		if _, exists := actual[key]; !exists {
			delete(metadata.Files, key)
			delete(metadata.Links, key)
			delete(metadata.Orphaned, key)
			delete(metadata.LegacyTargets, key)
			changed = true
			continue
		}
		if meta.Inode < 2 {
			meta.Inode = stableInode(key)
			metadata.Files[key] = meta
			changed = true
		}
	}
	for key, fallback := range actual {
		if _, exists := metadata.Files[key]; !exists {
			metadata.Files[key] = fallback
			metadata.Orphaned[key] = time.Now().UnixNano()
			changed = true
		}
	}
	for key := range metadata.Links {
		if _, exists := metadata.Files[key]; !exists {
			delete(metadata.Links, key)
			changed = true
		}
	}
	for key := range metadata.Orphaned {
		if _, exists := metadata.Files[key]; !exists {
			delete(metadata.Orphaned, key)
			changed = true
		}
	}
	for key := range metadata.LegacyTargets {
		if _, exists := metadata.Files[key]; !exists {
			delete(metadata.LegacyTargets, key)
			changed = true
		}
	}
	return changed, nil
}
