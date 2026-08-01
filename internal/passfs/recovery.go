package passfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type RecoveryItem struct {
	ObjectID         string        `json:"objectID"`
	Path             string        `json:"path"`
	State            RecoveryState `json:"state"`
	Reason           string        `json:"reason,omitempty"`
	ObservedUnixNano int64         `json:"observedUnixNano"`
	Size             uint64        `json:"size"`
}

// RecoveryItems returns encrypted objects whose project-side link was deleted
// or replaced. It never opens plaintext and therefore never authorizes.
func RecoveryItems(vault string) ([]RecoveryItem, error) {
	root, err := filepath.Abs(vault)
	if err != nil {
		return nil, err
	}
	var items []RecoveryItem
	err = withMetadataFileLock(root, func() error {
		metadata, err := readMetadata(root)
		if err != nil {
			return err
		}
		items = make([]RecoveryItem, 0, len(metadata.Recovery))
		for key, recovery := range metadata.Recovery {
			meta, exists := metadata.Files[key]
			if !exists {
				continue
			}
			objectID, err := objectIDFromStoragePath(filepath.FromSlash(key))
			if err != nil {
				return err
			}
			items = append(items, RecoveryItem{
				ObjectID:         objectID,
				Path:             recovery.Path,
				State:            recovery.State,
				Reason:           recovery.Reason,
				ObservedUnixNano: recovery.ObservedUnixNano,
				Size:             meta.Size,
			})
		}
		return nil
	})
	sort.Slice(items, func(i, j int) bool {
		if items[i].ObservedUnixNano != items[j].ObservedUnixNano {
			return items[i].ObservedUnixNano > items[j].ObservedUnixNano
		}
		return items[i].Path < items[j].Path
	})
	return items, err
}

// RestoreRecoveryLink recreates a missing project-side symlink. A conflicting
// filesystem entry is never overwritten: the caller must move it aside or
// explicitly protect it before restoring the original encrypted object.
func RestoreRecoveryLink(vault, mountPoint, reference string) error {
	root, err := filepath.Abs(vault)
	if err != nil {
		return err
	}
	return withMetadataFileLock(root, func() error {
		metadata, err := readMetadata(root)
		if err != nil {
			return err
		}
		key, recovery, err := findRecoveryEntry(metadata, reference)
		if err != nil {
			return err
		}
		if recovery.Path == "" || recovery.Path == "." {
			return errors.New("recovery item has no original project path")
		}
		objectID, err := objectIDFromStoragePath(filepath.FromSlash(key))
		if err != nil {
			return err
		}
		target, err := mountedObjectPath(mountPoint, objectID)
		if err != nil {
			return err
		}
		created, err := EnsureProtectedLink(recovery.Path, target)
		if err != nil {
			return fmt.Errorf("restore protected link: %w", err)
		}
		metadata.Links[key] = filepath.Clean(recovery.Path)
		delete(metadata.Recovery, key)
		delete(metadata.Orphaned, key)
		delete(metadata.LegacyTargets, key)
		if err := saveMetadata(root, metadata); err != nil {
			if created {
				link, inspectErr := inspectProtectedLink(recovery.Path)
				if inspectErr == nil && link.isSymlink &&
					link.target == filepath.Clean(target) {
					_ = os.Remove(recovery.Path)
				}
			}
			return fmt.Errorf("record restored protected link: %w", err)
		}
		return nil
	})
}

func findRecoveryEntry(
	metadata Metadata,
	reference string,
) (string, RecoveryEntry, error) {
	cleanReference := filepath.Clean(reference)
	for key, entry := range metadata.Recovery {
		objectID, err := objectIDFromStoragePath(filepath.FromSlash(key))
		if err != nil {
			continue
		}
		if reference == objectID || cleanReference == filepath.Clean(entry.Path) ||
			cleanReference == filepath.Clean(filepath.FromSlash(key)) {
			return key, entry, nil
		}
	}
	return "", RecoveryEntry{}, fmt.Errorf("recovery item %q was not found", reference)
}

func (v *Volume) PurgeRecovery(reference string) error {
	v.metadataMu.RLock()
	key, _, err := findRecoveryEntry(v.metadata, reference)
	v.metadataMu.RUnlock()
	if err != nil {
		return err
	}
	return v.removeProtectedFile(filepath.FromSlash(key))
}
