package passfs

import (
	"errors"
	"fmt"
	"os"
)

type protectedLinkReference interface {
	currentPath() (path string, linked bool, err error)
	close() error
}

type protectedLinkTracker struct {
	references map[string]protectedLinkReference
}

func newProtectedLinkTracker() *protectedLinkTracker {
	return &protectedLinkTracker{
		references: make(map[string]protectedLinkReference),
	}
}

func (tracker *protectedLinkTracker) ensure(relative, sourcePath string) error {
	key := metadataKey(relative)
	if reference := tracker.references[key]; reference != nil {
		currentPath, linked, err := reference.currentPath()
		if err != nil {
			return err
		}
		if linked {
			same, err := sameLink(currentPath, sourcePath)
			if err != nil {
				return err
			}
			if same {
				return nil
			}
			return errors.New(
				"the tracked protected link moved while another link appeared at its old pathname; encrypted data was preserved",
			)
		}
		_ = reference.close()
		delete(tracker.references, key)
	}

	reference, err := openProtectedLinkReference(sourcePath)
	if err != nil {
		return fmt.Errorf("track protected link: %w", err)
	}
	tracker.references[key] = reference
	return nil
}

func (tracker *protectedLinkTracker) state(
	relative string,
) (path string, linked bool, tracked bool, err error) {
	reference := tracker.references[metadataKey(relative)]
	if reference == nil {
		return "", false, false, nil
	}
	path, linked, err = reference.currentPath()
	return path, linked, true, err
}

func (tracker *protectedLinkTracker) replace(
	oldRelative string,
	newRelative string,
	sourcePath string,
) error {
	tracker.forget(oldRelative)
	if err := tracker.ensure(newRelative, sourcePath); err != nil {
		return fmt.Errorf("track moved protected link: %w", err)
	}
	return nil
}

func (tracker *protectedLinkTracker) rekey(moves map[string]string) {
	references := make(map[string]protectedLinkReference, len(moves))
	for oldRelative := range moves {
		oldKey := metadataKey(oldRelative)
		if reference := tracker.references[oldKey]; reference != nil {
			references[oldKey] = reference
			delete(tracker.references, oldKey)
		}
	}
	for oldRelative, newRelative := range moves {
		oldKey := metadataKey(oldRelative)
		if reference := references[oldKey]; reference != nil {
			tracker.references[metadataKey(newRelative)] = reference
		}
	}
}

func (tracker *protectedLinkTracker) forget(relative string) {
	key := metadataKey(relative)
	if reference := tracker.references[key]; reference != nil {
		_ = reference.close()
		delete(tracker.references, key)
	}
}

func (tracker *protectedLinkTracker) close() {
	for key, reference := range tracker.references {
		_ = reference.close()
		delete(tracker.references, key)
	}
}

func sameLink(firstPath, secondPath string) (bool, error) {
	first, err := os.Lstat(firstPath)
	if err != nil {
		return false, err
	}
	second, err := os.Lstat(secondPath)
	if err != nil {
		return false, err
	}
	return os.SameFile(first, second), nil
}
