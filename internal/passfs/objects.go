package passfs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	metadataFormatVersion         = 3
	previousMetadataFormatVersion = 2
	legacyMetadataFormatVersion   = 1
	objectStorageDirectory        = "objects"
	objectNamespaceDirectory      = "by-id"
	objectIDLength                = 36
	objectIDCompactLength         = 32
)

// newObjectID returns an RFC 4122 version-4 identifier. Object identifiers are
// immutable: user-visible pathnames are link-index metadata and never affect
// the ciphertext location or the mounted target.
func newObjectID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate protected object id: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return formatObjectID(value), nil
}

// legacyObjectID is deterministic so an interrupted v1-to-v2 migration can
// resume after either the ciphertext move or the metadata commit.
func legacyObjectID(volumeID, legacyKey string) string {
	digest := sha256.Sum256([]byte(volumeID + "\x00" + metadataKey(legacyKey)))
	var value [16]byte
	copy(value[:], digest[:16])
	value[6] = value[6]&0x0f | 0x50
	value[8] = value[8]&0x3f | 0x80
	return formatObjectID(value)
}

func formatObjectID(value [16]byte) string {
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" +
		encoded[8:12] + "-" +
		encoded[12:16] + "-" +
		encoded[16:20] + "-" +
		encoded[20:32]
}

func normalizeObjectID(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != objectIDLength ||
		value[8] != '-' || value[13] != '-' ||
		value[18] != '-' || value[23] != '-' {
		return "", errors.New("invalid protected object id")
	}
	compact := strings.NewReplacer("-", "").Replace(value)
	if len(compact) != objectIDCompactLength {
		return "", errors.New("invalid protected object id")
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return "", errors.New("invalid protected object id")
	}
	return value, nil
}

func objectStoragePath(objectID string) (string, error) {
	normalized, err := normalizeObjectID(objectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(objectStorageDirectory, normalized), nil
}

func objectIDFromStoragePath(storage string) (string, error) {
	clean := filepath.Clean(storage)
	prefix := objectStorageDirectory + string(filepath.Separator)
	if !strings.HasPrefix(clean, prefix) {
		return "", fmt.Errorf("%s is not a protected object entry", storage)
	}
	objectID := strings.TrimPrefix(clean, prefix)
	if strings.ContainsRune(objectID, rune(filepath.Separator)) {
		return "", errors.New("protected object entry has nested components")
	}
	return normalizeObjectID(objectID)
}

func mountedObjectPath(mountPoint, objectID string) (string, error) {
	normalized, err := normalizeObjectID(objectID)
	if err != nil {
		return "", err
	}
	absoluteMount, err := filepath.Abs(mountPoint)
	if err != nil {
		return "", err
	}
	return filepath.Join(absoluteMount, objectNamespaceDirectory, normalized), nil
}

func mountedPathForStorage(mountPoint, storage string) (string, error) {
	objectID, err := objectIDFromStoragePath(storage)
	if err != nil {
		return "", err
	}
	return mountedObjectPath(mountPoint, objectID)
}

func objectIDFromMountedPath(mountPoint, target string) (string, error) {
	absoluteMount, err := filepath.Abs(mountPoint)
	if err != nil {
		return "", err
	}
	absoluteTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(
		filepath.Join(absoluteMount, objectNamespaceDirectory),
		absoluteTarget,
	)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		strings.ContainsRune(relative, rune(filepath.Separator)) {
		return "", errors.New("symlink does not target a passfs object")
	}
	return normalizeObjectID(relative)
}

func objectIDFromOpaqueTarget(target string) (string, error) {
	clean := filepath.Clean(target)
	if !filepath.IsAbs(clean) || filepath.Base(filepath.Dir(clean)) != objectNamespaceDirectory {
		return "", errors.New("symlink does not target a passfs object")
	}
	return normalizeObjectID(filepath.Base(clean))
}

func targetMatchesStorage(target, storage string) bool {
	targetID, err := objectIDFromOpaqueTarget(target)
	if err != nil {
		return false
	}
	storageID, err := objectIDFromStoragePath(storage)
	return err == nil && targetID == storageID
}
