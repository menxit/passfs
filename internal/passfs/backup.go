package passfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	backupFormatVersion = 1
	backupManifestName  = "passfs-backup.json"
	backupVaultName     = "vault"
)

type BackupFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type BackupManifest struct {
	Version         int          `json:"version"`
	CreatedUnixNano int64        `json:"createdUnixNano"`
	VolumeID        string       `json:"volumeID"`
	Files           []BackupFile `json:"files"`
}

type VerificationReport struct {
	VolumeID string `json:"volumeID"`
	Files    int    `json:"files"`
	Bytes    uint64 `json:"bytes"`
}

// CreateBackup copies only the documented vault files and atomically publishes
// the completed backup directory. Callers must quiesce the mounted service.
func CreateBackup(vault, destination string) (BackupManifest, error) {
	root, err := filepath.Abs(vault)
	if err != nil {
		return BackupManifest{}, err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return BackupManifest{}, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return BackupManifest{}, fmt.Errorf("backup destination %s already exists", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupManifest{}, err
	}
	if pathWithin(destination, root) {
		return BackupManifest{}, errors.New("backup destination must be outside the PassFS vault")
	}
	public, err := loadPublicConfig(root)
	if err != nil {
		return BackupManifest{}, err
	}
	if _, err := vaultIndexForVerification(root); err != nil {
		return BackupManifest{}, fmt.Errorf("refuse to back up an inconsistent vault: %w", err)
	}
	paths, err := vaultBackupPaths(root)
	if err != nil {
		return BackupManifest{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return BackupManifest{}, err
	}
	staging, err := os.MkdirTemp(parent, ".passfs-backup-*")
	if err != nil {
		return BackupManifest{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	manifest := BackupManifest{
		Version:         backupFormatVersion,
		CreatedUnixNano: time.Now().UnixNano(),
		VolumeID:        public.VolumeID,
		Files:           make([]BackupFile, 0, len(paths)),
	}
	for _, relative := range paths {
		source := filepath.Join(root, filepath.FromSlash(relative))
		target := filepath.Join(staging, backupVaultName, filepath.FromSlash(relative))
		digest, size, err := copyBackupFile(source, target)
		if err != nil {
			return BackupManifest{}, err
		}
		manifest.Files = append(manifest.Files, BackupFile{
			Path: relative, Size: size, SHA256: digest,
		})
	}
	if err := WriteJSONFileAtomic(
		filepath.Join(staging, backupManifestName), manifest, 0o600,
	); err != nil {
		return BackupManifest{}, err
	}
	for _, directory := range []string{
		filepath.Join(backupVaultName, internalDirName),
		filepath.Join(backupVaultName, objectStorageDirectory),
		backupVaultName,
	} {
		if err := syncDirectory(filepath.Join(staging, directory)); err != nil {
			return BackupManifest{}, err
		}
	}
	if err := syncDirectory(staging); err != nil {
		return BackupManifest{}, err
	}
	if err := renameNoReplace(staging, destination); err != nil {
		return BackupManifest{}, fmt.Errorf("publish backup: %w", err)
	}
	committed = true
	if err := syncDirectory(parent); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

func vaultBackupPaths(root string) ([]string, error) {
	paths := []string{
		filepath.ToSlash(filepath.Join(internalDirName, publicConfigName)),
		filepath.ToSlash(filepath.Join(internalDirName, identityFileName)),
		filepath.ToSlash(filepath.Join(internalDirName, metadataFileName)),
	}
	entries, err := os.ReadDir(filepath.Join(root, objectStorageDirectory))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 ||
			!strings.HasSuffix(entry.Name(), encryptedSuffix) {
			continue
		}
		if _, err := normalizeObjectID(strings.TrimSuffix(entry.Name(), encryptedSuffix)); err != nil {
			continue
		}
		paths = append(paths, filepath.ToSlash(filepath.Join(objectStorageDirectory, entry.Name())))
	}
	sort.Strings(paths)
	return paths, nil
}

func copyBackupFile(source, target string) (string, int64, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("backup source %s is not a regular file", source)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", 0, err
	}
	input, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return "", 0, errors.Join(copyErr, closeErr)
	}
	if written != info.Size() {
		return "", 0, fmt.Errorf("backup source %s changed while copying", source)
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func readBackupManifest(backup string) (BackupManifest, string, error) {
	root, err := filepath.Abs(backup)
	if err != nil {
		return BackupManifest{}, "", err
	}
	for _, directory := range []string{root, filepath.Join(root, backupVaultName)} {
		info, err := os.Lstat(directory)
		if err != nil {
			return BackupManifest{}, "", err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return BackupManifest{}, "", fmt.Errorf("backup path %s is not a real directory", directory)
		}
	}
	manifestPath := filepath.Join(root, backupManifestName)
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil {
		return BackupManifest{}, "", err
	}
	if !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 {
		return BackupManifest{}, "", errors.New("backup manifest is not a regular file")
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return BackupManifest{}, "", err
	}
	defer file.Close()
	var manifest BackupManifest
	if err := decodeBoundedJSON(file, 16*1024*1024, &manifest); err != nil {
		return BackupManifest{}, "", fmt.Errorf("parse backup manifest: %w", err)
	}
	if manifest.Version != backupFormatVersion || manifest.VolumeID == "" {
		return BackupManifest{}, "", errors.New("unsupported or incomplete PassFS backup manifest")
	}
	return manifest, filepath.Join(root, backupVaultName), nil
}

func VerifyBackup(
	ctx context.Context,
	backup string,
	prompter Prompter,
	maxFileSize int64,
) (VerificationReport, error) {
	manifest, vault, err := readBackupManifest(backup)
	if err != nil {
		return VerificationReport{}, err
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, expected := range manifest.Files {
		if err := validateBackupRelativePath(expected.Path); err != nil {
			return VerificationReport{}, err
		}
		if _, duplicate := seen[expected.Path]; duplicate {
			return VerificationReport{}, fmt.Errorf("duplicate backup entry %s", expected.Path)
		}
		seen[expected.Path] = struct{}{}
		actualHash, actualSize, err := hashRegularFile(filepath.Join(vault, filepath.FromSlash(expected.Path)))
		if err != nil {
			return VerificationReport{}, err
		}
		if actualSize != expected.Size || actualHash != expected.SHA256 {
			return VerificationReport{}, fmt.Errorf("backup checksum mismatch for %s", expected.Path)
		}
	}
	if err := validateBackupTree(vault, seen); err != nil {
		return VerificationReport{}, err
	}
	report, err := VerifyVault(ctx, vault, prompter, maxFileSize)
	if err != nil {
		return VerificationReport{}, err
	}
	if report.VolumeID != manifest.VolumeID {
		return VerificationReport{}, errors.New("backup manifest volume ID does not match the vault")
	}
	return report, nil
}

func VerifyVault(
	ctx context.Context,
	vault string,
	prompter Prompter,
	maxFileSize int64,
) (VerificationReport, error) {
	metadata, err := vaultIndexForVerification(vault)
	if err != nil {
		return VerificationReport{}, err
	}
	volume, err := LoadVolume(vault, prompter, maxFileSize, 0)
	if err != nil {
		return VerificationReport{}, err
	}
	identity, err := volume.requestIdentity(ctx, PromptRequest{
		Path: vault, Operation: "verify", Description: "Authorize verifying every encrypted file in this PassFS vault.",
	})
	if err != nil {
		return VerificationReport{}, err
	}
	keys := make([]string, 0, len(metadata.Files))
	for key := range metadata.Files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	report := VerificationReport{VolumeID: volume.VolumeID(), Files: len(keys)}
	for _, key := range keys {
		data, err := volume.decryptFileWithIdentity(filepath.FromSlash(key), identity)
		if err != nil {
			return VerificationReport{}, fmt.Errorf("verify %s: %w", key, err)
		}
		size := uint64(len(data))
		wipe(data)
		if size != metadata.Files[key].Size {
			return VerificationReport{}, fmt.Errorf(
				"verify %s: plaintext size %d does not match metadata size %d",
				key, size, metadata.Files[key].Size,
			)
		}
		report.Bytes += size
	}
	return report, nil
}

func RestoreBackup(backup, destination string) (BackupManifest, error) {
	manifest, sourceVault, err := readBackupManifest(backup)
	if err != nil {
		return BackupManifest{}, err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return BackupManifest{}, err
	}
	if pathWithin(destination, filepath.Dir(sourceVault)) {
		return BackupManifest{}, errors.New("restore destination must be outside the backup")
	}
	if _, err := os.Lstat(destination); err == nil {
		return BackupManifest{}, fmt.Errorf("restore destination %s already exists", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupManifest{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return BackupManifest{}, err
	}
	staging, err := os.MkdirTemp(parent, ".passfs-restore-*")
	if err != nil {
		return BackupManifest{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	for _, entry := range manifest.Files {
		if err := validateBackupRelativePath(entry.Path); err != nil {
			return BackupManifest{}, err
		}
		digest, size, err := copyBackupFile(
			filepath.Join(sourceVault, filepath.FromSlash(entry.Path)),
			filepath.Join(staging, filepath.FromSlash(entry.Path)),
		)
		if err != nil {
			return BackupManifest{}, err
		}
		if digest != entry.SHA256 || size != entry.Size {
			return BackupManifest{}, fmt.Errorf("backup checksum mismatch for %s", entry.Path)
		}
	}
	for _, directory := range []string{internalDirName, objectStorageDirectory} {
		if err := syncDirectory(filepath.Join(staging, directory)); err != nil {
			return BackupManifest{}, err
		}
	}
	if err := syncDirectory(staging); err != nil {
		return BackupManifest{}, err
	}
	if err := renameNoReplace(staging, destination); err != nil {
		return BackupManifest{}, fmt.Errorf("publish restored vault: %w", err)
	}
	committed = true
	return manifest, syncDirectory(parent)
}

func vaultIndexForVerification(vault string) (Metadata, error) {
	root, err := filepath.Abs(vault)
	if err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	if err := withMetadataFileLock(root, func() error {
		var err error
		metadata, err = readMetadata(root)
		return err
	}); err != nil {
		return Metadata{}, err
	}
	actual := make(map[string]struct{})
	entries, err := os.ReadDir(filepath.Join(root, objectStorageDirectory))
	if err != nil {
		return Metadata{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() ||
			!strings.HasSuffix(entry.Name(), encryptedSuffix) {
			return Metadata{}, fmt.Errorf(
				"unexpected entry in encrypted object directory: %s",
				entry.Name(),
			)
		}
		objectID, err := normalizeObjectID(strings.TrimSuffix(entry.Name(), encryptedSuffix))
		if err != nil {
			return Metadata{}, fmt.Errorf("unexpected encrypted object %s", entry.Name())
		}
		storage, _ := objectStoragePath(objectID)
		actual[metadataKey(storage)] = struct{}{}
	}
	for key := range metadata.Files {
		if _, err := objectIDFromStoragePath(filepath.FromSlash(key)); err != nil {
			return Metadata{}, fmt.Errorf("invalid object index entry %s", key)
		}
		if _, exists := actual[key]; !exists {
			return Metadata{}, fmt.Errorf("encrypted object %s is missing", key)
		}
	}
	for key := range actual {
		if _, indexed := metadata.Files[key]; !indexed {
			return Metadata{}, fmt.Errorf("encrypted object %s is not indexed by metadata", key)
		}
	}
	linkedPaths := make(map[string]string, len(metadata.Links))
	for key, path := range metadata.Links {
		if _, indexed := metadata.Files[key]; !indexed {
			return Metadata{}, fmt.Errorf("link metadata references unknown object %s", key)
		}
		if path == "" || !filepath.IsAbs(path) {
			return Metadata{}, fmt.Errorf("link metadata for %s has no absolute path", key)
		}
		clean := filepath.Clean(path)
		if previous, duplicate := linkedPaths[clean]; duplicate && previous != key {
			return Metadata{}, fmt.Errorf("multiple encrypted objects claim project path %s", clean)
		}
		linkedPaths[clean] = key
	}
	for key := range metadata.Recovery {
		if _, indexed := metadata.Files[key]; !indexed {
			return Metadata{}, fmt.Errorf("recovery metadata references unknown object %s", key)
		}
	}
	return metadata, nil
}

func validateBackupTree(vault string, expected map[string]struct{}) error {
	return filepath.WalkDir(vault, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(vault, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup contains symbolic link %s", relative)
		}
		if entry.IsDir() {
			if relative != internalDirName && relative != objectStorageDirectory {
				return fmt.Errorf("backup contains unexpected directory %s", relative)
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("backup contains non-regular file %s", relative)
		}
		if _, ok := expected[relative]; !ok {
			return fmt.Errorf("backup file %s is not covered by its manifest", relative)
		}
		return nil
	})
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func validateBackupRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(path)) != path ||
		path == ".." || strings.HasPrefix(path, "../") {
		return fmt.Errorf("unsafe backup path %q", path)
	}
	return nil
}

func hashRegularFile(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("backup entry %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
