package passfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const settingsVersion = 2

const (
	defaultHomeName = ".passfs"
	legacyHomeName  = ".config/passfs"
)

type Settings struct {
	Version    int    `json:"version"`
	Vault      string `json:"vault"`
	MountPoint string `json:"mountPoint"`
	UnlockFor  string `json:"unlockFor"`
	TouchID    bool   `json:"touchId,omitempty"`
	Adapter    string `json:"adapter,omitempty"`

	path string
}

func DefaultSettingsPath() (string, error) {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find user home directory: %w", err)
	}
	current := filepath.Join(homeDirectory, defaultHomeName, "config.json")
	if _, err := os.Stat(current); err == nil {
		return current, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect passfs settings: %w", err)
	}
	legacy := filepath.Join(homeDirectory, filepath.FromSlash(legacyHomeName), "config.json")
	if _, err := os.Stat(legacy); err == nil {
		return legacy, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect legacy passfs settings: %w", err)
	}
	return current, nil
}

// LegacySettingsPath returns the settings location used before ~/.passfs.
// It is exposed so the CLI can stop a service using that path before moving
// its mounted state directory.
func LegacySettingsPath() (string, error) {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find user home directory: %w", err)
	}
	return filepath.Join(
		homeDirectory,
		filepath.FromSlash(legacyHomeName),
		"config.json",
	), nil
}

// MigrateLegacyHome atomically moves the former ~/.config/passfs directory to
// ~/.passfs and rewrites only paths that lived inside that directory. Callers
// must stop the filesystem service first because the old directory contains
// the mount point.
func MigrateLegacyHome() (bool, error) {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Errorf("find user home directory: %w", err)
	}
	legacyRoot := filepath.Join(homeDirectory, filepath.FromSlash(legacyHomeName))
	legacySettingsPath := filepath.Join(legacyRoot, "config.json")
	currentRoot := filepath.Join(homeDirectory, defaultHomeName)
	currentSettingsPath := filepath.Join(currentRoot, "config.json")

	if _, err := os.Stat(currentSettingsPath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect current passfs settings: %w", err)
	}
	legacyInfo, err := os.Lstat(legacyRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect legacy passfs home: %w", err)
	}
	if !legacyInfo.IsDir() || legacyInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("legacy passfs home %s is not a directory", legacyRoot)
	}
	if _, err := os.Stat(legacySettingsPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect legacy passfs settings: %w", err)
	}
	if _, err := os.Lstat(currentRoot); err == nil {
		return false, fmt.Errorf(
			"cannot migrate passfs: both %s and %s exist",
			legacyRoot,
			currentRoot,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect current passfs home: %w", err)
	}

	legacySettings, err := LoadSettings(legacySettingsPath)
	if err != nil {
		return false, err
	}
	if err := os.Rename(legacyRoot, currentRoot); err != nil {
		return false, fmt.Errorf("move passfs home to %s: %w", currentRoot, err)
	}
	rollback := func() {
		_ = os.Rename(currentRoot, legacyRoot)
	}
	if err := os.Chmod(currentRoot, 0o700); err != nil {
		rollback()
		return false, fmt.Errorf("secure migrated passfs home: %w", err)
	}

	vault := migratedHomePath(legacySettings.Vault, legacyRoot, currentRoot)
	mountPoint := migratedHomePath(
		legacySettings.MountPoint,
		legacyRoot,
		currentRoot,
	)
	unlockFor, err := legacySettings.UnlockDuration()
	if err != nil {
		rollback()
		return false, err
	}
	currentSettings, err := NewSettings(
		currentSettingsPath,
		vault,
		mountPoint,
		unlockFor,
	)
	if err != nil {
		rollback()
		return false, err
	}
	currentSettings.TouchID = legacySettings.TouchID
	currentSettings.Adapter = legacySettings.Adapter
	if err := currentSettings.Save(); err != nil {
		rollback()
		return false, fmt.Errorf("rewrite migrated passfs settings: %w", err)
	}
	return true, nil
}

func migratedHomePath(path, oldRoot, newRoot string) string {
	relative, err := filepath.Rel(oldRoot, path)
	if err != nil || relative == ".." || strings.HasPrefix(
		relative,
		".."+string(os.PathSeparator),
	) {
		return path
	}
	return filepath.Join(newRoot, relative)
}

func defaultConfigEntry(name string) (string, error) {
	configPath, err := DefaultSettingsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(configPath), name), nil
}

func DefaultVaultPath() (string, error) {
	return defaultConfigEntry("vault")
}

func DefaultMountPoint() (string, error) {
	return defaultConfigEntry("mnt")
}

func NewSettings(
	path string,
	vault string,
	mountPoint string,
	unlockFor time.Duration,
) (*Settings, error) {
	if unlockFor < 0 {
		return nil, errors.New("unlock duration cannot be negative")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absoluteVault, err := filepath.Abs(vault)
	if err != nil {
		return nil, err
	}
	absoluteMountPoint, err := filepath.Abs(mountPoint)
	if err != nil {
		return nil, err
	}
	if err := validateVaultAndMountPoint(absoluteVault, absoluteMountPoint); err != nil {
		return nil, err
	}
	return &Settings{
		Version:    settingsVersion,
		Vault:      absoluteVault,
		MountPoint: absoluteMountPoint,
		UnlockFor:  unlockFor.String(),
		path:       absolutePath,
	}, nil
}

func LoadSettings(path string) (*Settings, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("open passfs settings: %w", err)
	}
	defer file.Close()

	var disk Settings
	if err := decodeBoundedJSON(file, 4*1024*1024, &disk); err != nil {
		return nil, fmt.Errorf("parse passfs settings: %w", err)
	}
	if disk.Version != settingsVersion {
		return nil, fmt.Errorf("unsupported settings version %d", disk.Version)
	}
	if disk.Vault == "" {
		return nil, errors.New("settings do not define a vault")
	}
	if disk.MountPoint == "" {
		return nil, errors.New("settings do not define a mount point")
	}

	settings, err := NewSettings(absolutePath, disk.Vault, disk.MountPoint, 0)
	if err != nil {
		return nil, err
	}
	settings.UnlockFor = disk.UnlockFor
	settings.TouchID = disk.TouchID
	settings.Adapter = disk.Adapter
	if _, err := settings.UnlockDuration(); err != nil {
		return nil, err
	}
	return settings, nil
}

func (settings *Settings) Save() error {
	if settings.path == "" {
		return errors.New("settings path is not configured")
	}
	settings.Version = settingsVersion
	if err := WriteJSONFileAtomic(settings.path, settings, 0o600); err != nil {
		return err
	}
	return nil
}

func (settings *Settings) Path() string {
	return settings.path
}

func (settings *Settings) UnlockDuration() (time.Duration, error) {
	if settings.UnlockFor == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(settings.UnlockFor)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("invalid unlock duration %q", settings.UnlockFor)
	}
	return duration, nil
}

func (settings *Settings) SetUnlockDuration(duration time.Duration) error {
	if duration < 0 {
		return errors.New("unlock duration cannot be negative")
	}
	settings.UnlockFor = duration.String()
	return nil
}

func (settings *Settings) SetMountPoint(mountPoint string) error {
	absolute, err := filepath.Abs(mountPoint)
	if err != nil {
		return err
	}
	if err := validateVaultAndMountPoint(settings.Vault, absolute); err != nil {
		return err
	}
	settings.MountPoint = absolute
	return nil
}

func MountedPath(mountPoint, absolutePath string) (string, error) {
	absolute, err := filepath.Abs(absolutePath)
	if err != nil {
		return "", err
	}
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(absolute)), "/")
	return filepath.Join(mountPoint, filepath.FromSlash(clean)), nil
}

func OriginalPath(storagePath string) (string, error) {
	clean := filepath.Clean(storagePath)
	prefix := "files" + string(os.PathSeparator)
	if !strings.HasPrefix(clean, prefix) {
		return "", fmt.Errorf("%s is not an absolute-path storage entry", storagePath)
	}
	relative := strings.TrimPrefix(clean, prefix)
	if relative == "" || relative == "." {
		return "", errors.New("storage entry does not identify a file")
	}
	return filepath.Join(string(os.PathSeparator), relative), nil
}

func validateVaultAndMountPoint(vault, mountPoint string) error {
	resolvedVault, err := ResolvePath(vault)
	if err != nil {
		return fmt.Errorf("resolve vault path: %w", err)
	}
	resolvedMountParent, err := ResolvePath(filepath.Dir(mountPoint))
	if err != nil {
		return fmt.Errorf("resolve mount point: %w", err)
	}
	resolvedMountPoint := filepath.Join(resolvedMountParent, filepath.Base(mountPoint))
	if PathWithin(resolvedVault, resolvedMountPoint) ||
		PathWithin(resolvedMountPoint, resolvedVault) {
		return errors.New("vault and mount point must not contain each other")
	}
	return nil
}
