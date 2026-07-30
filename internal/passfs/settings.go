package passfs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const settingsVersion = 2

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
	return filepath.Join(homeDirectory, ".config", "passfs", "config.json"), nil
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
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := WriteFileAtomic(settings.path, data, 0o600); err != nil {
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
