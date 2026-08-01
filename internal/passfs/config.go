package passfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
)

const (
	formatVersion    = 1
	internalDirName  = ".passfs"
	publicConfigName = "config.json"
	identityFileName = "identity.age"
	metadataFileName = "metadata.json"
)

var ErrAuthentication = errors.New("incorrect passphrase")

type PublicConfig struct {
	Version   int    `json:"version"`
	VolumeID  string `json:"volumeId"`
	Recipient string `json:"recipient"`
}

type privateConfig struct {
	Version  int    `json:"version"`
	VolumeID string `json:"volumeId"`
	Identity string `json:"identity"`
}

func InitVolume(ctx context.Context, cipherDir string, prompter Prompter) (err error) {
	return initVolume(ctx, cipherDir, prompter, nil)
}

func initVolume(
	ctx context.Context,
	cipherDir string,
	prompter Prompter,
	identityHook func(PublicConfig, *age.X25519Identity) error,
) (err error) {
	if err := ensureEmptyDirectory(cipherDir); err != nil {
		return err
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate volume identity: %w", err)
	}
	volumeIDBytes := make([]byte, 16)
	if _, err := rand.Read(volumeIDBytes); err != nil {
		return fmt.Errorf("generate volume id: %w", err)
	}
	volumeID := hex.EncodeToString(volumeIDBytes)

	passphrase, err := prompter.Prompt(ctx, PromptRequest{
		Path:        cipherDir,
		Operation:   "initialize",
		Description: "Choose a recovery passphrase for your new PassFS vault.",
	})
	if err != nil {
		return err
	}
	confirmation, err := prompter.Prompt(ctx, PromptRequest{
		Path:        cipherDir,
		Operation:   "initialize",
		Description: "Confirm the recovery passphrase for your new PassFS vault.",
	})
	if err != nil {
		return err
	}
	if passphrase != confirmation {
		return errors.New("passphrases do not match")
	}
	if passphrase == "" {
		return errors.New("passphrase cannot be empty")
	}

	internalDir := filepath.Join(cipherDir, internalDirName)
	objectsDir := filepath.Join(cipherDir, objectStorageDirectory)
	initialized := false
	defer func() {
		if initialized {
			return
		}
		_ = os.RemoveAll(internalDir)
		_ = os.RemoveAll(objectsDir)
	}()
	if err := os.MkdirAll(internalDir, 0o700); err != nil {
		return fmt.Errorf("create internal directory: %w", err)
	}
	if err := os.MkdirAll(objectsDir, 0o700); err != nil {
		return fmt.Errorf("create encrypted object directory: %w", err)
	}

	public := PublicConfig{
		Version:   formatVersion,
		VolumeID:  volumeID,
		Recipient: identity.Recipient().String(),
	}
	private := privateConfig{
		Version:  formatVersion,
		VolumeID: volumeID,
		Identity: identity.String(),
	}

	if err := WriteJSONFileAtomic(
		filepath.Join(internalDir, publicConfigName),
		public,
		0o600,
	); err != nil {
		return fmt.Errorf("write public config: %w", err)
	}

	privateData, err := json.Marshal(private)
	if err != nil {
		return err
	}
	defer wipe(privateData)
	if err := writePassphraseEncryptedFile(filepath.Join(internalDir, identityFileName), privateData, passphrase); err != nil {
		return fmt.Errorf("write encrypted identity: %w", err)
	}

	metadata := Metadata{
		Version:       metadataFormatVersion,
		Files:         make(map[string]FileMeta),
		Links:         make(map[string]string),
		Orphaned:      make(map[string]int64),
		LegacyTargets: make(map[string]string),
	}
	if err := WriteJSONFileAtomic(
		filepath.Join(internalDir, metadataFileName),
		metadata,
		0o600,
	); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	if identityHook != nil {
		if err := identityHook(public, identity); err != nil {
			return fmt.Errorf("configure platform identity unlock: %w", err)
		}
	}
	initialized = true
	return nil
}

// initVolumeWithOptionalIdentity keeps the passphrase-protected recovery
// identity usable when an optional platform identity store is unavailable.
// The volume itself remains transactional; only a failed optional hook is
// downgraded to a warning.
func initVolumeWithOptionalIdentity(
	ctx context.Context,
	cipherDir string,
	prompter Prompter,
	identityHook func(PublicConfig, *age.X25519Identity) error,
) (configured bool, configureErr error, err error) {
	err = initVolume(
		ctx,
		cipherDir,
		prompter,
		func(public PublicConfig, identity *age.X25519Identity) error {
			configureErr = identityHook(public, identity)
			return nil
		},
	)
	if err != nil {
		return false, nil, err
	}
	return configureErr == nil, configureErr, nil
}

func ChangePassphrase(ctx context.Context, cipherDir string, prompter Prompter) error {
	public, err := loadPublicConfig(cipherDir)
	if err != nil {
		return err
	}
	privateData, err := unlockPrivateConfig(ctx, cipherDir, public, prompter, PromptRequest{
		Path:        cipherDir,
		Operation:   "change passphrase",
		Description: "Enter the current PassFS passphrase.",
	})
	if err != nil {
		return err
	}
	defer wipe(privateData)

	newPassphrase, err := prompter.Prompt(ctx, PromptRequest{
		Path:        cipherDir,
		Operation:   "change passphrase",
		Description: "Choose a new PassFS recovery passphrase.",
	})
	if err != nil {
		return err
	}
	confirmation, err := prompter.Prompt(ctx, PromptRequest{
		Path:        cipherDir,
		Operation:   "change passphrase",
		Description: "Confirm the new PassFS recovery passphrase.",
	})
	if err != nil {
		return err
	}
	if newPassphrase != confirmation {
		return errors.New("passphrases do not match")
	}
	if newPassphrase == "" {
		return errors.New("passphrase cannot be empty")
	}
	return writePassphraseEncryptedFile(
		filepath.Join(cipherDir, internalDirName, identityFileName),
		privateData,
		newPassphrase,
	)
}

func loadPublicConfig(cipherDir string) (PublicConfig, error) {
	var config PublicConfig
	file, err := os.Open(filepath.Join(cipherDir, internalDirName, publicConfigName))
	if err != nil {
		return config, fmt.Errorf("read public config: %w", err)
	}
	defer file.Close()
	if err := decodeBoundedJSON(file, 1024*1024, &config); err != nil {
		return config, fmt.Errorf("parse public config: %w", err)
	}
	if config.Version != formatVersion {
		return config, fmt.Errorf("unsupported volume format version %d", config.Version)
	}
	if config.VolumeID == "" || config.Recipient == "" {
		return config, errors.New("invalid public config")
	}
	return config, nil
}

func unlockPrivateConfig(
	ctx context.Context,
	cipherDir string,
	public PublicConfig,
	prompter Prompter,
	request PromptRequest,
) ([]byte, error) {
	passphrase, err := prompter.Prompt(ctx, request)
	if err != nil {
		return nil, err
	}
	scryptIdentity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, ErrAuthentication
	}

	encrypted, err := os.Open(filepath.Join(cipherDir, internalDirName, identityFileName))
	if err != nil {
		return nil, fmt.Errorf("open encrypted identity: %w", err)
	}
	defer encrypted.Close()
	reader, err := age.Decrypt(encrypted, scryptIdentity)
	if err != nil {
		return nil, ErrAuthentication
	}
	data, err := io.ReadAll(io.LimitReader(reader, 64*1024+1))
	if err != nil {
		return nil, fmt.Errorf("decrypt volume identity: %w", err)
	}
	if len(data) > 64*1024 {
		wipe(data)
		return nil, errors.New("private config is unexpectedly large")
	}

	var private privateConfig
	if err := json.Unmarshal(data, &private); err != nil {
		wipe(data)
		return nil, errors.New("invalid private config")
	}
	if private.Version != public.Version || private.VolumeID != public.VolumeID {
		wipe(data)
		return nil, errors.New("private config does not match public config")
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(private.Identity))
	if err != nil || identity.Recipient().String() != public.Recipient {
		wipe(data)
		return nil, errors.New("private identity does not match public recipient")
	}
	return data, nil
}

func parsePrivateIdentity(data []byte) (*age.X25519Identity, error) {
	var private privateConfig
	if err := json.Unmarshal(data, &private); err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.TrimSpace(private.Identity))
}

func writePassphraseEncryptedFile(path string, plaintext []byte, passphrase string) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}

	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return err
	}
	if _, err := writer.Write(plaintext); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return WriteFileAtomic(path, ciphertext.Bytes(), 0o600)
}

func ensureEmptyDirectory(path string) error {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(path, 0o700)
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s is not empty", path)
	}
	return nil
}

// WriteFileAtomic replaces path only after the complete contents have been
// written and synced.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".passfs-config-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)

	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

// WriteJSONFileAtomic encodes indented JSON and publishes it with the same
// durability guarantees as WriteFileAtomic.
func WriteJSONFileAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return WriteFileAtomic(path, data, mode)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil &&
		!errors.Is(err, os.ErrInvalid) &&
		!errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func decodeBoundedJSON(reader io.Reader, maximum int64, destination any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maximum {
		return errors.New("JSON document exceeds the maximum size")
	}
	return json.Unmarshal(data, destination)
}

func wipe(data []byte) {
	clear(data)
}
