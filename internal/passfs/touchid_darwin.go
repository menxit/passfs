//go:build darwin

package passfs

/*
#cgo LDFLAGS: -framework AppKit -framework Foundation -framework LocalAuthentication -framework Security

#include <stdlib.h>

enum {
	PASSFS_TOUCHID_SUCCESS = 0,
	PASSFS_TOUCHID_NOT_FOUND = 1,
	PASSFS_TOUCHID_CANCELLED = 2,
	PASSFS_TOUCHID_AUTHENTICATION_FAILED = 3,
	PASSFS_TOUCHID_ERROR = 4,
	PASSFS_TOUCHID_MISSING_ENTITLEMENT = 5
};

int passfs_touchid_available(char **error_message);
int passfs_touchid_store(
	const char *identifier,
	const unsigned char *secret,
	long secret_length,
	char **error_message
);
int passfs_touchid_copy(
	const char *identifier,
	const char *reason,
	unsigned char **secret,
	long *secret_length,
	char **error_message
);
int passfs_touchid_delete(const char *identifier, char **error_message);
int passfs_touchid_exists(const char *identifier, char **error_message);
int passfs_touchid_prepare_ui(char **error_message);
int passfs_touchid_parent_is_trusted(int parent_pid, char **error_message);
void passfs_free_secret(unsigned char *secret, long length);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"filippo.io/age"
)

const touchIDRightPrefix = "com.menxit.passfs.identity."
const touchIDPromptTimeout = 45 * time.Second

var (
	ErrTouchIDNotConfigured    = errors.New("Touch ID is not configured for this passfs volume")
	ErrTouchIDAuthentication   = errors.New("Touch ID authentication failed")
	ErrTouchIDInProgress       = errors.New("another Touch ID authorization is already in progress")
	ErrTouchIDTimeout          = errors.New("Touch ID authorization timed out")
	ErrTouchIDUnsupportedBuild = errors.New(
		"this passfs build cannot use Touch ID; macOS requires a signed app bundle with Keychain entitlements",
	)
)

type TouchIDPrompter struct {
	volumeID     string
	recipient    string
	copyIdentity func(string, string) ([]byte, error)
	timeout      time.Duration

	mu     sync.Mutex
	active bool
}

func InitVolumePreferTouchID(
	ctx context.Context,
	cipherDir string,
	prompter Prompter,
) (enabled bool, warning error, err error) {
	if err := requireTouchIDAvailable(); err != nil {
		initErr := InitVolume(ctx, cipherDir, prompter)
		return false, err, initErr
	}
	var volumeID string
	enabled, warning, err = initVolumeWithOptionalIdentity(
		ctx,
		cipherDir,
		prompter,
		func(public PublicConfig, identity *age.X25519Identity) error {
			volumeID = public.VolumeID
			return storeTouchIDIdentity(public, identity)
		},
	)
	if err != nil || warning == nil || volumeID == "" {
		return enabled, warning, err
	}
	if !errors.Is(warning, ErrTouchIDUnsupportedBuild) {
		if cleanupErr := touchIDDelete(volumeID); cleanupErr != nil {
			warning = errors.Join(
				warning,
				fmt.Errorf("clean up incomplete Touch ID state: %w", cleanupErr),
			)
		}
	}
	return false, warning, nil
}

func NewTouchIDPrompter(cipherDir string) (Prompter, error) {
	public, err := loadPublicConfig(cipherDir)
	if err != nil {
		return nil, err
	}
	return &TouchIDPrompter{
		volumeID:     public.VolumeID,
		recipient:    public.Recipient,
		copyIdentity: touchIDCopy,
		timeout:      touchIDPromptTimeout,
	}, nil
}

func (p *TouchIDPrompter) Prompt(
	context.Context,
	PromptRequest,
) (string, error) {
	return "", errors.New("Touch ID provides an age identity, not a passphrase")
}

func (p *TouchIDPrompter) PromptIdentity(
	ctx context.Context,
	request PromptRequest,
) (*age.X25519Identity, error) {
	p.mu.Lock()
	if p.active {
		p.mu.Unlock()
		return nil, ErrTouchIDInProgress
	}
	p.active = true
	p.mu.Unlock()

	select {
	case <-ctx.Done():
		p.mu.Lock()
		p.active = false
		p.mu.Unlock()
		return nil, ctx.Err()
	default:
	}

	type copyResult struct {
		secret []byte
		err    error
	}
	result := make(chan copyResult)
	abandoned := make(chan struct{})
	go func() {
		secret, err := p.copyIdentity(p.volumeID, DescribePrompt(request))
		p.mu.Lock()
		p.active = false
		p.mu.Unlock()
		select {
		case result <- copyResult{secret: secret, err: err}:
		case <-abandoned:
			wipe(secret)
		}
	}()

	timer := time.NewTimer(p.timeout)
	defer timer.Stop()

	var copied copyResult
	select {
	case <-ctx.Done():
		close(abandoned)
		return nil, ctx.Err()
	case <-timer.C:
		close(abandoned)
		return nil, ErrTouchIDTimeout
	case copied = <-result:
		close(abandoned)
	}
	if copied.err != nil {
		return nil, copied.err
	}
	secret := copied.secret
	defer wipe(secret)
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(secret)))
	if err != nil || identity.Recipient().String() != p.recipient {
		return nil, errors.New("Touch ID identity does not match the passfs volume")
	}
	return identity, nil
}

func EnableTouchID(
	ctx context.Context,
	cipherDir string,
	prompter Prompter,
) error {
	if err := requireTouchIDAvailable(); err != nil {
		return err
	}
	public, err := loadPublicConfig(cipherDir)
	if err != nil {
		return err
	}
	privateData, err := unlockPrivateConfig(
		ctx,
		cipherDir,
		public,
		prompter,
		PromptRequest{
			Path:        cipherDir,
			Operation:   "enable Touch ID",
			Description: "Enter the passfs passphrase to enable Touch ID",
		},
	)
	if err != nil {
		return err
	}
	defer wipe(privateData)
	identity, err := parsePrivateIdentity(privateData)
	if err != nil {
		return fmt.Errorf("parse passfs identity: %w", err)
	}
	return storeTouchIDIdentity(public, identity)
}

func DisableTouchID(cipherDir string) error {
	public, err := loadPublicConfig(cipherDir)
	if err != nil {
		return err
	}
	return touchIDDelete(public.VolumeID)
}

func TouchIDConfigured(cipherDir string) (bool, error) {
	public, err := loadPublicConfig(cipherDir)
	if err != nil {
		return false, err
	}
	return touchIDExists(public.VolumeID)
}

func VerifyTouchID(ctx context.Context, cipherDir string) error {
	prompter, err := NewTouchIDPrompter(cipherDir)
	if err != nil {
		return err
	}
	identityPrompter, ok := prompter.(IdentityPrompter)
	if !ok {
		return errors.New("Touch ID identity prompter is unavailable")
	}
	_, err = identityPrompter.PromptIdentity(ctx, PromptRequest{
		Path:        cipherDir,
		Operation:   "verify Touch ID",
		Description: "Verify Touch ID for passfs",
	})
	return err
}

func PrepareTouchIDUI() error {
	var errorMessage *C.char
	status := C.passfs_touchid_prepare_ui(&errorMessage)
	return touchIDStatusError(status, errorMessage)
}

func ValidateTouchIDHelperParent(parentPID int) error {
	if parentPID <= 1 {
		return errors.New("Touch ID helper requires a passfs service parent")
	}
	var errorMessage *C.char
	status := C.passfs_touchid_parent_is_trusted(
		C.int(parentPID),
		&errorMessage,
	)
	return touchIDStatusError(status, errorMessage)
}

func TouchIDIdentity(cipherDir, reason string) (*age.X25519Identity, error) {
	public, err := loadPublicConfig(cipherDir)
	if err != nil {
		return nil, err
	}
	secret, err := touchIDCopy(public.VolumeID, reason)
	if err != nil {
		return nil, err
	}
	defer wipe(secret)
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(secret)))
	if err != nil || identity.Recipient().String() != public.Recipient {
		return nil, errors.New("Touch ID identity does not match the passfs volume")
	}
	return identity, nil
}

func storeTouchIDIdentity(
	public PublicConfig,
	identity *age.X25519Identity,
) error {
	if identity.Recipient().String() != public.Recipient {
		return errors.New("Touch ID identity does not match the passfs volume")
	}
	secret := []byte(identity.String())
	defer wipe(secret)
	return touchIDStore(public.VolumeID, secret)
}

func touchIDStore(volumeID string, secret []byte) error {
	if len(secret) == 0 {
		return errors.New("refusing to store an empty passfs identity")
	}
	identifier := C.CString(touchIDIdentifier(volumeID))
	defer C.free(unsafe.Pointer(identifier))

	var errorMessage *C.char
	status := C.passfs_touchid_store(
		identifier,
		(*C.uchar)(unsafe.Pointer(&secret[0])),
		C.long(len(secret)),
		&errorMessage,
	)
	return touchIDStatusError(status, errorMessage)
}

func touchIDCopy(volumeID, prompt string) ([]byte, error) {
	identifier := C.CString(touchIDIdentifier(volumeID))
	promptValue := C.CString(prompt)
	defer C.free(unsafe.Pointer(identifier))
	defer C.free(unsafe.Pointer(promptValue))

	var secret *C.uchar
	var secretLength C.long
	var errorMessage *C.char
	status := C.passfs_touchid_copy(
		identifier,
		promptValue,
		&secret,
		&secretLength,
		&errorMessage,
	)
	if status != C.PASSFS_TOUCHID_SUCCESS {
		return nil, touchIDStatusError(status, errorMessage)
	}
	defer C.passfs_free_secret(secret, secretLength)
	return C.GoBytes(unsafe.Pointer(secret), C.int(secretLength)), nil
}

func touchIDDelete(volumeID string) error {
	identifier := C.CString(touchIDIdentifier(volumeID))
	defer C.free(unsafe.Pointer(identifier))

	var errorMessage *C.char
	status := C.passfs_touchid_delete(identifier, &errorMessage)
	if status == C.PASSFS_TOUCHID_NOT_FOUND {
		freeCError(errorMessage)
		return nil
	}
	return touchIDStatusError(status, errorMessage)
}

func touchIDExists(volumeID string) (bool, error) {
	identifier := C.CString(touchIDIdentifier(volumeID))
	defer C.free(unsafe.Pointer(identifier))

	var errorMessage *C.char
	status := C.passfs_touchid_exists(identifier, &errorMessage)
	if status == C.PASSFS_TOUCHID_NOT_FOUND {
		freeCError(errorMessage)
		return false, nil
	}
	if err := touchIDStatusError(status, errorMessage); err != nil {
		return false, err
	}
	return true, nil
}

func touchIDIdentifier(volumeID string) string {
	return touchIDRightPrefix + volumeID
}

func requireTouchIDAvailable() error {
	var errorMessage *C.char
	if C.passfs_touchid_available(&errorMessage) != 0 {
		freeCError(errorMessage)
		return nil
	}
	description := cErrorDescription(
		errorMessage,
		"Touch ID is unavailable or has no enrolled fingerprints",
	)
	return fmt.Errorf("Touch ID is unavailable: %s", description)
}

func touchIDStatusError(status C.int, message *C.char) error {
	if status == C.PASSFS_TOUCHID_SUCCESS {
		freeCError(message)
		return nil
	}
	description := cErrorDescription(message, "unknown LocalAuthentication error")
	switch status {
	case C.PASSFS_TOUCHID_NOT_FOUND:
		return fmt.Errorf(
			"%w; run \"passfs touchid enable\"",
			ErrTouchIDNotConfigured,
		)
	case C.PASSFS_TOUCHID_CANCELLED:
		return ErrPromptCancelled
	case C.PASSFS_TOUCHID_AUTHENTICATION_FAILED:
		return fmt.Errorf("%w: %s", ErrTouchIDAuthentication, description)
	case C.PASSFS_TOUCHID_MISSING_ENTITLEMENT:
		return fmt.Errorf("%w: %s", ErrTouchIDUnsupportedBuild, description)
	default:
		return fmt.Errorf("Touch ID error: %s", description)
	}
}

func cErrorDescription(message *C.char, fallback string) string {
	if message == nil {
		return fallback
	}
	description := C.GoString(message)
	C.free(unsafe.Pointer(message))
	return description
}

func freeCError(message *C.char) {
	if message != nil {
		C.free(unsafe.Pointer(message))
	}
}
