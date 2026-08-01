//go:build darwin

package passfs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	authorizationBrokerProtocolVersion = 1
	authorizationBrokerMessageLimit    = 16 * 1024
	authorizationBrokerPassphraseLimit = 4 * 1024
	authorizationBrokerTimeout         = 50 * time.Second
	passFSCLIIdentifier                = "com.menxit.passfs"
	passFSFSKitIdentifier              = "com.menxit.passfs.filesystem"
	passFSAppGroupIdentifier           = "3943PK2P39.com.menxit.passfs.shared"
)

type authorizationBrokerRequest struct {
	Version     int    `json:"version"`
	Path        string `json:"path,omitempty"`
	Operation   string `json:"operation,omitempty"`
	Description string `json:"description,omitempty"`
}

type authorizationBrokerResponse struct {
	Version    int    `json:"version"`
	Passphrase string `json:"passphrase,omitempty"`
	Error      string `json:"error,omitempty"`
	Code       string `json:"code,omitempty"`
}

type authorizationPeerValidator func(*net.UnixConn, string) error

// PassphraseBroker presents native passphrase dialogs outside the sandboxed
// FSKit extension. The socket lives in the shared PassFS app-group container,
// and both peers verify the other process before any prompt or secret is
// exchanged. No passphrase is persisted in that container.
type PassphraseBroker struct {
	listener *net.UnixListener
	prompter Prompter
	validate authorizationPeerValidator
	ctx      context.Context
	cancel   context.CancelFunc
	closed   sync.Once
	workers  sync.WaitGroup
	mu       sync.Mutex
	clients  map[*net.UnixConn]struct{}
	closing  bool
}

// StartFSKitPassphraseBroker starts the trusted host side used when an FSKit
// volume is configured for passphrase authorization.
func StartFSKitPassphraseBroker(
	vault string,
	prompter Prompter,
) (*PassphraseBroker, error) {
	return startFSKitPassphraseBroker(vault, prompter, validateAuthorizationPeer)
}

func startFSKitPassphraseBroker(
	vault string,
	prompter Prompter,
	validate authorizationPeerValidator,
) (*PassphraseBroker, error) {
	runtimeDirectory, err := authorizationBrokerRuntimeDirectory(true)
	if err != nil {
		return nil, err
	}
	return startFSKitPassphraseBrokerIn(
		vault,
		prompter,
		validate,
		runtimeDirectory,
	)
}

func startFSKitPassphraseBrokerIn(
	vault string,
	prompter Prompter,
	validate authorizationPeerValidator,
	runtimeDirectory string,
) (*PassphraseBroker, error) {
	if prompter == nil {
		return nil, errors.New("passphrase broker requires a prompter")
	}
	path, err := authorizationBrokerSocketPathIn(vault, runtimeDirectory)
	if err != nil {
		return nil, err
	}
	listener, err := listenAuthorizationSocket(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("protect FSKit authorization socket: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	broker := &PassphraseBroker{
		listener: listener,
		prompter: prompter,
		validate: validate,
		ctx:      ctx,
		cancel:   cancel,
		clients:  make(map[*net.UnixConn]struct{}),
	}
	broker.workers.Add(1)
	go broker.serve()
	return broker, nil
}

func listenAuthorizationSocket(path string) (*net.UnixListener, error) {
	if len(path) >= len(syscall.RawSockaddrUnix{}.Path) {
		return nil, fmt.Errorf("FSKit authorization socket path is too long: %s", path)
	}
	address := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err == nil {
		listener.SetUnlinkOnClose(true)
		return listener, nil
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, fmt.Errorf("listen for FSKit passphrase authorization: %w", err)
	}

	probe, probeErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if probeErr == nil {
		_ = probe.Close()
		return nil, errors.New("another FSKit passphrase broker is already running")
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		return nil, fmt.Errorf("inspect stale FSKit authorization socket: %w", statErr)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("refusing to replace an unsafe FSKit authorization socket")
	}
	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("remove stale FSKit authorization socket: %w", err)
	}
	listener, err = net.ListenUnix("unix", address)
	if err != nil {
		return nil, fmt.Errorf("listen for FSKit passphrase authorization: %w", err)
	}
	listener.SetUnlinkOnClose(true)
	return listener, nil
}

func (broker *PassphraseBroker) serve() {
	defer broker.workers.Done()
	for {
		connection, err := broker.listener.AcceptUnix()
		if err != nil {
			if broker.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		broker.mu.Lock()
		if broker.closing {
			broker.mu.Unlock()
			_ = connection.Close()
			return
		}
		broker.clients[connection] = struct{}{}
		broker.mu.Unlock()
		broker.workers.Add(1)
		go func() {
			defer broker.workers.Done()
			broker.handle(connection)
		}()
	}
}

func (broker *PassphraseBroker) handle(connection *net.UnixConn) {
	defer func() {
		broker.mu.Lock()
		delete(broker.clients, connection)
		broker.mu.Unlock()
		_ = connection.Close()
	}()
	deadline := time.Now().Add(authorizationBrokerTimeout)
	_ = connection.SetDeadline(deadline)
	if err := broker.validate(connection, passFSFSKitIdentifier); err != nil {
		_ = writeAuthorizationMessage(connection, authorizationBrokerResponse{
			Version: authorizationBrokerProtocolVersion,
			Error:   "untrusted FSKit authorization client",
			Code:    "untrusted",
		})
		return
	}

	var wireRequest authorizationBrokerRequest
	if err := readAuthorizationMessage(connection, &wireRequest); err != nil {
		_ = writeAuthorizationMessage(connection, authorizationBrokerResponse{
			Version: authorizationBrokerProtocolVersion,
			Error:   err.Error(),
			Code:    "invalid-request",
		})
		return
	}
	if err := validateAuthorizationRequest(wireRequest); err != nil {
		_ = writeAuthorizationMessage(connection, authorizationBrokerResponse{
			Version: authorizationBrokerProtocolVersion,
			Error:   err.Error(),
			Code:    "invalid-request",
		})
		return
	}

	promptContext, cancelPrompt := context.WithDeadline(
		broker.ctx,
		deadline,
	)
	defer cancelPrompt()
	passphrase, err := broker.prompter.Prompt(promptContext, PromptRequest{
		Path:        wireRequest.Path,
		Operation:   wireRequest.Operation,
		Description: wireRequest.Description,
	})
	response := authorizationBrokerResponse{
		Version:    authorizationBrokerProtocolVersion,
		Passphrase: passphrase,
	}
	if err != nil {
		response.Passphrase = ""
		response.Error = err.Error()
		response.Code = "prompt"
		if errors.Is(err, ErrPromptCancelled) {
			response.Code = "cancelled"
		} else if errors.Is(err, context.Canceled) {
			response.Code = "cancelled"
		}
	} else if passphrase == "" || len(passphrase) > authorizationBrokerPassphraseLimit {
		response.Passphrase = ""
		response.Error = "passphrase dialog returned an invalid value"
		response.Code = "prompt"
	}
	_ = writeAuthorizationMessage(connection, response)
}

func (broker *PassphraseBroker) Close() error {
	var closeErr error
	broker.closed.Do(func() {
		broker.cancel()
		broker.mu.Lock()
		broker.closing = true
		for client := range broker.clients {
			_ = client.Close()
		}
		broker.mu.Unlock()
		closeErr = broker.listener.Close()
		broker.workers.Wait()
	})
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

type fsKitPassphrasePrompter struct {
	socketPath string
	validate   authorizationPeerValidator
}

// NewFSKitPassphrasePrompter creates the sandboxed client used by the FSKit
// bridge. It intentionally implements passphrase prompting, not identity
// prompting, so decryption and identity validation remain inside the extension.
func NewFSKitPassphrasePrompter(vault string) (Prompter, error) {
	return newFSKitPassphrasePrompter(vault, validateAuthorizationPeer)
}

func newFSKitPassphrasePrompter(
	vault string,
	validate authorizationPeerValidator,
) (Prompter, error) {
	runtimeDirectory, err := authorizationBrokerRuntimeDirectory(false)
	if err != nil {
		return nil, err
	}
	return newFSKitPassphrasePrompterIn(
		vault,
		validate,
		runtimeDirectory,
	)
}

func newFSKitPassphrasePrompterIn(
	vault string,
	validate authorizationPeerValidator,
	runtimeDirectory string,
) (Prompter, error) {
	path, err := authorizationBrokerSocketPathIn(vault, runtimeDirectory)
	if err != nil {
		return nil, err
	}
	return &fsKitPassphrasePrompter{socketPath: path, validate: validate}, nil
}

func (prompter *fsKitPassphrasePrompter) Prompt(
	ctx context.Context,
	request PromptRequest,
) (string, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", prompter.socketPath)
	if err != nil {
		return "", fmt.Errorf("connect to PassFS passphrase dialog: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return "", errors.New("PassFS passphrase broker is not a Unix socket")
	}
	defer unixConnection.Close()
	deadline := time.Now().Add(authorizationBrokerTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = unixConnection.SetDeadline(deadline)
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = unixConnection.SetDeadline(time.Now())
	})
	defer stopCancellation()
	if err := prompter.validate(unixConnection, passFSCLIIdentifier); err != nil {
		return "", fmt.Errorf("verify PassFS passphrase broker: %w", err)
	}
	if err := writeAuthorizationMessage(unixConnection, authorizationBrokerRequest{
		Version:     authorizationBrokerProtocolVersion,
		Path:        request.Path,
		Operation:   request.Operation,
		Description: request.Description,
	}); err != nil {
		return "", err
	}

	var response authorizationBrokerResponse
	if err := readAuthorizationMessage(unixConnection, &response); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	if response.Version != authorizationBrokerProtocolVersion {
		return "", errors.New("unsupported PassFS authorization broker response")
	}
	if response.Error != "" {
		if response.Code == "cancelled" {
			return "", ErrPromptCancelled
		}
		return "", errors.New(response.Error)
	}
	if response.Passphrase == "" || len(response.Passphrase) > authorizationBrokerPassphraseLimit {
		return "", errors.New("PassFS passphrase broker returned an invalid value")
	}
	return response.Passphrase, nil
}

func authorizationBrokerSocketPathIn(
	vault string,
	runtimeDirectory string,
) (string, error) {
	public, err := loadPublicConfig(filepath.Clean(vault))
	if err != nil {
		return "", err
	}
	runtimeDirectory = filepath.Clean(runtimeDirectory)
	info, err := os.Lstat(runtimeDirectory)
	if err != nil {
		return "", fmt.Errorf("inspect PassFS runtime directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		stat.Uid != uint32(os.Geteuid()) ||
		info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("PassFS runtime directory is not private to the current user")
	}
	digest := sha256.Sum256([]byte(public.VolumeID))
	name := "p" + base64.RawURLEncoding.EncodeToString(digest[:12])
	path := filepath.Join(runtimeDirectory, name)
	if len(path) >= len(syscall.RawSockaddrUnix{}.Path) {
		return "", fmt.Errorf("FSKit authorization socket path is too long: %s", path)
	}
	return path, nil
}

func authorizationBrokerRuntimeDirectory(create bool) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate the current user's home directory: %w", err)
	}
	containerSuffix := filepath.Join(
		"Library",
		"Containers",
		passFSFSKitIdentifier,
		"Data",
	)
	if strings.HasSuffix(filepath.Clean(home), containerSuffix) {
		home = strings.TrimSuffix(filepath.Clean(home), containerSuffix)
		home = strings.TrimSuffix(home, string(os.PathSeparator))
	}
	runtimeDirectory := filepath.Join(
		home,
		"Library",
		"Group Containers",
		passFSAppGroupIdentifier,
		"Authorization",
	)
	if create {
		if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
			return "", fmt.Errorf("create PassFS authorization directory: %w", err)
		}
	}
	return runtimeDirectory, nil
}

func validateAuthorizationRequest(request authorizationBrokerRequest) error {
	if request.Version != authorizationBrokerProtocolVersion {
		return errors.New("unsupported PassFS authorization broker request")
	}
	if len(request.Path) > 4096 || strings.ContainsRune(request.Path, 0) ||
		len(request.Operation) > 128 || strings.ContainsRune(request.Operation, 0) ||
		len(request.Description) > 2048 || strings.ContainsRune(request.Description, 0) {
		return errors.New("invalid PassFS authorization request")
	}
	return nil
}

func writeAuthorizationMessage(connection io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data)+1 > authorizationBrokerMessageLimit {
		return errors.New("PassFS authorization message is too large")
	}
	data = append(data, '\n')
	_, err = io.Copy(connection, bytes.NewReader(data))
	return err
}

func readAuthorizationMessage(connection io.Reader, destination any) error {
	reader := bufio.NewReader(io.LimitReader(connection, authorizationBrokerMessageLimit+1))
	data, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read PassFS authorization message: %w", err)
	}
	if len(data) > authorizationBrokerMessageLimit {
		return errors.New("PassFS authorization message is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode PassFS authorization message: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("PassFS authorization message contains trailing data")
	}
	return nil
}

func validateAuthorizationPeer(
	connection *net.UnixConn,
	expectedIdentifier string,
) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var peerPID int
	var peerUID uint32
	var socketErr error
	if err := raw.Control(func(fileDescriptor uintptr) {
		peerPID, socketErr = unix.GetsockoptInt(
			int(fileDescriptor),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERPID,
		)
		if socketErr != nil {
			return
		}
		credentials, credentialErr := unix.GetsockoptXucred(
			int(fileDescriptor),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERCRED,
		)
		if credentialErr != nil {
			socketErr = credentialErr
			return
		}
		peerUID = credentials.Uid
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	if peerPID <= 1 || peerUID != uint32(os.Geteuid()) {
		return errors.New("PassFS authorization peer has invalid credentials")
	}
	return validateSignedPassFSProcess(peerPID, expectedIdentifier)
}

// ValidateSignedLocalPeer verifies that a Unix-socket peer has the current
// user's credentials and a valid PassFS signature from the same developer
// team as this process.
func ValidateSignedLocalPeer(
	connection *net.UnixConn,
	expectedIdentifier string,
) error {
	return validateAuthorizationPeer(connection, expectedIdentifier)
}
