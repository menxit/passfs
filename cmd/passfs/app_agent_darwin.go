//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"passfs/internal/passfs"
)

const (
	passFSAppGroupIdentifier = "3943PK2P39.com.menxit.passfs.shared"
	passFSAppIdentifier      = "com.menxit.passfs"
	appAgentRequestLimit     = 64 * 1024
	appAgentResponseLimit    = 16 * 1024 * 1024
	appAgentCommandTimeout   = 15 * time.Minute
	appAgentBackupTimeout    = 2 * time.Hour
	appAgentMaximumClients   = 4
)

func runPlatformAppAgent(stderr io.Writer) error {
	socketPath, err := appAgentSocketPath()
	if err != nil {
		return err
	}
	listener, err := listenAppAgent(socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var workers sync.WaitGroup
	defer workers.Wait()
	clients := make(chan struct{}, appAgentMaximumClients)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			fmt.Fprintf(stderr, "passfs control agent: accept: %v\n", err)
			continue
		}
		select {
		case clients <- struct{}{}:
		case <-ctx.Done():
			_ = connection.Close()
			return nil
		default:
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			writeAppAgentResponse(connection, appAgentResponse{
				Version: appAgentProtocolVersion,
				Error:   "PassFS control agent is busy",
			})
			_ = connection.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-clients }()
			handleAppAgentConnection(connection)
		}()
	}
}

func appAgentSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate user home: %w", err)
	}
	directory := filepath.Join(
		home,
		"Library",
		"Group Containers",
		passFSAppGroupIdentifier,
		"Control",
	)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create PassFS control directory: %w", err)
	}
	if err := validatePrivateAgentDirectory(directory); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "agent.sock")
	if len(path) >= len(syscall.RawSockaddrUnix{}.Path) {
		return "", errors.New("PassFS control socket path is too long")
	}
	return path, nil
}

func validatePrivateAgentDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect PassFS control directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
		return errors.New("PassFS control directory is not private to the current user")
	}
	return nil
}

func listenAppAgent(path string) (*net.UnixListener, error) {
	address := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err == nil {
		listener.SetUnlinkOnClose(true)
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			_ = listener.Close()
			return nil, chmodErr
		}
		return listener, nil
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, fmt.Errorf("listen for PassFS app commands: %w", err)
	}
	probe, probeErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if probeErr == nil {
		_ = probe.Close()
		return nil, errors.New("another PassFS control agent is already running")
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		return nil, fmt.Errorf("inspect stale PassFS control socket: %w", statErr)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("refusing to replace an unsafe PassFS control socket")
	}
	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("remove stale PassFS control socket: %w", err)
	}
	return listenAppAgent(path)
}

func handleAppAgentConnection(connection *net.UnixConn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(appAgentCommandTimeout))
	if err := passfs.ValidateSignedLocalPeer(connection, passFSAppIdentifier); err != nil {
		writeAppAgentResponse(connection, appAgentResponse{
			Version: appAgentProtocolVersion,
			Error:   "untrusted PassFS app client",
		})
		return
	}
	var request appAgentRequest
	decoder := json.NewDecoder(io.LimitReader(connection, appAgentRequestLimit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeAppAgentResponse(connection, appAgentResponse{
			Version: appAgentProtocolVersion,
			Error:   "invalid PassFS app request",
		})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeAppAgentResponse(connection, appAgentResponse{
			Version: appAgentProtocolVersion,
			Error:   "invalid trailing PassFS app request data",
		})
		return
	}
	_ = connection.SetDeadline(
		time.Now().Add(appAgentTimeout(request.Operation)),
	)
	writeAppAgentResponse(connection, executeAppAgentRequest(request))
}

func appAgentTimeout(operation appAgentOperation) time.Duration {
	switch operation {
	case appAgentBackupCreate, appAgentBackupVerify, appAgentBackupRestore:
		return appAgentBackupTimeout
	default:
		return appAgentCommandTimeout
	}
}

func writeAppAgentResponse(writer io.Writer, response appAgentResponse) {
	data, err := json.Marshal(response)
	if err != nil || len(data)+1 > appAgentResponseLimit {
		data, _ = json.Marshal(appAgentResponse{
			Version: appAgentProtocolVersion,
			Error:   "PassFS app response is too large",
		})
	}
	data = append(data, '\n')
	_, _ = writer.Write(data)
}
