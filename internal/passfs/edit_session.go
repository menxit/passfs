package passfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	sessionBegin = "begin:"
	sessionEnd   = "end:"
)

func BeginEditSession(targetPath string) (string, error) {
	return beginControlSession(
		targetPath,
		editSessionMarkerName,
		"edit session",
	)
}

func EndEditSession(targetPath, token string) error {
	return endControlSession(targetPath, editSessionMarkerName, token)
}

func beginControlSession(
	targetPath string,
	markerName string,
	description string,
) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate %s token: %w", description, err)
	}
	token := hex.EncodeToString(random)
	if err := setControlXattr(
		targetPath,
		markerName,
		[]byte(sessionBegin+token),
	); err != nil {
		return "", err
	}
	return token, nil
}

func endControlSession(targetPath, markerName, token string) error {
	if err := validateSessionToken(token); err != nil {
		return err
	}
	return setControlXattr(
		targetPath,
		markerName,
		[]byte(sessionEnd+token),
	)
}

func parseSessionCommand(value []byte) (operation, token string, err error) {
	command := string(value)
	switch {
	case strings.HasPrefix(command, sessionBegin):
		operation = "begin"
		token = strings.TrimPrefix(command, sessionBegin)
	case strings.HasPrefix(command, sessionEnd):
		operation = "end"
		token = strings.TrimPrefix(command, sessionEnd)
	default:
		return "", "", errors.New("invalid session command")
	}
	if err := validateSessionToken(token); err != nil {
		return "", "", err
	}
	return operation, token, nil
}

func validateSessionToken(token string) error {
	if len(token) != 32 {
		return errors.New("invalid session token")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return errors.New("invalid session token")
	}
	return nil
}
