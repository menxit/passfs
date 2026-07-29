package passfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	editSessionBegin = "begin:"
	editSessionEnd   = "end:"
)

func BeginEditSession(targetPath string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate edit session token: %w", err)
	}
	token := hex.EncodeToString(random)
	if err := setControlXattr(
		targetPath,
		editSessionMarkerName,
		[]byte(editSessionBegin+token),
	); err != nil {
		return "", err
	}
	return token, nil
}

func EndEditSession(targetPath, token string) error {
	if err := validateEditSessionToken(token); err != nil {
		return err
	}
	return setControlXattr(
		targetPath,
		editSessionMarkerName,
		[]byte(editSessionEnd+token),
	)
}

func parseEditSessionCommand(value []byte) (operation, token string, err error) {
	command := string(value)
	switch {
	case strings.HasPrefix(command, editSessionBegin):
		operation = "begin"
		token = strings.TrimPrefix(command, editSessionBegin)
	case strings.HasPrefix(command, editSessionEnd):
		operation = "end"
		token = strings.TrimPrefix(command, editSessionEnd)
	default:
		return "", "", errors.New("invalid edit session command")
	}
	if err := validateEditSessionToken(token); err != nil {
		return "", "", err
	}
	return operation, token, nil
}

func validateEditSessionToken(token string) error {
	if len(token) != 32 {
		return errors.New("invalid edit session token")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return errors.New("invalid edit session token")
	}
	return nil
}
