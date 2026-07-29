package updater

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const stateVersion = 1

type State struct {
	Version      int       `json:"version"`
	CheckedAt    time.Time `json:"checkedAt"`
	Available    string    `json:"available,omitempty"`
	LastNotified string    `json:"lastNotified,omitempty"`
}

func LoadState(path string) (State, error) {
	var state State
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.Version != stateVersion {
		return State{}, errors.New("unsupported update state version")
	}
	return state, nil
}

func SaveState(path string, state State) error {
	state.Version = stateVersion
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".update-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
