package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"passfs/internal/passfs"
	"passfs/internal/updater"
)

type uiSnapshot struct {
	Unprotected               []string               `json:"unprotected,omitempty"`
	Protected                 []passfs.ProtectedFile `json:"protected"`
	Ignored                   []string               `json:"ignored"`
	TouchID                   bool                   `json:"touchID"`
	UnlockDurationNanoseconds int64                  `json:"unlockDurationNanoseconds"`
	Initialized               bool                   `json:"initialized"`
	Mounted                   bool                   `json:"mounted"`
	AvailableUpdate           string                 `json:"availableUpdate,omitempty"`
	StateDirectory            string                 `json:"stateDirectory,omitempty"`
	VaultMetadataDirectory    string                 `json:"vaultMetadataDirectory,omitempty"`
}

func runUISnapshot(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("__ui-status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var noScan bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(&noScan, "no-scan", false, "omit plaintext secret discovery")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("invalid UI status request")
	}
	result := uiSnapshot{
		Protected: []passfs.ProtectedFile{},
		Ignored:   []string{},
	}

	if !noScan {
		result.Unprotected = []string{}
		var scanOutput bytes.Buffer
		if err := runScan(
			[]string{"--json", "--config", common.configPath},
			&scanOutput,
			stderr,
		); err != nil {
			return err
		}
		if err := json.Unmarshal(scanOutput.Bytes(), &result.Unprotected); err != nil {
			return err
		}
	}
	ignored, err := loadScanIgnoredPaths(common.configPath)
	if err != nil {
		return err
	}
	result.Ignored = sortedPathSet(ignored)

	settings, err := passfs.LoadSettings(common.configPath)
	if errors.Is(err, os.ErrNotExist) {
		result.AvailableUpdate = availableUpdateVersion()
		return writeJSON(stdout, result)
	}
	if err != nil {
		return err
	}
	result.Initialized = true
	result.StateDirectory = filepath.Dir(settings.Path())
	result.VaultMetadataDirectory = filepath.Join(settings.Vault, ".passfs")
	result.Protected, err = passfs.ProtectedFiles(settings.Vault)
	if err != nil {
		return err
	}
	unlockFor, err := settings.UnlockDuration()
	if err != nil {
		return err
	}
	result.UnlockDurationNanoseconds = int64(unlockFor)
	result.TouchID = uiTouchIDEnabled(settings)
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	result.Mounted = mount.mounted && mount.passfs && mount.healthy
	result.AvailableUpdate = availableUpdateVersion()
	return writeJSON(stdout, result)
}

func availableUpdateVersion() string {
	path, err := updateStatePath()
	if err != nil {
		return ""
	}
	state, err := updater.LoadState(path)
	if err != nil || state.Available == "" {
		return ""
	}
	newer, err := updater.IsNewer(state.Available, version)
	if err != nil || !newer {
		return ""
	}
	return state.Available
}
