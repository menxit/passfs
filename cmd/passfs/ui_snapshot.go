package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"passfs/internal/passfs"
	"passfs/internal/updater"
)

type uiSnapshot struct {
	Unprotected               []uiFileRecord     `json:"unprotected,omitempty"`
	Protected                 []uiFileRecord     `json:"protected"`
	Recovery                  []uiRecoveryRecord `json:"recovery"`
	Ignored                   []uiFileRecord     `json:"ignored"`
	TouchID                   bool               `json:"touchID"`
	UnlockDurationNanoseconds int64              `json:"unlockDurationNanoseconds"`
	UnlockScope               passfs.UnlockScope `json:"unlockScope"`
	Initialized               bool               `json:"initialized"`
	Mounted                   bool               `json:"mounted"`
	AvailableUpdate           string             `json:"availableUpdate,omitempty"`
}

type uiFileRecord struct {
	Path               string `json:"path"`
	Project            string `json:"project"`
	Size               int64  `json:"size"`
	LastOpenedUnixNano int64  `json:"lastOpenedUnixNano"`
	Preview            string `json:"preview,omitempty"`
}

type uiRecoveryRecord struct {
	Path             string `json:"path"`
	Project          string `json:"project"`
	State            string `json:"state"`
	ObservedUnixNano int64  `json:"observedUnixNano"`
	Size             uint64 `json:"size"`
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
		Protected: []uiFileRecord{},
		Recovery:  []uiRecoveryRecord{},
		Ignored:   []uiFileRecord{},
	}

	if !noScan {
		var findings []string
		var scanOutput bytes.Buffer
		if err := runScan(
			[]string{"--json", "--config", common.configPath},
			&scanOutput,
			stderr,
		); err != nil {
			return err
		}
		if err := json.Unmarshal(scanOutput.Bytes(), &findings); err != nil {
			return err
		}
		result.Unprotected = uiFileRecords(findings, true)
	}
	ignored, err := loadScanIgnoredPaths(common.configPath)
	if err != nil {
		return err
	}
	result.Ignored = uiFileRecords(sortedPathSet(ignored), false)

	settings, err := passfs.LoadSettings(common.configPath)
	if errors.Is(err, os.ErrNotExist) {
		result.AvailableUpdate = availableUpdateVersion()
		return writeJSON(stdout, result)
	}
	if err != nil {
		return err
	}
	result.Initialized = true
	protected, err := passfs.ProtectedFiles(settings.Vault)
	if err != nil {
		return err
	}
	result.Protected = uiProtectedFileRecords(protected)
	recovery, err := passfs.RecoveryItems(settings.Vault)
	if err != nil {
		return err
	}
	result.Recovery = uiRecoveryFileRecords(recovery)
	unlockFor, err := settings.UnlockDuration()
	if err != nil {
		return err
	}
	result.UnlockDurationNanoseconds = int64(unlockFor)
	result.UnlockScope, err = settings.AuthorizationScope()
	if err != nil {
		return err
	}
	result.TouchID = uiTouchIDEnabled(settings)
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	result.Mounted = mount.mounted && mount.passfs && mount.healthy
	result.AvailableUpdate = availableUpdateVersion()
	return writeJSON(stdout, result)
}

func uiFileRecords(paths []string, includePreview bool) []uiFileRecord {
	result := make([]uiFileRecord, 0, len(paths))
	projects := make(map[string]string)
	for _, path := range paths {
		record := uiFileRecord{
			Path:    path,
			Project: scanProjectName(path, projects),
		}
		if info, err := os.Stat(path); err == nil {
			record.Size = info.Size()
			record.LastOpenedUnixNano = scanFileLastOpened(info).UnixNano()
		}
		if includePreview {
			record.Preview = maskedScanPreview(path)
		}
		result = append(result, record)
	}
	return result
}

func uiProtectedFileRecords(files []passfs.ProtectedFile) []uiFileRecord {
	result := make([]uiFileRecord, 0, len(files))
	projects := make(map[string]string)
	for _, file := range files {
		lastOpened := file.AccessedUnixNano
		if lastOpened <= 0 {
			lastOpened = file.ModifiedUnixNano
		}
		result = append(result, uiFileRecord{
			Path:               file.Path,
			Project:            scanProjectName(file.Path, projects),
			Size:               int64(file.Size),
			LastOpenedUnixNano: lastOpened,
		})
	}
	return result
}

func uiRecoveryFileRecords(items []passfs.RecoveryItem) []uiRecoveryRecord {
	result := make([]uiRecoveryRecord, 0, len(items))
	projects := make(map[string]string)
	for _, item := range items {
		result = append(result, uiRecoveryRecord{
			Path:             item.Path,
			Project:          scanProjectName(item.Path, projects),
			State:            string(item.State),
			ObservedUnixNano: item.ObservedUnixNano,
			Size:             item.Size,
		})
	}
	return result
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
