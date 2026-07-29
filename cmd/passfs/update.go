package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"passfs/internal/passfs"
	"passfs/internal/updater"
)

const updateCheckInterval = 24 * time.Hour

func runUpdate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var checkOnly bool
	flags.BoolVar(&checkOnly, "check", false, "check for a new version without installing it")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs update [--check]")
	}

	client := newUpdateClient()
	fmt.Fprintln(stdout, "Checking for passfs updates...")
	release, err := client.Latest(context.Background())
	if err != nil {
		return err
	}
	newer, err := updater.IsNewer(release.Version, version)
	if err != nil {
		return fmt.Errorf("compare update version with %q: %w", version, err)
	}
	if err := recordAvailableUpdate(release.Version, newer); err != nil {
		fmt.Fprintf(stderr, "Warning: could not save update status: %v\n", err)
	}
	if !newer {
		fmt.Fprintf(stdout, "passfs %s is up to date\n", version)
		return nil
	}
	fmt.Fprintf(
		stdout,
		"passfs %s is available (current version: %s)\n",
		release.Version,
		version,
	)
	if checkOnly {
		fmt.Fprintln(stdout, "Install it with:")
		fmt.Fprintln(stdout, "  passfs update")
		return nil
	}

	result, err := installPlatformUpdate(
		context.Background(),
		client,
		release,
		stdout,
	)
	if err != nil {
		return err
	}
	if !result.installed {
		return nil
	}
	if result.reload {
		configPath, pathErr := passfs.DefaultSettingsPath()
		if pathErr != nil {
			return pathErr
		}
		if _, statErr := os.Stat(configPath); statErr == nil {
			command := exec.Command(
				result.executable,
				"reload",
				"--config",
				configPath,
			)
			command.Stdout = stdout
			command.Stderr = stderr
			if reloadErr := command.Run(); reloadErr != nil {
				return actionableError{
					"passfs was updated, but its service could not be reloaded: " + reloadErr.Error(),
					"retry with:",
					"  passfs reload",
				}
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	return nil
}

type platformUpdateResult struct {
	installed  bool
	reload     bool
	executable string
}

func newUpdateClient() *updater.Client {
	baseURL := strings.TrimSpace(os.Getenv("PASSFS_UPDATE_BASE"))
	if baseURL == "" {
		baseURL = updater.DefaultReleaseBaseURL
	}
	return updater.NewClient(baseURL)
}

func updateStatePath() (string, error) {
	settingsPath, err := passfs.DefaultSettingsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(settingsPath), "update.json"), nil
}

func recordAvailableUpdate(available string, newer bool) error {
	path, err := updateStatePath()
	if err != nil {
		return err
	}
	state, err := updater.LoadState(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		state = updater.State{}
	}
	state.CheckedAt = time.Now()
	if newer {
		state.Available = available
	} else {
		state.Available = ""
		state.LastNotified = ""
	}
	return updater.SaveState(path, state)
}

func printCachedUpdateNotice(command string, writer io.Writer) {
	switch command {
	case "update", "serve", "__touchid-helper", "help", "--help", "-h",
		"version", "--version", "-version":
		return
	}
	path, err := updateStatePath()
	if err != nil {
		return
	}
	state, err := updater.LoadState(path)
	if err != nil || state.Available == "" {
		return
	}
	newer, err := updater.IsNewer(state.Available, version)
	if err != nil || !newer {
		return
	}
	fmt.Fprintf(
		writer,
		"passfs %s is available; update with \"passfs update\"\n",
		state.Available,
	)
}

func startUpdateMonitor(ctx context.Context, logger *log.Logger) {
	go func() {
		checkUpdateIfDue(ctx, logger)
		ticker := time.NewTicker(updateCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkUpdateIfDue(ctx, logger)
			}
		}
	}()
}

func checkUpdateIfDue(ctx context.Context, logger *log.Logger) {
	statePath, err := updateStatePath()
	if err != nil {
		logger.Printf("update check: %v", err)
		return
	}
	state, err := updater.LoadState(statePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Printf("update state: %v", err)
		state = updater.State{}
	}
	if !state.CheckedAt.IsZero() &&
		time.Since(state.CheckedAt) >= 0 &&
		time.Since(state.CheckedAt) < updateCheckInterval {
		return
	}

	release, checkErr := newUpdateClient().Latest(ctx)
	state.CheckedAt = time.Now()
	if checkErr != nil {
		logger.Printf("update check: %v", checkErr)
		if err := updater.SaveState(statePath, state); err != nil {
			logger.Printf("save update state: %v", err)
		}
		return
	}
	newer, err := updater.IsNewer(release.Version, version)
	if err != nil {
		logger.Printf("compare update version: %v", err)
		return
	}
	if !newer {
		state.Available = ""
		state.LastNotified = ""
	} else {
		state.Available = release.Version
		if state.LastNotified != release.Version {
			shown, notifyErr := notifyPlatformUpdate(release.Version)
			if notifyErr != nil {
				logger.Printf("update notification: %v", notifyErr)
			}
			if shown {
				state.LastNotified = release.Version
			}
		}
	}
	if err := updater.SaveState(statePath, state); err != nil {
		logger.Printf("save update state: %v", err)
	}
}
