package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"passfs/internal/passfs"
)

const scanIgnoreFileName = "scan-ignore.json"

func runIgnore(
	args []string,
	remove bool,
	stdout io.Writer,
	stderr io.Writer,
) error {
	command := "ignore"
	if remove {
		command = "unignore"
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return fmt.Errorf("passfs %s requires at least one FILE", command)
	}

	paths := make([]string, 0, flags.NArg())
	for _, argument := range flags.Args() {
		absolute, err := filepath.Abs(argument)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.Clean(absolute))
	}
	if err := updateScanIgnoredPaths(common.configPath, paths, remove); err != nil {
		return err
	}
	for _, path := range paths {
		action := "Ignored"
		if remove {
			action = "Restored"
		}
		fmt.Fprintf(stdout, "%s %s\n", action, terminalPath(path))
	}
	return nil
}

func runIgnored(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ignored", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var jsonOutput bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(&jsonOutput, "json", false, "write a JSON array")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs ignored [--json]")
	}
	ignored, err := loadScanIgnoredPaths(common.configPath)
	if err != nil {
		return err
	}
	paths := sortedPathSet(ignored)
	if jsonOutput {
		return writeJSON(stdout, paths)
	}
	for _, path := range paths {
		fmt.Fprintln(stdout, terminalPath(path))
	}
	return nil
}

func scanIgnorePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), scanIgnoreFileName)
}

func loadScanIgnoredPaths(configPath string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	file, err := os.Open(scanIgnorePath(configPath))
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open scan ignore list: %w", err)
	}
	defer file.Close()
	var paths []string
	if err := json.NewDecoder(file).Decode(&paths); err != nil {
		return nil, fmt.Errorf("parse scan ignore list: %w", err)
	}
	for _, path := range paths {
		if filepath.IsAbs(path) {
			result[filepath.Clean(path)] = struct{}{}
		}
	}
	return result, nil
}

func updateScanIgnoredPaths(
	configPath string,
	paths []string,
	remove bool,
) error {
	ignored, err := loadScanIgnoredPaths(configPath)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if remove {
			delete(ignored, filepath.Clean(path))
		} else {
			ignored[filepath.Clean(path)] = struct{}{}
		}
	}
	sorted := sortedPathSet(ignored)
	data, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := passfs.WriteFileAtomic(
		scanIgnorePath(configPath),
		data,
		0o600,
	); err != nil {
		return fmt.Errorf("save scan ignore list: %w", err)
	}
	return nil
}
