package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"passfs/internal/passfs"
)

func runProtected(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("protected", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var jsonOutput bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(&jsonOutput, "json", false, "write metadata as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs protected [options]")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	files, err := passfs.ProtectedFiles(settings.Vault)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, files)
	}
	for _, file := range files {
		fmt.Fprintln(stdout, terminalPath(file.Path))
	}
	return nil
}
