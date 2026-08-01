package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"passfs/internal/passfs"
)

type nonPromptingPrompter struct{}

func (nonPromptingPrompter) Prompt(
	context.Context,
	passfs.PromptRequest,
) (string, error) {
	return "", errors.New("recovery purge unexpectedly requested authorization")
}

func runRecovery(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: passfs recovery list|restore|purge [options]")
	}
	switch args[0] {
	case "list":
		return runRecoveryList(args[1:], stdout, stderr)
	case "restore":
		return runRecoveryRestore(args[1:], stdout, stderr)
	case "purge":
		return runRecoveryPurge(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown recovery command %q", args[0])
	}
}

func runRecoveryList(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recovery list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var jsonOutput bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(&jsonOutput, "json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs recovery list [options]")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	items, err := passfs.RecoveryItems(settings.Vault)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, items)
	}
	if len(items) == 0 {
		fmt.Fprintln(stdout, "No recoverable PassFS files")
		return nil
	}
	for _, item := range items {
		fmt.Fprintf(
			stdout,
			"%s\t%s\t%s\n",
			item.State,
			item.ObjectID,
			terminalPath(item.Path),
		)
	}
	return nil
}

func runRecoveryRestore(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recovery restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: passfs recovery restore [options] OBJECT_ID|PATH")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if err := passfs.WithLinkReconciliationLock(settings.Vault, func() error {
		return passfs.RestoreRecoveryLink(
			settings.Vault,
			settings.MountPoint,
			flags.Arg(0),
		)
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Restored protected link %s\n", terminalPath(flags.Arg(0)))
	return nil
}

func runRecoveryPurge(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recovery purge", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var confirmed bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(&confirmed, "yes", false, "confirm permanent ciphertext deletion")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || !confirmed {
		return errors.New("usage: passfs recovery purge --yes [options] OBJECT_ID|PATH")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	if mount.mounted {
		return errors.New("unmount PassFS before permanently purging recovery data")
	}
	volume, err := passfs.LoadVolume(
		settings.Vault,
		nonPromptingPrompter{},
		defaultMaxFileSize,
		0,
	)
	if err != nil {
		return err
	}
	if err := volume.PurgeRecovery(flags.Arg(0)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Permanently purged %s\n", terminalPath(flags.Arg(0)))
	return nil
}
