package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"passfs/internal/passfs"
)

func runBackup(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: passfs backup create|verify|restore [options]")
	}
	switch args[0] {
	case "create":
		return runBackupCreate(args[1:], stdout, stderr)
	case "verify":
		return runBackupVerify(args[1:], stdout, stderr)
	case "restore":
		return runBackupRestore(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown backup command %q", args[0])
	}
}

func addConfiguredPromptFlags(flags *flag.FlagSet, mode, pinentry *string) {
	flags.StringVar(mode, "prompt", "configured", `authorization backend: "configured", "tty", "native", "pinentry", or "auto"`)
	flags.StringVar(pinentry, "pinentry", "", "path to an optional pinentry executable")
}

func backupPrompter(
	settings *passfs.Settings,
	mode,
	pinentry string,
) (passfs.Prompter, error) {
	if strings.EqualFold(strings.TrimSpace(mode), "configured") {
		return newServicePrompter(settings)
	}
	return passfs.NewPrompter(mode, pinentry)
}

func runBackupCreate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("backup create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var promptMode, pinentry string
	var maxFileSize int64
	var restartService bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addConfiguredPromptFlags(flags, &promptMode, &pinentry)
	addMaxFileSizeFlag(flags, &maxFileSize)
	flags.BoolVar(
		&restartService,
		"restart-service",
		false,
		"temporarily stop an active PassFS filesystem and restart it afterward",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: passfs backup create [options] DESTINATION")
	}
	if err := validateMaxFileSize(maxFileSize); err != nil {
		return err
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	create := func() error {
		return createAndVerifyBackup(
			settings,
			flags.Arg(0),
			promptMode,
			pinentry,
			maxFileSize,
			stdout,
		)
	}
	if restartService {
		return withQuiescedFilesystem(settings, create)
	}
	return create()
}

func createAndVerifyBackup(
	settings *passfs.Settings,
	destination string,
	promptMode string,
	pinentry string,
	maxFileSize int64,
	stdout io.Writer,
) error {
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	if mount.mounted {
		return errors.New("unmount PassFS before creating a consistent backup")
	}
	manifest, err := passfs.CreateBackup(settings.Vault, destination)
	if err != nil {
		return err
	}
	prompter, err := backupPrompter(settings, promptMode, pinentry)
	if err != nil {
		return err
	}
	report, err := passfs.VerifyBackup(
		context.Background(), destination, prompter, maxFileSize,
	)
	if err != nil {
		return fmt.Errorf("backup was created but verification failed: %w", err)
	}
	fmt.Fprintf(
		stdout,
		"Created and verified backup %s (%d encrypted files, %d plaintext bytes, volume %s)\n",
		terminalPath(destination), report.Files, report.Bytes, manifest.VolumeID,
	)
	return nil
}

func runBackupVerify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("backup verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var promptMode, pinentry string
	var maxFileSize int64
	var jsonOutput bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addConfiguredPromptFlags(flags, &promptMode, &pinentry)
	addMaxFileSizeFlag(flags, &maxFileSize)
	flags.BoolVar(&jsonOutput, "json", false, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: passfs backup verify [options] BACKUP")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	prompter, err := backupPrompter(settings, promptMode, pinentry)
	if err != nil {
		return err
	}
	report, err := passfs.VerifyBackup(
		context.Background(), flags.Arg(0), prompter, maxFileSize,
	)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, report)
	}
	fmt.Fprintf(stdout, "Backup verified: %d encrypted files, %d plaintext bytes, volume %s\n", report.Files, report.Bytes, report.VolumeID)
	return nil
}

func runBackupRestore(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var promptMode, pinentry, destination string
	var maxFileSize int64
	var activate bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addConfiguredPromptFlags(flags, &promptMode, &pinentry)
	addMaxFileSizeFlag(flags, &maxFileSize)
	flags.StringVar(&destination, "vault", "", "new directory for the restored vault")
	flags.BoolVar(
		&activate,
		"activate",
		false,
		"make the restored vault active while preserving the current service state",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: passfs backup restore --vault NEW_VAULT [options] BACKUP")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if destination == "" {
		destination = settings.Vault
	}
	prompter, err := backupPrompter(settings, promptMode, pinentry)
	if err != nil {
		return err
	}
	if _, err := passfs.VerifyBackup(
		context.Background(), flags.Arg(0), prompter, maxFileSize,
	); err != nil {
		return fmt.Errorf("refuse to restore an unverified backup: %w", err)
	}
	manifest, err := passfs.RestoreBackup(flags.Arg(0), destination)
	if err != nil {
		return err
	}
	if activate {
		if err := activateRestoredVault(settings, destination); err != nil {
			return fmt.Errorf(
				"restored volume %s to %s, but could not activate it: %w",
				manifest.VolumeID,
				terminalPath(destination),
				err,
			)
		}
	}
	fmt.Fprintf(stdout, "Restored volume %s to %s", manifest.VolumeID, terminalPath(destination))
	if activate {
		fmt.Fprint(stdout, " and made it the active vault")
	}
	fmt.Fprintln(stdout)
	return nil
}

func withQuiescedFilesystem(
	settings *passfs.Settings,
	operation func() error,
) error {
	active, err := filesystemIsActive(settings)
	if err != nil {
		return err
	}
	if active {
		if err := runUnmount(
			[]string{"--config", settings.Path()},
			io.Discard,
			io.Discard,
		); err != nil {
			return fmt.Errorf("stop PassFS for backup: %w", err)
		}
	}
	operationErr := operation()
	var restartErr error
	if active {
		restartErr = restartFilesystem(settings)
	}
	return errors.Join(operationErr, restartErr)
}

func filesystemIsActive(settings *passfs.Settings) (bool, error) {
	status, err := queryService()
	if err != nil {
		return false, err
	}
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return false, err
	}
	if mount.mounted && !mount.passfs {
		return false, fmt.Errorf(
			"%s is mounted by another filesystem",
			terminalPath(settings.MountPoint),
		)
	}
	return status.Running || mount.mounted, nil
}

func restartFilesystem(settings *passfs.Settings) error {
	if err := runReload(
		[]string{"--config", settings.Path(), "--no-open"},
		io.Discard,
		io.Discard,
	); err != nil {
		return fmt.Errorf("restart PassFS: %w", err)
	}
	return nil
}

func activateRestoredVault(
	settings *passfs.Settings,
	destination string,
) error {
	active, err := filesystemIsActive(settings)
	if err != nil {
		return err
	}
	if active {
		if err := runUnmount(
			[]string{"--config", settings.Path()},
			io.Discard,
			io.Discard,
		); err != nil {
			return fmt.Errorf("stop PassFS before activating restored vault: %w", err)
		}
	}
	return activateVaultSelection(
		settings,
		destination,
		active,
		restartFilesystem,
	)
}

func activateVaultSelection(
	settings *passfs.Settings,
	destination string,
	restart bool,
	restartService func(*passfs.Settings) error,
) error {
	originalVault := settings.Vault
	if err := settings.SetVault(destination); err != nil {
		if restart {
			return errors.Join(err, restartService(settings))
		}
		return err
	}
	if err := settings.Save(); err != nil {
		_ = settings.SetVault(originalVault)
		if restart {
			return errors.Join(err, restartService(settings))
		}
		return err
	}
	if !restart {
		return nil
	}
	if err := restartService(settings); err == nil {
		return nil
	} else {
		activationErr := err
		if rollbackErr := settings.SetVault(originalVault); rollbackErr != nil {
			return errors.Join(activationErr, rollbackErr)
		}
		if rollbackErr := settings.Save(); rollbackErr != nil {
			return errors.Join(activationErr, rollbackErr)
		}
		return errors.Join(activationErr, restartService(settings))
	}
}

func runVault(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: passfs vault verify [options]")
	}
	flags := flag.NewFlagSet("vault verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var promptMode, pinentry string
	var maxFileSize int64
	var jsonOutput bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addConfiguredPromptFlags(flags, &promptMode, &pinentry)
	addMaxFileSizeFlag(flags, &maxFileSize)
	flags.BoolVar(&jsonOutput, "json", false, "write machine-readable JSON")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs vault verify [options]")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	prompter, err := backupPrompter(settings, promptMode, pinentry)
	if err != nil {
		return err
	}
	report, err := passfs.VerifyVault(
		context.Background(), settings.Vault, prompter, maxFileSize,
	)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(stdout, report)
	}
	fmt.Fprintf(stdout, "Vault verified: %d encrypted files, %d plaintext bytes, volume %s\n", report.Files, report.Bytes, report.VolumeID)
	return nil
}
