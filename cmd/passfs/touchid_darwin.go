//go:build darwin

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"passfs/internal/passfs"
)

func runTouchID(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: passfs touchid enable|disable|status|verify [options]")
	}
	switch args[0] {
	case "enable":
		return runTouchIDEnable(args[1:], stdout, stderr)
	case "disable":
		return runTouchIDDisable(args[1:], stdout, stderr)
	case "status":
		return runTouchIDStatus(args[1:], stdout, stderr)
	case "verify":
		return runTouchIDVerify(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printTouchIDUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown touchid command %q", args[0])
	}
}

func printTouchIDUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  passfs touchid enable [options]
  passfs touchid disable [options]
  passfs touchid status [options]
  passfs touchid verify [options]`)
}

func runTouchIDEnable(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("touchid enable", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var promptOptions promptFlags
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addPromptFlags(flags, &promptOptions)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs touchid enable [options]")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	prompter, err := promptOptions.build()
	if err != nil {
		return err
	}
	if err := passfs.EnableTouchID(
		context.Background(),
		settings.Vault,
		prompter,
	); err != nil {
		return err
	}
	settings.TouchID = true
	if err := settings.Save(); err != nil {
		rollbackErr := passfs.DisableTouchID(settings.Vault)
		return errors.Join(err, rollbackErr)
	}
	fmt.Fprintln(stdout, "Touch ID enabled")
	printReloadNotice(stdout)
	return nil
}

func runTouchIDDisable(args []string, stdout, stderr io.Writer) error {
	common, err := parseCommonOnlyFlags("touchid disable", args, stderr)
	if err != nil {
		return err
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	settings.TouchID = false
	if err := settings.Save(); err != nil {
		return err
	}
	if err := passfs.DisableTouchID(settings.Vault); err != nil {
		return fmt.Errorf(
			"Touch ID is disabled in passfs but its protected identity could not be removed: %w",
			err,
		)
	}
	fmt.Fprintln(stdout, "Touch ID disabled")
	printReloadNotice(stdout)
	return nil
}

func runTouchIDStatus(args []string, stdout, stderr io.Writer) error {
	common, err := parseCommonOnlyFlags("touchid status", args, stderr)
	if err != nil {
		return err
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if !settings.TouchID {
		fmt.Fprintln(stdout, "Touch ID: disabled")
		return nil
	}
	configured, err := passfs.TouchIDConfigured(settings.Vault)
	if err != nil {
		return err
	}
	protectedIdentity := "missing"
	if configured {
		protectedIdentity = "present"
	}
	fmt.Fprintf(
		stdout,
		"Touch ID:           enabled\nProtected identity: %s\n",
		protectedIdentity,
	)
	if !configured {
		return errors.New(
			"Touch ID is enabled but its protected identity is missing; run \"passfs touchid enable\"",
		)
	}
	return nil
}

func runTouchIDVerify(args []string, stdout, stderr io.Writer) error {
	common, err := parseCommonOnlyFlags("touchid verify", args, stderr)
	if err != nil {
		return err
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if !settings.TouchID {
		return errors.New("Touch ID is disabled")
	}
	if err := passfs.VerifyTouchID(context.Background(), settings.Vault); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Touch ID verified")
	return nil
}
