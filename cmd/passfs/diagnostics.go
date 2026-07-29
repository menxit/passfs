package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"passfs/internal/passfs"
)

func runDoctor(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var testPrompt bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(
		&testPrompt,
		"test-prompt",
		false,
		"open the automatic authorization prompt and discard its input",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs doctor [options]")
	}

	fmt.Fprintln(stdout, "passfs doctor")
	fmt.Fprintln(stdout)
	printCapability(stdout, platformFUSECapability())
	printCapability(stdout, platformPromptCapability())

	settings, settingsErr := passfs.LoadSettings(common.configPath)
	switch {
	case settingsErr == nil:
		fmt.Fprintf(stdout, "%-14s %s\n", "Configuration:", "ready — "+settings.Path())
	case errors.Is(settingsErr, os.ErrNotExist):
		fmt.Fprintf(
			stdout,
			"%-14s %s\n",
			"Configuration:",
			"not initialized — run \"passfs init\"",
		)
	default:
		fmt.Fprintf(
			stdout,
			"%-14s %s\n",
			"Configuration:",
			"unavailable — "+settingsErr.Error(),
		)
	}

	if settings != nil {
		printServiceDiagnosis(stdout)
		printMountDiagnosis(stdout, settings)
	}

	if !testPrompt {
		return nil
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Opening an authorization prompt. Its input will be discarded.")
	prompter, err := newDiagnosticPrompter(settings)
	if err != nil {
		return err
	}
	_, err = prompter.Prompt(context.Background(), passfs.PromptRequest{
		Path:        "/doctor/test",
		Operation:   "test",
		PID:         uint32(os.Getpid()),
		Description: "Test the passfs authorization prompt",
	})
	if err != nil {
		return fmt.Errorf("test authorization prompt: %w", err)
	}
	fmt.Fprintln(stdout, "Prompt test: successful")
	return nil
}

func printServiceDiagnosis(writer io.Writer) {
	service, err := queryService()
	if err != nil {
		fmt.Fprintf(writer, "%-14s %s\n", "Service:", "unavailable — "+err.Error())
		return
	}
	description := "not installed"
	if service.Installed {
		description = "stopped"
	}
	if service.Running {
		description = "running"
	}
	fmt.Fprintf(writer, "%-14s %s\n", "Service:", description)
}

func printMountDiagnosis(writer io.Writer, settings *passfs.Settings) {
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		fmt.Fprintf(writer, "%-14s %s\n", "Filesystem:", "unavailable — "+err.Error())
		return
	}
	description := "not mounted"
	switch {
	case mount.mounted && mount.passfs && mount.healthy:
		description = "mounted — " + settings.MountPoint
	case mount.mounted && mount.passfs:
		description = "mounted but unavailable — run \"passfs reload\""
	case mount.mounted:
		description = "mount point occupied by another filesystem"
	}
	fmt.Fprintf(writer, "%-14s %s\n", "Filesystem:", description)
}

func runSetup(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var noOpen bool
	flags.BoolVar(&noOpen, "no-open", false, "print setup instructions without opening a browser")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs setup [options]")
	}

	capability := platformFUSECapability()
	printCapability(stdout, capability)
	if capability.ready {
		if err := guidePlatformPromptSetup(stdout); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Continue with:")
		settingsPath, err := passfs.DefaultSettingsPath()
		if err != nil {
			return err
		}
		if _, err := os.Stat(settingsPath); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stdout, "  passfs init")
		} else if err != nil {
			return err
		}
		fmt.Fprintln(stdout, "  passfs mount")
		return nil
	}
	return guidePlatformFUSESetup(stdout, !noOpen)
}

func printCapability(writer io.Writer, capability platformCapability) {
	state := "action required"
	if capability.ready {
		state = "ready"
	}
	description := state
	if capability.detail != "" {
		description += " — " + capability.detail
	}
	fmt.Fprintf(writer, "%-14s %s\n", capability.name+":", description)
}
