//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"passfs/internal/passfs"
)

func runTouchIDHelper(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("__touchid-helper", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var vault string
	var reason string
	flags.StringVar(&vault, "vault", "", "")
	flags.StringVar(&reason, "reason", "", "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || vault == "" || reason == "" {
		return errors.New("invalid Touch ID helper request")
	}
	if err := passfs.ValidateTouchIDHelperParent(os.Getppid()); err != nil {
		return fmt.Errorf("reject untrusted Touch ID helper parent: %w", err)
	}
	if err := passfs.PrepareTouchIDUI(); err != nil {
		return fmt.Errorf("prepare Touch ID user interface: %w", err)
	}
	identity, err := passfs.TouchIDIdentity(vault, reason)
	if err != nil {
		return err
	}
	secret := []byte(identity.String())
	defer clear(secret)
	if _, err := stdout.Write(secret); err != nil {
		return fmt.Errorf("return Touch ID identity: %w", err)
	}
	return nil
}
