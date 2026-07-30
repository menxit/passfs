package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

const serviceCommandTimeout = 8 * time.Second

type serviceStatus struct {
	Installed bool
	Running   bool
}

func runServiceCommand(
	executable string,
	arguments ...string,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, executable, arguments...).CombinedOutput()
	if ctx.Err() != nil {
		return output, fmt.Errorf(
			"%s did not finish within %s: %w",
			executable,
			serviceCommandTimeout,
			ctx.Err(),
		)
	}
	return output, err
}
