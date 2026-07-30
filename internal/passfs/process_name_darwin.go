//go:build darwin

package passfs

import (
	"os/exec"
	"strconv"
	"strings"
)

func platformProcessName(pid uint32) string {
	output, err := exec.Command(
		"/bin/ps",
		"-p",
		strconv.FormatUint(uint64(pid), 10),
		"-o",
		"comm=",
	).Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func platformProcessID(pid uint32) uint32 {
	return pid
}

func platformParentProcessID(pid uint32) uint32 {
	output, err := exec.Command(
		"/bin/ps",
		"-p",
		strconv.FormatUint(uint64(pid), 10),
		"-o",
		"ppid=",
	).Output()
	if err != nil {
		return 0
	}
	parent, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(parent)
}
