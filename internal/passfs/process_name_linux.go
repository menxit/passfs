//go:build linux

package passfs

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func platformProcessName(pid uint32) string {
	processDirectory := filepath.Join(
		"/proc",
		strconv.FormatUint(uint64(pid), 10),
	)
	if name, err := os.ReadFile(filepath.Join(processDirectory, "comm")); err == nil {
		return string(name)
	}
	if executable, err := os.Readlink(filepath.Join(processDirectory, "exe")); err == nil {
		return executable
	}
	return ""
}

// Linux reports the calling task ID in FUSE requests. Go can move a goroutine
// between OS threads, so task IDs are not stable across syscalls from one CLI
// process. Resolve the task to its thread-group ID before using it as the
// authorization-session owner.
func platformProcessID(pid uint32) uint32 {
	status, err := os.Open(filepath.Join(
		"/proc",
		strconv.FormatUint(uint64(pid), 10),
		"status",
	))
	if err != nil {
		return pid
	}
	defer status.Close()

	scanner := bufio.NewScanner(status)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[0] != "Tgid:" {
			continue
		}
		tgid, err := strconv.ParseUint(fields[1], 10, 32)
		if err == nil && tgid != 0 {
			return uint32(tgid)
		}
		break
	}
	return pid
}

func platformParentProcessID(pid uint32) uint32 {
	parent, err := linuxParentPID(pid)
	if err != nil {
		return 0
	}
	return parent
}
