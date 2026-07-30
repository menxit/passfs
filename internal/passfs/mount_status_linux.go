//go:build linux

package passfs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func MountStatus(mountPoint string) (mounted bool, passfsMount bool, err error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, false, err
	}
	defer file.Close()

	target, err := canonicalMountPoint(mountPoint)
	if err != nil {
		return false, false, err
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 0 || separator+2 >= len(fields) || len(fields) < 5 {
			continue
		}
		matches, decodeErr := mountInfoPathMatches(fields[4], target)
		if decodeErr != nil {
			return false, false, decodeErr
		}
		if !matches {
			continue
		}
		fsType := fields[separator+1]
		source := fields[separator+2]
		return true, fsType == "fuse.passfs" && source == "passfs", nil
	}
	if err := scanner.Err(); err != nil {
		return false, false, err
	}
	return false, false, nil
}

// Mount points in /proc/self/mountinfo are kernel-resolved paths. Comparing
// them lexically avoids traversing unrelated mounts, some of which are
// intentionally inaccessible to unprivileged users (for example Docker
// network namespaces under /run/docker/netns).
func mountInfoPathMatches(encodedPath, target string) (bool, error) {
	current, err := decodeMountInfoPath(encodedPath)
	if err != nil {
		return false, err
	}
	return filepath.Clean(current) == target, nil
}

func UnmountPath(mountPoint string) error {
	var unmountErrors []error
	var helper string
	for _, name := range []string{"fusermount3", "fusermount"} {
		if path, err := exec.LookPath(name); err == nil {
			helper = path
			break
		}
	}
	if helper != "" {
		for _, arguments := range [][]string{
			{"-u", mountPoint},
			{"-u", "-z", mountPoint},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			output, err := exec.CommandContext(ctx, helper, arguments...).CombinedOutput()
			contextErr := ctx.Err()
			cancel()
			if err == nil {
				return nil
			}
			if contextErr != nil {
				err = errors.Join(err, contextErr)
			}
			unmountErrors = append(
				unmountErrors,
				fmt.Errorf(
					"%s %v: %w: %s",
					filepath.Base(helper),
					arguments,
					err,
					bytes.TrimSpace(output),
				),
			)
		}
	}
	if err := unix.Unmount(mountPoint, unix.MNT_DETACH); err != nil {
		unmountErrors = append(unmountErrors, err)
		return errors.Join(unmountErrors...)
	}
	return nil
}

func decodeMountInfoPath(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			index++
			continue
		}
		if index+3 >= len(value) {
			return "", errors.New("invalid escape in /proc/self/mountinfo")
		}
		decoded, err := strconv.ParseUint(value[index+1:index+4], 8, 8)
		if err != nil {
			return "", err
		}
		result.WriteByte(byte(decoded))
		index += 4
	}
	return result.String(), nil
}
