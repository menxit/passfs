package passfs

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	linkReferenceFileReserve = 256
	maxTrackedProtectedLinks = 65536
)

func ensureLinkReferenceCapacity(protectedLinks int) error {
	if protectedLinks < 0 || protectedLinks > maxTrackedProtectedLinks {
		return fmt.Errorf(
			"passfs can track at most %d protected links",
			maxTrackedProtectedLinks,
		)
	}
	required := uint64(protectedLinks + linkReferenceFileReserve)
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("read open-file limit: %w", err)
	}
	if limit.Cur >= required {
		return nil
	}
	if limit.Max != unix.RLIM_INFINITY && limit.Max < required {
		return fmt.Errorf(
			"open-file hard limit %d is too low to track %d protected links",
			limit.Max,
			protectedLinks,
		)
	}
	limit.Cur = required
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf(
			"raise open-file limit to track %d protected links: %w",
			protectedLinks,
			err,
		)
	}
	return nil
}
