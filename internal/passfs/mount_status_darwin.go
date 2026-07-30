//go:build darwin

package passfs

import (
	"bytes"
	"strings"

	"golang.org/x/sys/unix"
)

func MountStatus(mountPoint string) (mounted bool, passfsMount bool, err error) {
	mounted, adapter, err := MountAdapterStatus(mountPoint)
	return mounted, adapter != MountAdapterUnknown, err
}

func MountAdapterStatus(
	mountPoint string,
) (mounted bool, adapter string, err error) {
	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return false, MountAdapterUnknown, err
	}
	mounts := make([]unix.Statfs_t, count)
	count, err = unix.Getfsstat(mounts, unix.MNT_NOWAIT)
	if err != nil {
		return false, MountAdapterUnknown, err
	}
	target, err := canonicalMountPoint(mountPoint)
	if err != nil {
		return false, MountAdapterUnknown, err
	}
	for index := 0; index < count; index++ {
		mount := mounts[index]
		current, canonicalErr := canonicalMountPoint(cString(mount.Mntonname[:]))
		if canonicalErr != nil || current != target {
			continue
		}
		fsType := strings.ToLower(cString(mount.Fstypename[:]))
		source := cString(mount.Mntfromname[:])
		isFUSE := strings.Contains(fsType, "fuse")
		switch {
		case isFUSE && source == "passfs":
			return true, MountAdapterFUSE, nil
		case fsType == "passfs":
			return true, MountAdapterFSKit, nil
		default:
			return true, MountAdapterUnknown, nil
		}
	}
	return false, MountAdapterUnknown, nil
}

func UnmountPath(mountPoint string) error {
	if err := unix.Unmount(mountPoint, 0); err == nil {
		return nil
	}
	return unix.Unmount(mountPoint, unix.MNT_FORCE)
}

func cString(value []byte) string {
	if end := bytes.IndexByte(value, 0); end >= 0 {
		value = value[:end]
	}
	return string(value)
}
