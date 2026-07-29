package passfs

import (
	"os"
	"path/filepath"
)

// canonicalMountPoint resolves aliases in the parent directory without
// traversing the mount itself. Traversing the mount point would fail for an
// orphaned FUSE mount, which is precisely when MountStatus is needed most.
func canonicalMountPoint(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		resolvedParent = parent
	}
	return filepath.Join(resolvedParent, filepath.Base(absolute)), nil
}
