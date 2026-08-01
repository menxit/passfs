package passfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ResolvePath resolves the longest existing path prefix. Unlike
// filepath.EvalSymlinks, it also supports a missing final path.
func ResolvePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(absolute), nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

// ResolvePathEntry resolves symbolic links in the parent directory without
// following the final path component. External protected paths need this form:
// macOS aliases such as /tmp must share one vault namespace, while an existing
// protected link must continue to identify its original pathname.
func ResolvePathEntry(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolvedParent, err := ResolvePath(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(absolute)), nil
}

func PathWithin(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	return root == path ||
		strings.HasPrefix(path, root+string(os.PathSeparator))
}
