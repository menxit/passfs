package passfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type ImportResult struct {
	TargetPath  string
	Imported    bool
	LinkCreated bool
}

// ImportThroughMount moves a plaintext file into the mounted passfs namespace
// and replaces its original pathname with a symbolic link to the protected
// view. All writes to targetPath therefore go through the running FUSE process;
// the CLI never writes ciphertext or metadata concurrently with it.
//
// If the target is already protected and the original pathname is absent, the
// function only restores the symbolic link. This supports volumes created by
// passfs versions that removed the original plaintext pathname.
func ImportThroughMount(sourcePath, mountPoint string, maxFileSize int64) (result ImportResult, err error) {
	if maxFileSize <= 0 {
		return result, errors.New("maximum file size must be greater than zero")
	}
	mountPoint, err = filepath.Abs(mountPoint)
	if err != nil {
		return result, err
	}
	mounted, isPassFS, err := MountStatus(mountPoint)
	if err != nil {
		return result, fmt.Errorf("inspect passfs mount: %w", err)
	}
	if !mounted || !isPassFS {
		return result, errors.New("target is not a mounted passfs filesystem")
	}
	sourcePath, err = filepath.Abs(sourcePath)
	if err != nil {
		return result, err
	}
	targetPath, err := MountedPath(mountPoint, sourcePath)
	if err != nil {
		return result, err
	}
	result.TargetPath = targetPath
	if PathWithin(mountPoint, sourcePath) {
		return result, errors.New("cannot import a file from inside the passfs mount")
	}
	result, err = importFile(sourcePath, targetPath, maxFileSize)
	if err != nil {
		return result, err
	}
	if err := MarkProtectedLink(targetPath); err != nil {
		return result, fmt.Errorf(
			"protected link is installed but could not be registered with the passfs service: %w\nrestart passfs with:\n  passfs reload\nthen retry the command",
			err,
		)
	}
	return result, nil
}

func importFile(sourcePath, targetPath string, maxFileSize int64) (result ImportResult, err error) {
	result.TargetPath = targetPath
	if targetInfo, targetErr := os.Lstat(targetPath); targetErr == nil {
		if !targetInfo.Mode().IsRegular() {
			return result, fmt.Errorf("protected target %s is not a regular file", targetPath)
		}
		created, linkErr := EnsureProtectedLink(sourcePath, targetPath)
		if linkErr != nil {
			return result, linkErr
		}
		result.LinkCreated = created
		return result, nil
	} else if !errors.Is(targetErr, os.ErrNotExist) {
		return result, fmt.Errorf("check encrypted target: %w", targetErr)
	}

	data, info, err := readSourceFile(sourcePath, maxFileSize)
	if err != nil {
		return result, err
	}
	defer wipe(data)

	targetCreated := false
	linkInstalled := false
	defer func() {
		if err == nil || !targetCreated || linkInstalled {
			return
		}
		if removeErr := os.Remove(targetPath); removeErr != nil &&
			!errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(
				err,
				fmt.Errorf("remove encrypted target during rollback: %w", removeErr),
			)
		}
	}()

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return result, fmt.Errorf("create encrypted path: %w", err)
	}
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return result, fmt.Errorf("create encrypted target: %w", err)
	}
	targetCreated = true
	if _, err := target.Write(data); err != nil {
		_ = target.Close()
		return result, fmt.Errorf("write encrypted target: %w", err)
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		return result, fmt.Errorf("sync encrypted target: %w", err)
	}
	if err := target.Close(); err != nil {
		return result, fmt.Errorf("close encrypted target: %w", err)
	}
	if err := os.Chmod(targetPath, info.Mode().Perm()); err != nil {
		return result, fmt.Errorf("preserve file mode: %w", err)
	}
	if err := os.Chtimes(targetPath, info.ModTime(), info.ModTime()); err != nil {
		return result, fmt.Errorf("preserve modification time: %w", err)
	}
	linkInstalled, err = replaceRegularFileWithLink(sourcePath, targetPath, info)
	if linkInstalled {
		result.Imported = true
		result.LinkCreated = true
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

func readSourceFile(sourcePath string, maxFileSize int64) ([]byte, os.FileInfo, error) {
	initial, err := os.Lstat(sourcePath)
	if err != nil {
		return nil, nil, err
	}
	if !initial.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", sourcePath)
	}

	file, err := os.OpenFile(
		sourcePath,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", sourcePath)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink > 1 {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s has multiple hard links", sourcePath)
	}
	if info.Size() > maxFileSize {
		_ = file.Close()
		return nil, nil, ErrFileTooLarge
	}

	data, readErr := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	closeErr := file.Close()
	if readErr != nil {
		wipe(data)
		return nil, nil, readErr
	}
	if closeErr != nil {
		wipe(data)
		return nil, nil, closeErr
	}
	if int64(len(data)) > maxFileSize {
		wipe(data)
		return nil, nil, ErrFileTooLarge
	}
	return data, info, nil
}

func replaceRegularFileWithLink(
	sourcePath string,
	targetPath string,
	expected os.FileInfo,
) (installed bool, err error) {
	current, err := os.Lstat(sourcePath)
	if err != nil {
		return false, fmt.Errorf("recheck source before replacement: %w", err)
	}
	if !sameFileVersion(expected, current) {
		return false, fmt.Errorf("%s changed while it was being encrypted", sourcePath)
	}

	current, err = os.Lstat(sourcePath)
	if err != nil {
		return false, fmt.Errorf("recheck source before installing link: %w", err)
	}
	if !sameFileVersion(expected, current) {
		return false, fmt.Errorf("%s changed while it was being encrypted", sourcePath)
	}
	return exchangePathWithSymlink(
		sourcePath,
		targetPath,
		func(displacedPath string) error {
			displaced, err := os.Lstat(displacedPath)
			if err != nil {
				return fmt.Errorf("inspect displaced source file: %w", err)
			}
			if !sameFileVersion(expected, displaced) {
				return fmt.Errorf("%s changed while it was being encrypted", sourcePath)
			}
			return nil
		},
	)
}

func sameFileVersion(expected, current os.FileInfo) bool {
	return current.Mode().IsRegular() &&
		os.SameFile(expected, current) &&
		current.Size() == expected.Size() &&
		current.Mode() == expected.Mode() &&
		current.ModTime().Equal(expected.ModTime())
}

// EnsureProtectedLink creates sourcePath as an absolute symbolic link to
// targetPath. An existing link to the same target is accepted; every other
// existing filesystem entry is left untouched.
func EnsureProtectedLink(sourcePath, targetPath string) (bool, error) {
	sourcePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return false, err
	}
	targetPath, err = filepath.Abs(targetPath)
	if err != nil {
		return false, err
	}

	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		return false, fmt.Errorf("inspect protected path %s: %w", sourcePath, err)
	}
	if !link.exists {
		if err := os.Symlink(targetPath, sourcePath); err != nil {
			return false, fmt.Errorf("create protected link %s: %w", sourcePath, err)
		}
		if err := syncDirectory(filepath.Dir(sourcePath)); err != nil {
			_ = os.Remove(sourcePath)
			return false, fmt.Errorf("sync protected link: %w", err)
		}
		return true, nil
	}
	if !link.isSymlink {
		return false, fmt.Errorf(
			"%s already exists and is not the passfs protected link",
			sourcePath,
		)
	}
	if link.target != filepath.Clean(targetPath) {
		return false, fmt.Errorf(
			"%s points to %s instead of the passfs target %s",
			sourcePath,
			link.target,
			targetPath,
		)
	}
	return false, nil
}
