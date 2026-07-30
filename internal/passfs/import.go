package passfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	sourcePath, targetPath, err := resolveImportPaths(sourcePath, mountPoint)
	if err != nil {
		return result, err
	}
	result.TargetPath = targetPath
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

// ValidateImportThroughMount checks whether an import can proceed without
// changing either the source file or the mounted volume. ImportThroughMount
// still repeats every check to protect against changes after validation.
func ValidateImportThroughMount(sourcePath, mountPoint string, maxFileSize int64) error {
	if maxFileSize <= 0 {
		return errors.New("maximum file size must be greater than zero")
	}
	sourcePath, targetPath, err := resolveImportPaths(sourcePath, mountPoint)
	if err != nil {
		return err
	}
	targetInfo, targetErr := os.Lstat(targetPath)
	switch {
	case targetErr == nil:
		if !targetInfo.Mode().IsRegular() {
			return fmt.Errorf("protected target %s is not a regular file", targetPath)
		}
		link, err := inspectProtectedLink(sourcePath)
		if err != nil {
			return fmt.Errorf("inspect protected path %s: %w", sourcePath, err)
		}
		if !link.exists {
			return nil
		}
		if !link.isSymlink {
			return fmt.Errorf(
				"%s already exists and is not the passfs protected link",
				sourcePath,
			)
		}
		if link.target != filepath.Clean(targetPath) {
			return fmt.Errorf(
				"%s points to %s instead of the passfs target %s",
				sourcePath,
				link.target,
				targetPath,
			)
		}
		return nil
	case !errors.Is(targetErr, os.ErrNotExist):
		return fmt.Errorf("check encrypted target: %w", targetErr)
	}

	file, _, err := openValidatedSource(sourcePath, maxFileSize)
	if err != nil {
		return err
	}
	return file.Close()
}

func resolveImportPaths(sourcePath, mountPoint string) (string, string, error) {
	absoluteMountPoint, err := filepath.Abs(mountPoint)
	if err != nil {
		return "", "", err
	}
	mountPoint = absoluteMountPoint
	mounted, isPassFS, err := MountStatus(mountPoint)
	if err != nil {
		return "", "", fmt.Errorf("inspect passfs mount: %w", err)
	}
	if !mounted || !isPassFS {
		return "", "", errors.New("target is not a mounted passfs filesystem")
	}
	sourcePath, err = filepath.Abs(sourcePath)
	if err != nil {
		return "", "", err
	}
	targetPath, err := MountedPath(mountPoint, sourcePath)
	if err != nil {
		return "", "", err
	}
	if PathWithin(mountPoint, sourcePath) {
		return "", "", errors.New("cannot import a file from inside the passfs mount")
	}
	if err := validateImportTarget(mountPoint, targetPath); err != nil {
		return "", "", err
	}
	return sourcePath, targetPath, nil
}

func validateImportTarget(mountPoint, targetPath string) error {
	relative, err := filepath.Rel(mountPoint, targetPath)
	if err != nil {
		return err
	}
	components := strings.Split(filepath.Clean(relative), string(os.PathSeparator))
	for _, component := range components[:len(components)-1] {
		if strings.HasSuffix(component, encryptedSuffix) {
			return fmt.Errorf(
				"cannot protect files below directory %q because passfs reserves the %s suffix for encrypted files",
				component,
				encryptedSuffix,
			)
		}
	}
	name := components[len(components)-1]
	if len([]byte(name))+len(encryptedSuffix) > 255 {
		return fmt.Errorf(
			"file name is too long after adding passfs encrypted suffix %s",
			encryptedSuffix,
		)
	}
	return nil
}

// ReconcileProtectedEdit restores the protected link after an editor replaces
// it with a regular file during an atomic save. The replacement plaintext is
// written through the mounted target before the link is atomically restored.
// A matching protected link needs no reconciliation.
func ReconcileProtectedEdit(sourcePath, targetPath string, maxFileSize int64) (bool, error) {
	if maxFileSize <= 0 {
		return false, errors.New("maximum file size must be greater than zero")
	}
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
		return false, fmt.Errorf("inspect edited path: %w", err)
	}
	if !link.exists {
		return false, fmt.Errorf("%s was removed by the editor", sourcePath)
	}
	if link.isSymlink {
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

	data, info, err := readSourceFile(sourcePath, maxFileSize)
	if err != nil {
		return false, fmt.Errorf("read editor replacement: %w", err)
	}
	defer wipe(data)

	if err := writeProtectedReplacement(targetPath, data, info); err != nil {
		return false, err
	}
	installed, err := replaceRegularFileWithLink(
		sourcePath,
		targetPath,
		info,
		data,
	)
	if err != nil {
		return installed, fmt.Errorf(
			"restore protected link after editor replacement: %w",
			err,
		)
	}
	if err := MarkProtectedLink(targetPath); err != nil {
		return true, fmt.Errorf("register restored protected link: %w", err)
	}
	return true, nil
}

func writeProtectedReplacement(targetPath string, data []byte, info os.FileInfo) error {
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("open protected target after editor replacement: %w", err)
	}
	if _, err := target.Write(data); err != nil {
		_ = target.Close()
		return fmt.Errorf("write protected target after editor replacement: %w", err)
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		return fmt.Errorf("sync protected target after editor replacement: %w", err)
	}
	if err := target.Close(); err != nil {
		return fmt.Errorf("close protected target after editor replacement: %w", err)
	}
	if err := os.Chmod(targetPath, info.Mode().Perm()); err != nil {
		return fmt.Errorf("preserve edited file mode: %w", err)
	}
	if err := os.Chtimes(targetPath, info.ModTime(), info.ModTime()); err != nil {
		return fmt.Errorf("preserve edited file modification time: %w", err)
	}
	return nil
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
	linkInstalled, err = replaceRegularFileWithLink(
		sourcePath,
		targetPath,
		info,
		data,
	)
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
	file, info, err := openValidatedSource(sourcePath, maxFileSize)
	if err != nil {
		return nil, nil, err
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

func openValidatedSource(sourcePath string, maxFileSize int64) (*os.File, os.FileInfo, error) {
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
	return file, info, nil
}

func replaceRegularFileWithLink(
	sourcePath string,
	targetPath string,
	expected os.FileInfo,
	expectedData []byte,
) (installed bool, err error) {
	current, err := os.Lstat(sourcePath)
	if err != nil {
		return false, fmt.Errorf("recheck source before replacement: %w", err)
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
			displacedData, _, err := readSourceFile(
				displacedPath,
				int64(len(expectedData))+1,
			)
			if err != nil {
				return fmt.Errorf("verify displaced source contents: %w", err)
			}
			defer wipe(displacedData)
			if !bytes.Equal(displacedData, expectedData) {
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
