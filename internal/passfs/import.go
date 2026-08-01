package passfs

import (
	"bytes"
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

type ProtectedLinkRegistrar func(sourcePath, targetPath string) error

// ImportThroughMount moves a plaintext file into the mounted passfs namespace
// and replaces its original pathname with a symbolic link to the protected
// view. All writes to targetPath therefore go through the mounted filesystem
// adapter; the CLI never writes ciphertext through the backing store.
//
// If the target is already protected and the original pathname is absent, the
// function only restores the symbolic link. This supports volumes created by
// passfs versions that removed the original plaintext pathname.
// The registrar lets each filesystem adapter choose its control plane for the
// verified project-side symbolic link.
func ImportThroughMount(
	sourcePath string,
	vault string,
	mountPoint string,
	maxFileSize int64,
	register ProtectedLinkRegistrar,
) (result ImportResult, err error) {
	if maxFileSize <= 0 {
		return result, errors.New("maximum file size must be greater than zero")
	}
	if register == nil {
		return result, errors.New("protected link registrar is required")
	}
	sourcePath, targetPath, err := resolveImportPaths(sourcePath, vault, mountPoint, true)
	if err != nil {
		return result, err
	}
	result.TargetPath = targetPath
	result, err = importFile(sourcePath, targetPath, maxFileSize)
	if err != nil {
		return result, err
	}
	if err := register(sourcePath, targetPath); err != nil {
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
func ValidateImportThroughMount(sourcePath, vault, mountPoint string, maxFileSize int64) error {
	if maxFileSize <= 0 {
		return errors.New("maximum file size must be greater than zero")
	}
	sourcePath, targetPath, err := resolveImportPaths(sourcePath, vault, mountPoint, true)
	if err != nil {
		return err
	}
	targetInfo, targetErr := os.Lstat(targetPath)
	switch {
	case targetErr == nil:
		if !targetInfo.Mode().IsRegular() {
			return fmt.Errorf("protected target %s is not a regular file", targetPath)
		}
		return validateExistingImportTarget(
			sourcePath,
			targetPath,
			targetInfo,
			maxFileSize,
		)
	case !errors.Is(targetErr, os.ErrNotExist):
		return fmt.Errorf("check encrypted target: %w", targetErr)
	}

	file, _, err := openValidatedSource(sourcePath, maxFileSize)
	if err != nil {
		return err
	}
	return file.Close()
}

func validateExistingImportTarget(
	sourcePath string,
	targetPath string,
	targetInfo os.FileInfo,
	maxFileSize int64,
) error {
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		return fmt.Errorf("inspect protected path %s: %w", sourcePath, err)
	}
	if !link.exists {
		return nil
	}
	if !link.isSymlink {
		if targetInfo.Size() == 0 {
			source, sourceInfo, sourceErr := openValidatedSource(
				sourcePath,
				maxFileSize,
			)
			if sourceErr != nil {
				return sourceErr
			}
			if closeErr := source.Close(); closeErr != nil {
				return closeErr
			}
			if sourceInfo.Size() > 0 {
				return nil
			}
		}
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
}

func resolveImportPaths(
	sourcePath string,
	vault string,
	mountPoint string,
	allocate bool,
) (string, string, error) {
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
	_, targetPath, err := protectedObjectForSource(
		vault,
		mountPoint,
		sourcePath,
		allocate,
	)
	if err != nil {
		return "", "", err
	}
	if PathWithin(mountPoint, sourcePath) {
		return "", "", errors.New("cannot import a file from inside the passfs mount")
	}
	return sourcePath, targetPath, nil
}

// ReconcileProtectedEdit restores the protected link after an editor replaces
// it with a regular file during an atomic save. The replacement plaintext is
// written through the mounted target before the link is atomically restored.
// A matching protected link needs no reconciliation.
func ReconcileProtectedEdit(
	sourcePath string,
	targetPath string,
	maxFileSize int64,
	register ProtectedLinkRegistrar,
) (bool, error) {
	if maxFileSize <= 0 {
		return false, errors.New("maximum file size must be greater than zero")
	}
	if register == nil {
		return false, errors.New("protected link registrar is required")
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
	if err := register(sourcePath, targetPath); err != nil {
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
		recovered, recoverErr := recoverInterruptedEmptyImport(
			sourcePath,
			targetPath,
			targetInfo,
			maxFileSize,
		)
		if recoverErr != nil {
			return result, recoverErr
		}
		if !recovered {
			created, linkErr := EnsureProtectedLink(sourcePath, targetPath)
			if linkErr != nil {
				return result, linkErr
			}
			result.LinkCreated = created
			return result, nil
		}
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

// recoverInterruptedEmptyImport removes the zero-length target left behind
// when a filesystem adapter successfully created a protected file but failed
// before returning its open handle. Recovery is deliberately narrow: the
// original must still be a nonempty regular file, while the protected target
// must still be the exact empty file observed by the caller.
func recoverInterruptedEmptyImport(
	sourcePath string,
	targetPath string,
	targetInfo os.FileInfo,
	maxFileSize int64,
) (bool, error) {
	if targetInfo.Size() != 0 {
		return false, nil
	}
	source, sourceInfo, err := openValidatedSource(sourcePath, maxFileSize)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// A missing source is the normal legacy case: the empty protected
			// target is authoritative and its project-side link can be restored.
			return false, nil
		}
		return false, fmt.Errorf(
			"validate source while recovering an interrupted import: %w",
			err,
		)
	}
	if err := source.Close(); err != nil {
		return false, fmt.Errorf("close source after interrupted import check: %w", err)
	}
	if sourceInfo.Size() == 0 {
		return false, nil
	}

	currentTarget, err := os.Lstat(targetPath)
	if err != nil {
		return false, fmt.Errorf("recheck interrupted encrypted target: %w", err)
	}
	if !sameFileVersion(targetInfo, currentTarget) {
		return false, errors.New(
			"protected target changed while recovering an interrupted import",
		)
	}
	if err := os.Remove(targetPath); err != nil {
		return false, fmt.Errorf("remove interrupted encrypted target: %w", err)
	}
	return true, nil
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
