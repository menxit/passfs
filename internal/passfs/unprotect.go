package passfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"filippo.io/age"
)

type UnprotectIssue struct {
	Path string
	Err  error
}

type UnprotectReport struct {
	Unprotected []string
	Failed      []UnprotectIssue
	Warnings    []UnprotectIssue
	Err         error
}

type plaintextDestination struct {
	absent     bool
	linkTarget string
}

// UnprotectAll materializes every protected file at its original absolute
// path. A ciphertext is removed only after its plaintext has been durably
// installed. Callers must stop the FUSE service before invoking this method.
func (v *Volume) UnprotectAll(
	ctx context.Context,
	forbiddenRoots []string,
) UnprotectReport {
	v.namespaceMu.Lock()
	defer v.namespaceMu.Unlock()

	records := v.linkRecords()
	protected := make([]linkRecord, 0, len(records))
	for _, record := range records {
		if record.protected {
			protected = append(protected, record)
		}
	}
	return v.unprotectRecords(
		ctx,
		protected,
		forbiddenRoots,
		v.root,
		"Authorize converting all passfs files to plaintext",
	)
}

// UnprotectFile materializes one protected file at its original absolute path.
// A ciphertext is removed only after its plaintext has been durably installed.
// Callers must stop the FUSE service before invoking this method.
func (v *Volume) UnprotectFile(
	ctx context.Context,
	sourcePath string,
	forbiddenRoots []string,
) UnprotectReport {
	var report UnprotectReport
	absolute, err := filepath.Abs(sourcePath)
	if err != nil {
		report.Failed = append(report.Failed, UnprotectIssue{
			Path: sourcePath,
			Err:  err,
		})
		return report
	}
	absolute = filepath.Clean(absolute)

	v.namespaceMu.Lock()
	defer v.namespaceMu.Unlock()

	for _, record := range v.linkRecords() {
		if !record.protected {
			continue
		}
		original, err := OriginalPath(record.relative)
		if err != nil || filepath.Clean(original) != absolute {
			continue
		}
		return v.unprotectRecords(
			ctx,
			[]linkRecord{record},
			forbiddenRoots,
			absolute,
			"Authorize converting this passfs file to plaintext",
		)
	}

	report.Failed = append(report.Failed, UnprotectIssue{
		Path: absolute,
		Err:  errors.New("file is not protected by passfs"),
	})
	return report
}

func (v *Volume) unprotectRecords(
	ctx context.Context,
	protected []linkRecord,
	forbiddenRoots []string,
	promptPath string,
	promptDescription string,
) UnprotectReport {
	var report UnprotectReport
	if len(protected) == 0 {
		return report
	}

	identity, err := v.requestIdentity(ctx, PromptRequest{
		Path:        promptPath,
		Operation:   "unprotect",
		Description: promptDescription,
	})
	if err != nil {
		report.Err = err
		return report
	}

	for _, record := range protected {
		issuePath := record.relative
		sourcePath, err := OriginalPath(record.relative)
		if sourcePath != "" {
			issuePath = sourcePath
		}
		if err == nil {
			err = validateUnprotectDestination(sourcePath, forbiddenRoots)
		}
		if err == nil {
			var warning error
			warning, err = v.unprotectFile(record, sourcePath, identity)
			if warning != nil {
				report.Warnings = append(report.Warnings, UnprotectIssue{
					Path: sourcePath,
					Err:  warning,
				})
			}
		}
		if err != nil {
			report.Failed = append(report.Failed, UnprotectIssue{
				Path: issuePath,
				Err:  err,
			})
			continue
		}
		report.Unprotected = append(report.Unprotected, sourcePath)
	}
	return report
}

func (v *Volume) unprotectFile(
	record linkRecord,
	sourcePath string,
	identity *age.X25519Identity,
) (warning, err error) {
	data, err := v.decryptFileWithIdentity(record.relative, identity)
	if err != nil {
		return nil, err
	}
	defer wipe(data)

	meta := v.fileMeta(record.relative, nil)
	destination, alreadyMaterialized, err := v.inspectUnprotectDestination(
		record,
		sourcePath,
		data,
	)
	if err != nil {
		return nil, err
	}
	if !alreadyMaterialized {
		if err := materializePlaintext(sourcePath, data, meta, destination); err != nil {
			return nil, fmt.Errorf("materialize plaintext: %w", err)
		}
	}

	removed, cleanupErr := v.removeMaterializedCiphertext(record.relative)
	if !removed {
		return nil, fmt.Errorf(
			"plaintext was materialized but encrypted data was preserved: %w",
			cleanupErr,
		)
	}
	return cleanupErr, nil
}

func (v *Volume) inspectUnprotectDestination(
	record linkRecord,
	sourcePath string,
	plaintext []byte,
) (plaintextDestination, bool, error) {
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		return plaintextDestination{}, false, err
	}
	if !link.exists {
		if record.linkTarget != "" {
			return plaintextDestination{}, false, errors.New(
				"the registered protected link is missing; encrypted data was preserved",
			)
		}
		parentInfo, err := os.Stat(filepath.Dir(sourcePath))
		if err != nil {
			return plaintextDestination{}, false, fmt.Errorf(
				"inspect destination directory: %w",
				err,
			)
		}
		if !parentInfo.IsDir() {
			return plaintextDestination{}, false, errors.New(
				"plaintext destination parent is not a directory",
			)
		}
		return plaintextDestination{absent: true}, false, nil
	}
	if link.isSymlink {
		if record.linkTarget == "" ||
			link.target != filepath.Clean(record.linkTarget) {
			return plaintextDestination{}, false, errors.New(
				"pathname is not the registered passfs link; encrypted data was preserved",
			)
		}
		return plaintextDestination{
			linkTarget: filepath.Clean(record.linkTarget),
		}, false, nil
	}

	current, _, err := readSourceFile(sourcePath, v.maxFileSize)
	if err != nil {
		return plaintextDestination{}, false, fmt.Errorf(
			"inspect existing plaintext destination: %w",
			err,
		)
	}
	defer wipe(current)
	if !bytes.Equal(current, plaintext) {
		return plaintextDestination{}, false, errors.New(
			"pathname contains different plaintext; encrypted data was preserved",
		)
	}
	return plaintextDestination{}, true, nil
}

func materializePlaintext(
	sourcePath string,
	data []byte,
	meta FileMeta,
	destination plaintextDestination,
) (resultErr error) {
	parent := filepath.Dir(sourcePath)
	temporaryDirectory, err := os.MkdirTemp(parent, ".passfs-unprotect-*")
	if err != nil {
		return err
	}
	temporaryPath := filepath.Join(temporaryDirectory, "plaintext")
	var stagedInfo os.FileInfo
	cleanup := func() error {
		info, statErr := os.Lstat(temporaryPath)
		switch {
		case statErr == nil && stagedInfo != nil && os.SameFile(stagedInfo, info):
			if err := os.Remove(temporaryPath); err != nil {
				return err
			}
		case statErr != nil && !errors.Is(statErr, os.ErrNotExist):
			return statErr
		}
		if err := os.Remove(temporaryDirectory); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	cleaned := false
	defer func() {
		if !cleaned {
			resultErr = errors.Join(resultErr, cleanup())
		}
	}()
	file, err := os.OpenFile(
		temporaryPath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return err
	}
	stagedInfo, err = file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	closeWithError := func(operationErr error) error {
		return errors.Join(operationErr, file.Close())
	}
	if _, err := file.Write(data); err != nil {
		return closeWithError(err)
	}
	if err := file.Chmod(os.FileMode(meta.Mode & 0o777)); err != nil {
		return closeWithError(err)
	}
	modTime := time.Unix(0, meta.MTime)
	if meta.MTime == 0 {
		modTime = time.Now()
	}
	if err := os.Chtimes(temporaryPath, modTime, modTime); err != nil {
		return closeWithError(err)
	}
	if err := file.Sync(); err != nil {
		return closeWithError(err)
	}
	if err := file.Close(); err != nil {
		return err
	}

	if err := atomicInstallPlaintext(temporaryPath, sourcePath, destination); err != nil {
		return err
	}
	if err := cleanup(); err != nil {
		return fmt.Errorf("remove plaintext staging directory: %w", err)
	}
	cleaned = true
	return syncDirectory(parent)
}

func atomicInstallPlaintext(
	temporaryPath string,
	sourcePath string,
	destination plaintextDestination,
) error {
	if destination.absent {
		if err := renameNoReplace(temporaryPath, sourcePath); err != nil {
			return fmt.Errorf("install plaintext without replacing a file: %w", err)
		}
		return nil
	}

	if err := exchangePaths(temporaryPath, sourcePath); err != nil {
		return fmt.Errorf("atomically replace protected link: %w", err)
	}
	if displacedLinkMatches(
		temporaryPath,
		filepath.Dir(sourcePath),
		destination.linkTarget,
	) {
		return os.Remove(temporaryPath)
	}
	rollbackErr := exchangePaths(temporaryPath, sourcePath)
	return errors.Join(
		errors.New("protected link changed while plaintext was being installed"),
		rollbackErr,
	)
}

func displacedLinkMatches(path, originalParent, expectedTarget string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(path)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(originalParent, target)
	}
	return filepath.Clean(target) == filepath.Clean(expectedTarget)
}

func (v *Volume) removeMaterializedCiphertext(
	relative string,
) (removed bool, cleanupErr error) {
	path, err := v.encryptedPath(relative)
	if err != nil {
		return false, err
	}
	key := metadataKey(relative)

	v.metadataMu.Lock()
	meta, hadMeta := v.metadata.Files[key]
	linkTarget, hadLink := v.metadata.Links[key]
	if err := v.updateMetadataLocked(func(metadata *Metadata) error {
		delete(metadata.Files, key)
		delete(metadata.Links, key)
		return nil
	}); err != nil {
		v.metadataMu.Unlock()
		return false, fmt.Errorf("prepare encrypted metadata removal: %w", err)
	}
	v.metadataMu.Unlock()

	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		restoreErr := v.restoreUnprotectMetadata(
			key,
			meta,
			hadMeta,
			linkTarget,
			hadLink,
		)
		return false, errors.Join(
			fmt.Errorf("remove encrypted file: %w", err),
			restoreErr,
		)
	}

	parent := filepath.Dir(path)
	syncErr := syncDirectory(parent)
	pruneErr := pruneEmptyDirectories(parent, filepath.Join(v.root, "files"))
	return true, errors.Join(syncErr, pruneErr)
}

func (v *Volume) restoreUnprotectMetadata(
	key string,
	meta FileMeta,
	hadMeta bool,
	linkTarget string,
	hadLink bool,
) error {
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	if err := v.updateMetadataLocked(func(metadata *Metadata) error {
		if hadMeta {
			metadata.Files[key] = meta
		}
		if hadLink {
			metadata.Links[key] = linkTarget
		}
		return nil
	}); err != nil {
		return fmt.Errorf("restore metadata after encrypted-file removal failed: %w", err)
	}
	return nil
}

func pruneEmptyDirectories(directory, stop string) error {
	stop = filepath.Clean(stop)
	for current := filepath.Clean(directory); current != stop; current = filepath.Dir(current) {
		if !PathWithin(stop, current) {
			return errors.New("refusing to prune outside the encrypted files directory")
		}
		err := os.Remove(current)
		if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func validateUnprotectDestination(sourcePath string, forbiddenRoots []string) error {
	resolvedSource, err := ResolvePath(sourcePath)
	if err != nil {
		return fmt.Errorf("resolve plaintext destination: %w", err)
	}
	for _, root := range forbiddenRoots {
		resolvedRoot, err := ResolvePath(root)
		if err != nil {
			return fmt.Errorf("resolve forbidden passfs path: %w", err)
		}
		if PathWithin(resolvedRoot, resolvedSource) {
			return fmt.Errorf(
				"refusing to materialize plaintext inside passfs internal path %s",
				root,
			)
		}
	}
	return nil
}
