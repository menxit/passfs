package passfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const linkSyncInterval = 500 * time.Millisecond

type LinkSyncLogger interface {
	Printf(format string, values ...any)
}

// RunLinkSynchronizer keeps registered project-side symbolic links and
// protected files in sync. Files created only inside the mounted filesystem are
// intentionally not published at their mapped source paths; passfs encrypt
// registers a link explicitly. Once registered, removing that link deletes the
// corresponding protected file.
func RunLinkSynchronizer(
	ctx context.Context,
	volume *Volume,
	mountPoint string,
	logger LinkSyncLogger,
) {
	previousIssues := make(map[string]string)
	synchronize := func() {
		issues := synchronizeLinksOnce(volume, mountPoint)
		currentIssues := make(map[string]string, len(issues))
		for path, issue := range issues {
			message := issue.Error()
			currentIssues[path] = message
			if previousIssues[path] != message && logger != nil {
				logger.Printf("synchronize protected link %s: %v", path, issue)
			}
		}
		previousIssues = currentIssues
	}

	synchronize()
	ticker := time.NewTicker(linkSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			synchronize()
		}
	}
}

func synchronizeLinksOnce(volume *Volume, mountPoint string) map[string]error {
	issues := make(map[string]error)
	for _, record := range volume.linkRecords() {
		sourcePath, err := OriginalPath(record.relative)
		if err != nil {
			issues[record.relative] = err
			continue
		}
		targetPath, err := MountedPath(mountPoint, sourcePath)
		if err != nil {
			issues[sourcePath] = err
			continue
		}

		link, err := inspectProtectedLink(sourcePath)
		if err != nil {
			issues[sourcePath] = err
			continue
		}

		switch {
		case record.protected && record.linkTarget != "" && !link.exists:
			if err := volume.removeProtectedFile(record.relative); err != nil &&
				!errors.Is(err, os.ErrNotExist) {
				issues[sourcePath] = fmt.Errorf("remove encrypted file: %w", err)
				continue
			}
			if err := volume.setLinkTarget(record.relative, ""); err != nil {
				issues[sourcePath] = fmt.Errorf("clear removed link record: %w", err)
			}

		case record.protected && record.linkTarget != "" && !link.isSymlink:
			issues[sourcePath] = errors.New(
				"pathname was replaced instead of deleted; encrypted data was preserved",
			)

		case record.protected && record.linkTarget != "":
			recordedTarget := filepath.Clean(record.linkTarget)
			currentTarget := filepath.Clean(targetPath)
			switch link.target {
			case currentTarget:
				if recordedTarget != currentTarget {
					if err := volume.setLinkTarget(record.relative, currentTarget); err != nil {
						issues[sourcePath] = fmt.Errorf("update protected link record: %w", err)
					}
				}
			case recordedTarget:
				if err := replaceProtectedLink(
					sourcePath,
					currentTarget,
					recordedTarget,
				); err != nil {
					issues[sourcePath] = fmt.Errorf("update protected link target: %w", err)
					continue
				}
				if err := volume.setLinkTarget(record.relative, currentTarget); err != nil {
					issues[sourcePath] = fmt.Errorf("update protected link record: %w", err)
				}
			default:
				issues[sourcePath] = errors.New(
					"symbolic link target changed outside passfs; encrypted data was preserved",
				)
			}

		case !record.protected && record.linkTarget != "":
			if link.isSymlink && link.target == filepath.Clean(record.linkTarget) {
				if err := os.Remove(sourcePath); err != nil {
					issues[sourcePath] = fmt.Errorf("remove dangling protected link: %w", err)
					continue
				}
				if err := syncDirectory(filepath.Dir(sourcePath)); err != nil {
					issues[sourcePath] = fmt.Errorf("sync removed protected link: %w", err)
					continue
				}
			}
			if link.exists && (!link.isSymlink ||
				link.target != filepath.Clean(record.linkTarget)) {
				issues[sourcePath] = errors.New(
					"protected file was removed but its pathname now belongs to another entry",
				)
			}
			if err := volume.setLinkTarget(record.relative, ""); err != nil {
				issues[sourcePath] = fmt.Errorf("clear dangling link record: %w", err)
			}
		}
	}
	return issues
}

type protectedLink struct {
	exists    bool
	isSymlink bool
	target    string
}

func inspectProtectedLink(sourcePath string) (protectedLink, error) {
	info, err := os.Lstat(sourcePath)
	if errors.Is(err, os.ErrNotExist) {
		return protectedLink{}, nil
	}
	if err != nil {
		return protectedLink{}, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return protectedLink{exists: true}, nil
	}
	linkTarget, err := os.Readlink(sourcePath)
	if err != nil {
		return protectedLink{}, err
	}
	if !filepath.IsAbs(linkTarget) {
		linkTarget = filepath.Join(filepath.Dir(sourcePath), linkTarget)
	}
	return protectedLink{
		exists:    true,
		isSymlink: true,
		target:    filepath.Clean(linkTarget),
	}, nil
}

func replaceProtectedLink(sourcePath, targetPath, expectedTarget string) error {
	_, err := exchangePathWithSymlink(
		sourcePath,
		targetPath,
		func(displacedPath string) error {
			link, err := inspectProtectedLink(displacedPath)
			if err != nil {
				return err
			}
			if !link.isSymlink || link.target != filepath.Clean(expectedTarget) {
				return errors.New(
					"protected link changed while its target was being updated",
				)
			}
			return nil
		},
	)
	return err
}
