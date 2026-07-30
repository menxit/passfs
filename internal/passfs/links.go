package passfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const linkSyncInterval = 500 * time.Millisecond

type LinkSyncLogger interface {
	Printf(format string, values ...any)
}

type LinkSynchronizer struct {
	mu             sync.Mutex
	volume         *Volume
	mountPoint     string
	logger         LinkSyncLogger
	tracker        *protectedLinkTracker
	previousIssues map[string]string
	closed         bool
}

func NewLinkSynchronizer(
	volume *Volume,
	mountPoint string,
	logger LinkSyncLogger,
) (*LinkSynchronizer, error) {
	if err := ensureLinkReferenceCapacity(
		linkReferenceCount(volume.linkRecords()),
	); err != nil {
		return nil, err
	}
	synchronizer := &LinkSynchronizer{
		volume:         volume,
		mountPoint:     mountPoint,
		logger:         logger,
		tracker:        newProtectedLinkTracker(),
		previousIssues: make(map[string]string),
	}
	if err := volume.attachLinkSynchronizer(synchronizer); err != nil {
		return nil, err
	}
	return synchronizer, nil
}

// Synchronize performs one complete pass. Calling it once before exposing a
// newly mounted service ensures every existing protected link has a kernel
// reference before external rename or unlink operations can be interpreted.
func (synchronizer *LinkSynchronizer) Synchronize() {
	synchronizer.mu.Lock()
	defer synchronizer.mu.Unlock()
	if synchronizer.closed {
		return
	}

	issues := synchronizeLinksOnceTracked(
		synchronizer.volume,
		synchronizer.mountPoint,
		synchronizer.tracker,
	)
	currentIssues := make(map[string]string, len(issues))
	for path, issue := range issues {
		message := issue.Error()
		currentIssues[path] = message
		if errors.Is(issue, syscall.EBUSY) {
			continue
		}
		if synchronizer.previousIssues[path] != message &&
			synchronizer.logger != nil {
			synchronizer.logger.Printf(
				"synchronize protected link %q: %v",
				path,
				issue,
			)
		}
	}
	synchronizer.previousIssues = currentIssues
}

func (synchronizer *LinkSynchronizer) Run(ctx context.Context) {
	defer synchronizer.Close()
	ticker := time.NewTicker(linkSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			synchronizer.Synchronize()
		}
	}
}

func (synchronizer *LinkSynchronizer) Track(relative string) error {
	sourcePath, err := OriginalPath(relative)
	if err != nil {
		return err
	}
	synchronizer.mu.Lock()
	defer synchronizer.mu.Unlock()
	if synchronizer.closed {
		return errors.New("protected link tracker is closed")
	}
	if err := ensureLinkReferenceCapacity(
		linkReferenceCount(synchronizer.volume.linkRecords()),
	); err != nil {
		return err
	}
	return synchronizer.tracker.ensure(relative, sourcePath)
}

func (synchronizer *LinkSynchronizer) Close() {
	synchronizer.volume.detachLinkSynchronizer(synchronizer)
	synchronizer.mu.Lock()
	if !synchronizer.closed {
		synchronizer.closed = true
		synchronizer.tracker.close()
	}
	synchronizer.mu.Unlock()
}

func (v *Volume) attachLinkSynchronizer(synchronizer *LinkSynchronizer) error {
	v.linkSynchronizerMu.Lock()
	defer v.linkSynchronizerMu.Unlock()
	if v.linkSynchronizer != nil {
		return errors.New("a protected link synchronizer is already attached")
	}
	v.linkSynchronizer = synchronizer
	return nil
}

func (v *Volume) detachLinkSynchronizer(synchronizer *LinkSynchronizer) {
	v.linkSynchronizerMu.Lock()
	if v.linkSynchronizer == synchronizer {
		v.linkSynchronizer = nil
	}
	v.linkSynchronizerMu.Unlock()
}

func (v *Volume) registerProtectedLink(relative, target string) error {
	if err := v.setLinkTarget(relative, target); err != nil {
		return err
	}
	v.linkSynchronizerMu.RLock()
	synchronizer := v.linkSynchronizer
	v.linkSynchronizerMu.RUnlock()
	if synchronizer == nil {
		return nil
	}
	return synchronizer.Track(relative)
}

func synchronizeLinksOnceTracked(
	volume *Volume,
	mountPoint string,
	tracker *protectedLinkTracker,
) map[string]error {
	issues := make(map[string]error)
	records := volume.linkRecords()
	if tracker != nil {
		if err := ensureLinkReferenceCapacity(linkReferenceCount(records)); err != nil {
			issues[mountPoint] = fmt.Errorf(
				"reserve protected link tracking capacity: %w",
				err,
			)
			return issues
		}
	}
	processedMoves, moveIssues := synchronizeTrackedMoves(
		volume,
		mountPoint,
		tracker,
		records,
	)
	for path, issue := range moveIssues {
		issues[path] = issue
	}
	for _, record := range records {
		if processedMoves[metadataKey(record.relative)] {
			continue
		}
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

		recordedTarget := filepath.Clean(record.linkTarget)
		currentTarget := filepath.Clean(targetPath)
		if tracker != nil &&
			record.protected &&
			record.linkTarget != "" &&
			link.isSymlink &&
			(link.target == recordedTarget || link.target == currentTarget) {
			if err := tracker.ensure(record.relative, sourcePath); err != nil {
				issues[sourcePath] = err
				continue
			}
		}
		if tracker != nil && (!record.protected || record.linkTarget == "") {
			tracker.forget(record.relative)
		}

		switch {
		case record.protected && record.linkTarget != "" && !link.exists:
			movedPath, observedDeletion, moveErr := locateMovedProtectedLink(
				tracker,
				record,
				sourcePath,
				targetPath,
			)
			if moveErr != nil {
				issues[sourcePath] = moveErr
				continue
			}
			if movedPath != "" {
				if err := synchronizeMovedProtectedLink(
					volume,
					mountPoint,
					tracker,
					record,
					movedPath,
					targetPath,
				); err != nil {
					issues[sourcePath] = err
				}
				continue
			}
			if tracker != nil && !observedDeletion {
				issues[sourcePath] = errors.New(
					"protected link was already missing when passfs started; encrypted data was preserved because an offline move and deletion cannot be distinguished",
				)
				continue
			}
			if err := volume.removeProtectedFile(record.relative); err != nil &&
				!errors.Is(err, os.ErrNotExist) {
				issues[sourcePath] = fmt.Errorf("remove encrypted file: %w", err)
				continue
			}
			if tracker != nil {
				tracker.forget(record.relative)
			}
			if err := volume.setLinkTarget(record.relative, ""); err != nil {
				issues[sourcePath] = fmt.Errorf("clear removed link record: %w", err)
			}

		case record.protected && record.linkTarget != "" && !link.isSymlink:
			issues[sourcePath] = errors.New(
				"pathname was replaced instead of deleted; encrypted data was preserved",
			)

		case record.protected && record.linkTarget != "":
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
				if tracker != nil {
					if err := tracker.replace(
						record.relative,
						record.relative,
						sourcePath,
					); err != nil {
						issues[sourcePath] = err
						continue
					}
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

type trackedLinkMove struct {
	record     linkRecord
	sourcePath string
	movedPath  string
	oldTarget  string
	newTarget  string
	newStorage string
}

func synchronizeTrackedMoves(
	volume *Volume,
	mountPoint string,
	tracker *protectedLinkTracker,
	records []linkRecord,
) (map[string]bool, map[string]error) {
	processed := make(map[string]bool)
	issues := make(map[string]error)
	if tracker == nil {
		return processed, issues
	}

	moves := make(map[string]trackedLinkMove)
	for _, record := range records {
		if !record.protected || record.linkTarget == "" {
			continue
		}
		sourcePath, err := OriginalPath(record.relative)
		if err != nil {
			continue
		}
		movedPath, linked, tracked, err := tracker.state(record.relative)
		if err != nil || !tracked || !linked ||
			filepath.Clean(movedPath) == filepath.Clean(sourcePath) {
			continue
		}
		oldTarget, err := MountedPath(mountPoint, sourcePath)
		if err != nil {
			continue
		}
		newTarget, newStorage, err := movedProtectedLinkDestination(
			volume,
			mountPoint,
			movedPath,
			oldTarget,
		)
		if err != nil {
			continue
		}
		moves[metadataKey(record.relative)] = trackedLinkMove{
			record:     record,
			sourcePath: sourcePath,
			movedPath:  movedPath,
			oldTarget:  oldTarget,
			newTarget:  newTarget,
			newStorage: newStorage,
		}
	}

	incoming := make(map[string]string, len(moves))
	queue := make([]string, 0, len(moves))
	for oldKey, move := range moves {
		newKey := metadataKey(move.newStorage)
		incoming[newKey] = oldKey
		if _, occupiedByMove := moves[newKey]; !occupiedByMove {
			queue = append(queue, oldKey)
		}
	}
	sort.Strings(queue)
	for len(queue) != 0 {
		key := queue[0]
		queue = queue[1:]
		if processed[key] {
			continue
		}
		move := moves[key]
		err := synchronizeMovedProtectedLink(
			volume,
			mountPoint,
			tracker,
			move.record,
			move.movedPath,
			move.oldTarget,
		)
		processed[key] = true
		if err != nil {
			issues[move.sourcePath] = err
			continue
		}
		if predecessor := incoming[key]; predecessor != "" {
			queue = append(queue, predecessor)
		}
	}

	visited := make(map[string]bool, len(moves))
	for _, record := range records {
		start := metadataKey(record.relative)
		if processed[start] ||
			visited[start] ||
			moves[start].record.relative == "" {
			continue
		}
		var sequence []string
		indices := make(map[string]int)
		current := start
		for {
			if index, exists := indices[current]; exists {
				cycleKeys := sequence[index:]
				if len(cycleKeys) >= 2 {
					synchronizeTrackedMoveCycle(
						volume,
						tracker,
						moves,
						cycleKeys,
						processed,
						issues,
					)
				}
				break
			}
			if visited[current] {
				break
			}
			if processed[current] {
				break
			}
			move, exists := moves[current]
			if !exists {
				break
			}
			indices[current] = len(sequence)
			sequence = append(sequence, current)
			current = metadataKey(move.newStorage)
		}
		for _, key := range sequence {
			visited[key] = true
		}
	}
	return processed, issues
}

func synchronizeTrackedMoveCycle(
	volume *Volume,
	tracker *protectedLinkTracker,
	moves map[string]trackedLinkMove,
	cycleKeys []string,
	processed map[string]bool,
	issues map[string]error,
) {
	cycle := make([]string, len(cycleKeys))
	rekeys := make(map[string]string, len(cycleKeys))
	for index, key := range cycleKeys {
		move := moves[key]
		cycle[index] = move.record.relative
		rekeys[move.record.relative] = move.newStorage
		processed[key] = true
	}

	committed, cycleErr := volume.cycleProtectedFiles(cycle)
	if !committed {
		for _, key := range cycleKeys {
			move := moves[key]
			issues[move.sourcePath] = fmt.Errorf(
				"rotate encrypted files after protected link moves: %w",
				cycleErr,
			)
		}
		return
	}

	tracker.rekey(rekeys)
	for _, key := range cycleKeys {
		move := moves[key]
		updateErr := replaceProtectedLink(
			move.movedPath,
			move.newTarget,
			move.oldTarget,
		)
		if updateErr == nil {
			updateErr = volume.setLinkTarget(
				move.newStorage,
				move.newTarget,
			)
		}
		if updateErr != nil || cycleErr != nil {
			if updateErr != nil {
				updateErr = fmt.Errorf(
					"update moved protected link: %w",
					updateErr,
				)
			}
			issues[move.sourcePath] = errors.Join(
				cycleErr,
				updateErr,
			)
		}
	}
}

func linkReferenceCount(records []linkRecord) int {
	count := 0
	for _, record := range records {
		if record.protected && record.linkTarget != "" {
			count++
		}
	}
	return count
}

func locateMovedProtectedLink(
	tracker *protectedLinkTracker,
	record linkRecord,
	sourcePath string,
	targetPath string,
) (path string, observedDeletion bool, err error) {
	if tracker != nil {
		path, linked, tracked, err := tracker.state(record.relative)
		if err != nil {
			return "", false, fmt.Errorf("inspect tracked protected link: %w", err)
		}
		if tracked {
			if linked {
				if filepath.Clean(path) == filepath.Clean(sourcePath) {
					return "", false, errors.New(
						"tracked protected link still reports its missing original pathname; encrypted data was preserved",
					)
				}
				return path, false, nil
			}
			return "", true, nil
		}
	}

	path, err = findMovedProtectedLink(sourcePath, targetPath)
	if err != nil {
		return "", false, err
	}
	return path, false, nil
}

func synchronizeMovedProtectedLink(
	volume *Volume,
	mountPoint string,
	tracker *protectedLinkTracker,
	record linkRecord,
	movedPath string,
	oldTarget string,
) error {
	newTarget, newStorage, err := movedProtectedLinkDestination(
		volume,
		mountPoint,
		movedPath,
		oldTarget,
	)
	if err != nil {
		return err
	}
	if err := volume.renameProtectedFile(record.relative, newStorage); err != nil {
		return fmt.Errorf(
			"rename encrypted file after protected link move: %w",
			err,
		)
	}
	if err := replaceProtectedLink(movedPath, newTarget, oldTarget); err != nil {
		rollbackErr := volume.renameProtectedFile(
			newStorage,
			record.relative,
		)
		return errors.Join(
			fmt.Errorf("update moved protected link: %w", err),
			rollbackErr,
		)
	}

	var trackerErr error
	if tracker != nil {
		trackerErr = tracker.replace(
			record.relative,
			newStorage,
			movedPath,
		)
	}
	linkErr := volume.setLinkTarget(newStorage, newTarget)
	if linkErr != nil {
		linkErr = fmt.Errorf("register moved protected link: %w", linkErr)
	}
	return errors.Join(trackerErr, linkErr)
}

func movedProtectedLinkDestination(
	volume *Volume,
	mountPoint string,
	movedPath string,
	oldTarget string,
) (newTarget string, newStorage string, resultErr error) {
	movedLink, err := inspectProtectedLink(movedPath)
	if err != nil {
		return "", "", fmt.Errorf("inspect moved protected link: %w", err)
	}
	if !movedLink.isSymlink ||
		movedLink.target != filepath.Clean(oldTarget) {
		return "", "", errors.New(
			"moved protected link changed before it could be synchronized; encrypted data was preserved",
		)
	}
	internal, err := movedLinkUsesInternalStorage(
		volume.root,
		mountPoint,
		movedPath,
	)
	if err != nil {
		return "", "", fmt.Errorf("resolve moved protected link: %w", err)
	}
	if internal {
		return "", "", errors.New(
			"refusing to move a protected link into passfs internal storage",
		)
	}

	newTarget, err = MountedPath(mountPoint, movedPath)
	if err != nil {
		return "", "", err
	}
	if err := validateImportTarget(mountPoint, newTarget); err != nil {
		return "", "", fmt.Errorf("validate moved protected link: %w", err)
	}
	newRelative, err := filepath.Rel(mountPoint, newTarget)
	if err != nil || newRelative == "." ||
		newRelative == ".." ||
		strings.HasPrefix(newRelative, ".."+string(os.PathSeparator)) {
		return "", "", errors.New(
			"moved protected link resolves outside the passfs mount",
		)
	}
	return newTarget, storagePath(newRelative), nil
}

func movedLinkUsesInternalStorage(
	vault string,
	mountPoint string,
	movedPath string,
) (bool, error) {
	resolvedParent, err := ResolvePath(filepath.Dir(movedPath))
	if err != nil {
		return false, err
	}
	resolvedMovedPath := filepath.Join(resolvedParent, filepath.Base(movedPath))
	resolvedVault, err := ResolvePath(vault)
	if err != nil {
		return false, err
	}
	resolvedMountPoint, err := canonicalMountPoint(mountPoint)
	if err != nil {
		return false, err
	}

	roots := []string{resolvedVault, resolvedMountPoint}
	if filepath.Base(resolvedVault) == "vault" &&
		filepath.Base(resolvedMountPoint) == "mnt" &&
		filepath.Dir(resolvedVault) == filepath.Dir(resolvedMountPoint) {
		roots = append(roots, filepath.Dir(resolvedVault))
	}
	for _, root := range roots {
		if PathWithin(root, resolvedMovedPath) {
			return true, nil
		}
	}
	return false, nil
}

func findMovedProtectedLink(sourcePath, targetPath string) (string, error) {
	parent := filepath.Dir(sourcePath)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", fmt.Errorf("inspect directory for moved protected link: %w", err)
	}
	var match string
	for _, entry := range entries {
		candidate := filepath.Join(parent, entry.Name())
		if candidate == sourcePath || entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		link, err := inspectProtectedLink(candidate)
		if err != nil {
			return "", err
		}
		if !link.isSymlink || link.target != filepath.Clean(targetPath) {
			continue
		}
		if match != "" {
			return "", errors.New(
				"multiple symbolic links reference the missing passfs pathname; encrypted data was preserved",
			)
		}
		match = candidate
	}
	return match, nil
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
