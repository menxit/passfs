package passfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// Native filesystem notifications are the primary reconciliation trigger.
	// The long safety pass only protects against an exceptionally lost kernel
	// event; keeping it infrequent avoids repeatedly walking user directories on
	// an otherwise idle laptop.
	linkSyncSafetyInterval         = 6 * time.Hour
	linkSyncFallbackInterval       = time.Minute
	linkSyncRetryInterval          = 100 * time.Millisecond
	linkSyncRetryMaximum           = time.Second
	trackedLinkDeletionGrace       = 500 * time.Millisecond
	pendingObjectRegistrationGrace = 30 * time.Second
)

var errIncompleteLinkSearch = errors.New(
	"protected link could not be located with a complete search; encrypted data was preserved",
)

type LinkSyncLogger interface {
	Printf(format string, values ...any)
}

type LinkSynchronizer struct {
	mu             sync.Mutex
	volume         *Volume
	mountPoint     string
	logger         LinkSyncLogger
	tracker        *protectedLinkTracker
	search         *movedProtectedLinkSearch
	globalSearch   bool
	previousIssues map[string]string
	closed         bool
}

// EnableGlobalMoveSearch adds the user's home and temporary directory to the
// one-time offline-move index. Adapters enable it in production; focused
// engine tests and embedders retain bounded per-project roots by default.
func (synchronizer *LinkSynchronizer) EnableGlobalMoveSearch() {
	synchronizer.mu.Lock()
	synchronizer.globalSearch = true
	synchronizer.search = nil
	synchronizer.mu.Unlock()
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
func (synchronizer *LinkSynchronizer) Synchronize() bool {
	retry := false
	err := WithLinkReconciliationLock(
		synchronizer.volume.root,
		func() error {
			synchronizer.mu.Lock()
			defer synchronizer.mu.Unlock()
			if synchronizer.closed {
				return nil
			}

			// Construction is cheap and indexing is lazy. Rebuilding here keeps
			// the target set current after imports while performing no user-tree
			// I/O on the normal all-links-present path.
			synchronizer.search = newMovedProtectedLinkSearchWithGlobalRoots(
				synchronizer.volume.root,
				synchronizer.mountPoint,
				synchronizer.volume.linkRecords(),
				synchronizer.globalSearch,
			)
			issues := synchronizeLinksOnceTrackedWithSearch(
				synchronizer.volume,
				synchronizer.mountPoint,
				synchronizer.tracker,
				synchronizer.search,
			)
			currentIssues := make(map[string]string, len(issues))
			for path, issue := range issues {
				message := issue.Error()
				currentIssues[path] = message
				if errors.Is(issue, syscall.EBUSY) ||
					errors.Is(issue, os.ErrNotExist) {
					retry = true
				}
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
			return nil
		},
	)
	if err != nil {
		if synchronizer.logger != nil {
			synchronizer.logger.Printf(
				"coordinate protected link reconciliation: %v",
				err,
			)
		}
		return true
	}
	return retry
}

// Prepare installs kernel references for links that are already in place
// without searching for offline moves. Native adapters use it before mounting
// so startup is never blocked by a bounded home-directory reconciliation.
func (synchronizer *LinkSynchronizer) Prepare() error {
	synchronizer.mu.Lock()
	defer synchronizer.mu.Unlock()
	if synchronizer.closed {
		return errors.New("protected link tracker is closed")
	}
	if err := synchronizer.volume.refreshMetadata(); err != nil {
		return err
	}
	for _, record := range synchronizer.volume.linkRecords() {
		if !record.protected || record.sourcePath == "" {
			continue
		}
		sourcePath := record.sourcePath
		targetPath, err := mountedPathForStorage(synchronizer.mountPoint, record.relative)
		if err != nil {
			continue
		}
		link, err := inspectProtectedLink(sourcePath)
		if err != nil {
			continue
		}
		if link.isSymlink && link.target == filepath.Clean(targetPath) {
			if err := synchronizer.tracker.ensure(record.relative, sourcePath); err != nil {
				return err
			}
		}
	}
	return nil
}

func (synchronizer *LinkSynchronizer) Run(ctx context.Context) {
	defer synchronizer.Close()
	var watcher linkChangeWatcher
	var watchedDirectories []string
	retryInterval := linkSyncRetryInterval
	defer func() {
		if watcher != nil {
			_ = watcher.close()
		}
	}()

	for {
		desiredDirectories := synchronizer.watchDirectories()
		var watchErr error
		if watcher == nil ||
			!slices.Equal(desiredDirectories, watchedDirectories) {
			var replacement linkChangeWatcher
			replacement, watchErr = newLinkChangeWatcher(desiredDirectories)
			if watchErr == nil {
				if watcher != nil {
					_ = watcher.close()
				}
				watcher = replacement
				watchedDirectories = desiredDirectories
			}
		}

		interval := linkSyncSafetyInterval
		var events <-chan struct{}
		var watcherErrors <-chan error
		if watcher != nil {
			events = watcher.events()
			watcherErrors = watcher.errors()
		}
		if watchErr != nil || watcher == nil {
			interval = linkSyncFallbackInterval
			if synchronizer.logger != nil {
				synchronizer.logger.Printf(
					"watch protected links; using periodic reconciliation: %v",
					watchErr,
				)
			}
		}

		// Reconcile after installing the watches. The watcher remains active
		// across normal events, avoiding both a subscription gap and repeated
		// kqueue/inotify construction. A short retry is used only for a
		// transient pathname race or a busy namespace lock.
		if synchronizer.Synchronize() {
			interval = retryInterval
			retryInterval = min(linkSyncRetryMaximum, retryInterval*2)
		} else {
			retryInterval = linkSyncRetryInterval
		}
		updatedDirectories := synchronizer.watchDirectories()
		if watchErr == nil && watcher != nil && !slices.Equal(
			updatedDirectories,
			watchedDirectories,
		) {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-events:
		case err := <-watcherErrors:
			if err != nil && synchronizer.logger != nil {
				synchronizer.logger.Printf("watch protected links: %v", err)
			}
			if watcher != nil {
				_ = watcher.close()
				watcher = nil
				watchedDirectories = nil
			}
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (synchronizer *LinkSynchronizer) watchDirectories() []string {
	directories := make(map[string]struct{})
	add := func(path string) {
		if directory := nearestExistingDirectory(path); directory != "" {
			directories[directory] = struct{}{}
		}
	}
	add(filepath.Join(synchronizer.volume.root, internalDirName))
	for _, record := range synchronizer.volume.linkRecords() {
		if !record.protected || record.sourcePath == "" {
			continue
		}
		add(filepath.Dir(record.sourcePath))
	}
	result := make([]string, 0, len(directories))
	for directory := range directories {
		result = append(result, directory)
	}
	sort.Strings(result)
	return result
}

// Watch the closest live ancestor when a protected file's parent was removed.
// Its recreation then produces an event that lets the synchronizer move the
// watch back down. Recording a missing directory as watched would otherwise
// leave an inotify/kqueue subscription permanently absent until the safety
// reconciliation many hours later.
func nearestExistingDirectory(path string) string {
	for {
		path = filepath.Clean(path)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return ""
		}
		path = parent
	}
}

func uniqueExistingDirectories(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(path)
		if _, exists := seen[path]; exists {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	sort.Strings(result)
	return result
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

func synchronizeLinksOnceTrackedWithSearch(
	volume *Volume,
	mountPoint string,
	tracker *protectedLinkTracker,
	movedLinkSearch *movedProtectedLinkSearch,
) map[string]error {
	return synchronizeOpaqueLinksOnce(
		volume,
		mountPoint,
		tracker,
		movedLinkSearch,
	)
}

func synchronizeOpaqueLinksOnce(
	volume *Volume,
	mountPoint string,
	tracker *protectedLinkTracker,
	search *movedProtectedLinkSearch,
) map[string]error {
	issues := make(map[string]error)
	directoryMoves := make(map[linkDirectoryMove]int)
	if err := volume.refreshMetadata(); err != nil {
		issues[mountPoint] = fmt.Errorf("refresh protected link metadata: %w", err)
		return issues
	}
	records := volume.linkRecords()
	if search == nil {
		search = newMovedProtectedLinkSearch(volume.root, mountPoint, records)
	}
	if tracker != nil {
		if err := ensureLinkReferenceCapacity(linkReferenceCount(records)); err != nil {
			issues[mountPoint] = err
			return issues
		}
	}

	for _, record := range records {
		if !record.protected {
			continue
		}
		expectedTarget, err := mountedPathForStorage(mountPoint, record.relative)
		if err != nil {
			issues[record.relative] = err
			continue
		}
		sourcePath := filepath.Clean(record.sourcePath)
		if sourcePath == "." {
			sourcePath = ""
		}
		link := protectedLink{}
		if sourcePath != "" {
			link, err = inspectProtectedLink(sourcePath)
			if err != nil {
				issues[sourcePath] = err
				continue
			}
		}

		if link.isSymlink &&
			(targetMatchesStorage(link.target, record.relative) ||
				(record.legacyTarget != "" && link.target == filepath.Clean(record.legacyTarget))) {
			if link.target != filepath.Clean(expectedTarget) {
				if err := replaceProtectedLink(sourcePath, expectedTarget, link.target); err != nil {
					issues[sourcePath] = fmt.Errorf("migrate protected link target: %w", err)
					continue
				}
			}
			if tracker != nil {
				if err := tracker.ensure(record.relative, sourcePath); err != nil {
					issues[sourcePath] = err
					continue
				}
			}
			if err := volume.clearLinkOrphan(record.relative); err != nil {
				issues[sourcePath] = err
			}
			continue
		}
		if record.recovery.State != "" {
			// Recovery states are terminal until the user restores the original
			// link or explicitly replaces/purges the encrypted object. A correct
			// link above clears the state automatically; every other pathname is
			// deliberately left untouched.
			continue
		}

		movedPath := ""
		tracked := false
		trackedLinked := false
		if tracker != nil {
			trackedPath, linked, isTracked, trackErr := tracker.state(record.relative)
			if trackErr != nil {
				issues[sourcePath] = trackErr
				continue
			}
			tracked = isTracked
			trackedLinked = linked
			if tracked {
				if linked && filepath.Clean(trackedPath) != sourcePath {
					movedPath = trackedPath
				}
			}
		}
		if movedPath == "" && tracked {
			if trackedLinked {
				// The kernel still resolves the reference at the registered path,
				// while Lstat observed it missing. This is a short pathname race;
				// never turn it into a tree scan or a deletion.
				issues[sourcePath] = syscall.EBUSY
				continue
			}
			if link.exists {
				_ = volume.markLinkRecovery(
					record.relative,
					RecoveryConflict,
					"protected pathname was replaced",
					time.Now(),
				)
				issues[sourcePath] = errors.New(
					"protected pathname was replaced; encrypted data was preserved",
				)
				continue
			}
			if record.orphanedAt == 0 ||
				time.Since(time.Unix(0, record.orphanedAt)) < trackedLinkDeletionGrace {
				_ = volume.markLinkOrphan(record.relative, time.Now())
				issues[sourcePath] = syscall.EBUSY
				continue
			}
			if err := volume.markLinkRecovery(
				record.relative,
				RecoveryTrash,
				"protected link was deleted",
				time.Now(),
			); err != nil && !errors.Is(err, os.ErrNotExist) {
				issues[sourcePath] = fmt.Errorf("move deleted protected object to recovery: %w", err)
				continue
			}
			tracker.forget(record.relative)
			continue
		}
		if movedPath == "" {
			movedPath, err = search.find(sourcePath, expectedTarget)
			if err == nil && movedPath == "" && record.legacyTarget != "" {
				movedPath, err = search.find(sourcePath, record.legacyTarget)
			}
			if err != nil {
				issues[sourcePath] = err
				_ = volume.markLinkOrphan(record.relative, time.Now())
				continue
			}
		}

		if movedPath != "" {
			movedLink, inspectErr := inspectProtectedLink(movedPath)
			if inspectErr != nil {
				issues[movedPath] = inspectErr
				continue
			}
			if !movedLink.isSymlink ||
				(!targetMatchesStorage(movedLink.target, record.relative) &&
					movedLink.target != filepath.Clean(record.legacyTarget)) {
				issues[movedPath] = errors.New("moved protected link changed target; encrypted data was preserved")
				_ = volume.markLinkRecovery(
					record.relative,
					RecoveryConflict,
					"moved protected link changed target",
					time.Now(),
				)
				continue
			}
			if link.exists {
				// Common atomic-save implementations first move the old pathname
				// aside and then install a regular file at the original pathname.
				// Treat that as a conflict, not as a user rename: retaining the
				// editor's moved symlink would silently change which filename owns
				// the encrypted contents and block explicit replacement recovery.
				if err := retireProtectedLink(movedPath, record.relative); err != nil &&
					!errors.Is(err, os.ErrNotExist) {
					issues[movedPath] = fmt.Errorf("retire displaced protected link: %w", err)
					continue
				}
				if err := volume.markLinkRecovery(
					record.relative,
					RecoveryConflict,
					"atomic save replaced the protected pathname",
					time.Now(),
				); err != nil {
					issues[sourcePath] = fmt.Errorf("record atomic-save conflict: %w", err)
					continue
				}
				if tracker != nil {
					tracker.forget(record.relative)
				}
				issues[sourcePath] = errors.New(
					"atomic save replaced the protected pathname; encrypted data was preserved",
				)
				continue
			}
			if movedLink.target != filepath.Clean(expectedTarget) {
				if err := replaceProtectedLink(movedPath, expectedTarget, movedLink.target); err != nil {
					issues[movedPath] = err
					continue
				}
			}
			if move, ok := inferLinkDirectoryMove(sourcePath, movedPath); ok {
				directoryMoves[move]++
			}
			if err := volume.setLinkSource(record.relative, movedPath); err != nil {
				issues[movedPath] = err
				continue
			}
			if tracker != nil {
				if err := tracker.replace(record.relative, record.relative, movedPath); err != nil {
					issues[movedPath] = err
				}
			}
			continue
		}

		if link.exists {
			_ = volume.markLinkRecovery(
				record.relative,
				RecoveryConflict,
				"protected pathname was replaced",
				time.Now(),
			)
			issues[sourcePath] = errors.New("protected pathname was replaced; encrypted data was preserved")
			continue
		}
		if sourcePath == "" && record.orphanedAt != 0 &&
			time.Since(time.Unix(0, record.orphanedAt)) < pendingObjectRegistrationGrace {
			issues[record.relative] = syscall.EBUSY
			continue
		}
		if record.legacyTarget != "" {
			issues[record.relative] = errors.New(
				"legacy protected link could not be located; encrypted data was preserved",
			)
			continue
		}
		if !search.comprehensive || !search.indexed {
			_ = volume.markLinkOrphan(record.relative, time.Now())
			// This is a stable safety state, not a transient lock race. Retrying
			// every second would repeatedly walk the same directories and waste
			// battery; filesystem events or the long safety pass will wake us.
			issues[sourcePath] = errIncompleteLinkSearch
			continue
		}
		if err := volume.markLinkRecovery(
			record.relative,
			RecoveryTrash,
			"protected link was deleted",
			time.Now(),
		); err != nil && !errors.Is(err, os.ErrNotExist) {
			issues[sourcePath] = fmt.Errorf("move deleted protected object to recovery: %w", err)
			continue
		}
		if tracker != nil {
			tracker.forget(record.relative)
		}
	}
	for move, count := range directoryMoves {
		if count < 2 || !confirmedDirectoryMove(move) {
			continue
		}
		changed, err := volume.rebaseLinkSources(move.oldRoot, move.newRoot)
		if err != nil {
			issues[move.oldRoot] = fmt.Errorf("record moved protected directory: %w", err)
			continue
		}
		if changed > 0 {
			// Re-run once with the inferred paths so deleted children are
			// reconciled against the new parent rather than the stale one.
			issues[move.oldRoot] = syscall.EBUSY
		}
	}
	return issues
}

type linkDirectoryMove struct {
	oldRoot string
	newRoot string
}

func inferLinkDirectoryMove(oldPath, newPath string) (linkDirectoryMove, bool) {
	oldPath = filepath.Clean(oldPath)
	newPath = filepath.Clean(newPath)
	if !filepath.IsAbs(oldPath) || !filepath.IsAbs(newPath) || oldPath == newPath {
		return linkDirectoryMove{}, false
	}
	oldParts := strings.Split(strings.TrimPrefix(filepath.ToSlash(oldPath), "/"), "/")
	newParts := strings.Split(strings.TrimPrefix(filepath.ToSlash(newPath), "/"), "/")
	suffix := 0
	for suffix < len(oldParts) && suffix < len(newParts) &&
		oldParts[len(oldParts)-1-suffix] == newParts[len(newParts)-1-suffix] {
		suffix++
	}
	// A shared filename is required. A renamed individual file does not prove
	// anything about its parent directory.
	if suffix == 0 || suffix == len(oldParts) || suffix == len(newParts) {
		return linkDirectoryMove{}, false
	}
	oldRoot := filepath.FromSlash("/" + strings.Join(oldParts[:len(oldParts)-suffix], "/"))
	newRoot := filepath.FromSlash("/" + strings.Join(newParts[:len(newParts)-suffix], "/"))
	if oldRoot == string(filepath.Separator) || newRoot == string(filepath.Separator) ||
		oldRoot == newRoot {
		return linkDirectoryMove{}, false
	}
	return linkDirectoryMove{oldRoot: oldRoot, newRoot: newRoot}, true
}

func confirmedDirectoryMove(move linkDirectoryMove) bool {
	if _, err := os.Lstat(move.oldRoot); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	info, err := os.Stat(move.newRoot)
	return err == nil && info.IsDir()
}

func (v *Volume) rebaseLinkSources(oldRoot, newRoot string) (int, error) {
	oldRoot = filepath.Clean(oldRoot)
	newRoot = filepath.Clean(newRoot)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	changed := 0
	err := v.updateMetadataLocked(func(metadata *Metadata) error {
		for key, source := range metadata.Links {
			relative, err := filepath.Rel(oldRoot, filepath.Clean(source))
			if err != nil || relative == "." || relative == ".." ||
				strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				continue
			}
			metadata.Links[key] = filepath.Join(newRoot, relative)
			changed++
		}
		return nil
	})
	return changed, err
}

func linkReferenceCount(records []linkRecord) int {
	count := 0
	for _, record := range records {
		if record.protected && record.sourcePath != "" {
			count++
		}
	}
	return count
}

type movedProtectedLinkSearch struct {
	roots         []string
	internalRoots []string
	indexedRoots  []string
	targets       map[string]struct{}
	objectTargets map[string]string
	byTarget      map[string]map[string]struct{}
	nextRoot      int
	comprehensive bool
	indexed       bool
}

func newMovedProtectedLinkSearch(
	vault string,
	mountPoint string,
	records []linkRecord,
) *movedProtectedLinkSearch {
	return newMovedProtectedLinkSearchWithGlobalRoots(
		vault,
		mountPoint,
		records,
		false,
	)
}

func newMovedProtectedLinkSearchWithGlobalRoots(
	vault string,
	mountPoint string,
	records []linkRecord,
	global bool,
) *movedProtectedLinkSearch {
	roots := make(map[string]struct{})
	for _, record := range records {
		if !record.protected || record.sourcePath == "" {
			continue
		}
		sourcePath := record.sourcePath
		root := protectedLinkSearchRoot(sourcePath)
		roots[filepath.Clean(root)] = struct{}{}
	}
	orderedRoots := compactSearchRoots(roots)
	if global {
		home, _ := os.UserHomeDir()
		for _, broadRoot := range []string{
			home,
			os.TempDir(),
			canonicalTemporaryRoot(),
		} {
			broadRoot = filepath.Clean(broadRoot)
			if broadRoot == "." {
				continue
			}
			if _, alreadyPreferred := roots[broadRoot]; alreadyPreferred {
				continue
			}
			orderedRoots = append(orderedRoots, broadRoot)
		}
	}
	targets := make(map[string]struct{})
	objectTargets := make(map[string]string)
	for _, record := range records {
		if !record.protected {
			continue
		}
		if target, err := mountedPathForStorage(mountPoint, record.relative); err == nil {
			targets[filepath.Clean(target)] = struct{}{}
			if objectID, objectErr := objectIDFromStoragePath(record.relative); objectErr == nil {
				objectTargets[objectID] = filepath.Clean(target)
			}
		}
		if record.legacyTarget != "" {
			targets[filepath.Clean(record.legacyTarget)] = struct{}{}
		}
	}
	return &movedProtectedLinkSearch{
		roots:         orderedRoots,
		internalRoots: []string{filepath.Clean(vault), filepath.Clean(mountPoint)},
		targets:       targets,
		objectTargets: objectTargets,
		byTarget:      make(map[string]map[string]struct{}),
		comprehensive: global,
	}
}

func protectedLinkSearchRoot(sourcePath string) string {
	parent := filepath.Clean(filepath.Dir(sourcePath))
	home, _ := os.UserHomeDir()
	for current := parent; current != filepath.Dir(current); current = filepath.Dir(current) {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return nearestExistingSearchRoot(current)
		}
		if home != "" && filepath.Clean(current) == filepath.Clean(home) {
			break
		}
	}
	if home == "" || !PathWithin(home, sourcePath) {
		return nearestExistingSearchRoot(parent)
	}
	relative, err := filepath.Rel(home, parent)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		return nearestExistingSearchRoot(parent)
	}
	first := strings.Split(filepath.ToSlash(relative), "/")[0]
	if first == "" || first == "." {
		return nearestExistingSearchRoot(parent)
	}
	if first == "Library" {
		components := strings.Split(filepath.ToSlash(relative), "/")
		depth := min(2, len(components))
		if len(components) >= 3 && components[1] == "Application Support" {
			depth = 3
		}
		return nearestExistingSearchRoot(
			filepath.Join(append([]string{home}, components[:depth]...)...),
		)
	}
	return nearestExistingSearchRoot(filepath.Join(home, first))
}

func nearestExistingSearchRoot(root string) string {
	if existing := nearestExistingDirectory(root); existing != "" {
		return existing
	}
	return filepath.Clean(root)
}

func canonicalTemporaryRoot() string {
	root := filepath.Clean(os.TempDir())
	if runtime.GOOS != "darwin" {
		return root
	}
	// macOS uses a per-user directory for os.TempDir, while command-line tools
	// and applications commonly create durable temporary work below /tmp.
	// Resolve the system symlink so candidate paths and internal-root checks use
	// the same /private/tmp namespace returned by filepath.Abs.
	if resolved, err := filepath.EvalSymlinks("/tmp"); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean("/tmp")
}

func compactSearchRoots(roots map[string]struct{}) []string {
	ordered := make([]string, 0, len(roots))
	for root := range roots {
		ordered = append(ordered, root)
	}
	sort.Slice(ordered, func(left, right int) bool {
		if len(ordered[left]) == len(ordered[right]) {
			return ordered[left] < ordered[right]
		}
		return len(ordered[left]) > len(ordered[right])
	})
	return ordered
}

func (search *movedProtectedLinkSearch) find(
	sourcePath string,
	targetPath string,
) (string, error) {
	cleanTarget := filepath.Clean(targetPath)
	for {
		candidates := search.byTarget[cleanTarget]
		var match string
		for candidate := range candidates {
			if filepath.Clean(candidate) == filepath.Clean(sourcePath) {
				continue
			}
			if match != "" {
				return "", errors.New(
					"multiple symbolic links reference the missing passfs pathname; encrypted data was preserved",
				)
			}
			match = candidate
		}
		if match != "" || search.indexed {
			return match, nil
		}
		if err := search.indexNextRoot(); err != nil {
			return "", err
		}
	}
}

func (search *movedProtectedLinkSearch) indexNextRoot() error {
	if search.indexed {
		return nil
	}
	if search.nextRoot >= len(search.roots) {
		search.indexed = true
		return nil
	}
	root := search.roots[search.nextRoot]
	search.nextRoot++
	if err := search.indexRoot(root); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("search for an offline protected-link move: %w", err)
	}
	search.indexedRoots = append(search.indexedRoots, filepath.Clean(root))
	if search.nextRoot >= len(search.roots) {
		search.indexed = true
	}
	return nil
}

type movedProtectedLinkScanResult struct {
	directories []string
	links       map[string][]string
	incomplete  bool
}

func (search *movedProtectedLinkSearch) indexRoot(root string) error {
	if _, err := os.Stat(root); err != nil {
		return err
	}
	// Directory metadata traversal becomes I/O-bound well before one worker per
	// logical CPU. A modest cap avoids an avoidable SSD and energy spike when a
	// missing protected link triggers the exceptional offline-move search.
	workerCount := min(8, max(2, runtime.GOMAXPROCS(0)))
	if os.Getenv("PASSFS_LOW_POWER_MODE") == "1" {
		workerCount = 2
	}
	jobs := make(chan string)
	results := make(chan movedProtectedLinkScanResult, workerCount)
	for range workerCount {
		go func() {
			for directory := range jobs {
				results <- search.scanDirectory(directory)
			}
		}()
	}

	queue := []string{root}
	active := 0
	for len(queue) > 0 || active > 0 {
		if len(queue) > 0 && active < workerCount {
			directory := queue[0]
			queue = queue[1:]
			jobs <- directory
			active++
			continue
		}
		result := <-results
		active--
		if result.incomplete {
			// A skipped or unreadable directory could contain the moved link.
			// The index remains useful for finding moves, but it must never be
			// used as proof that a missing link was deleted.
			search.comprehensive = false
		}
		queue = append(queue, result.directories...)
		for target, paths := range result.links {
			if search.byTarget[target] == nil {
				search.byTarget[target] = make(map[string]struct{})
			}
			for _, path := range paths {
				search.byTarget[target][path] = struct{}{}
			}
		}
	}
	close(jobs)
	return nil
}

func (search *movedProtectedLinkSearch) scanDirectory(
	directory string,
) movedProtectedLinkScanResult {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return movedProtectedLinkScanResult{incomplete: true}
	}
	result := movedProtectedLinkScanResult{
		directories: make([]string, 0, len(entries)/4),
		links:       make(map[string][]string),
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		if entry.IsDir() {
			skip, incomplete := search.shouldSkipDirectory(path, entry.Name())
			if incomplete {
				result.incomplete = true
			}
			if !skip {
				result.directories = append(result.directories, path)
			}
			continue
		}
		if entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		link, err := inspectProtectedLink(path)
		if err != nil || !link.isSymlink {
			continue
		}
		target := filepath.Clean(link.target)
		indexTarget := target
		if _, tracked := search.targets[target]; !tracked {
			objectID, objectErr := objectIDFromOpaqueTarget(target)
			if objectErr != nil || search.objectTargets[objectID] == "" {
				continue
			}
			indexTarget = search.objectTargets[objectID]
		}
		result.links[indexTarget] = append(result.links[indexTarget], filepath.Clean(path))
	}
	return result
}

func (search *movedProtectedLinkSearch) shouldSkipDirectory(
	path string,
	name string,
) (skip bool, incomplete bool) {
	for _, internalRoot := range search.internalRoots {
		if PathWithin(internalRoot, path) {
			return true, false
		}
	}
	for _, indexedRoot := range search.indexedRoots {
		if filepath.Clean(path) == indexedRoot || PathWithin(indexedRoot, path) {
			return true, false
		}
	}
	home, _ := os.UserHomeDir()
	if filepath.Clean(filepath.Dir(path)) == filepath.Clean(home) {
		if _, excluded := broadHomeSearchExcludedDirectories[strings.ToLower(name)]; excluded {
			return true, true
		}
	}
	lowerName := strings.ToLower(name)
	if _, excluded := movedLinkSearchExcludedDirectories[lowerName]; excluded {
		return true, true
	}
	for _, suffix := range []string{
		".app", ".dsym", ".framework", ".xcarchive",
	} {
		if strings.HasSuffix(lowerName, suffix) {
			return true, true
		}
	}
	return false, false
}

var broadHomeSearchExcludedDirectories = map[string]struct{}{
	"applications": {},
	"library":      {},
	"movies":       {},
	"music":        {},
	"pictures":     {},
	"public":       {},
}

// Offline moves are user actions. Dependency stores, generated output and
// caches can contain millions of directories, but are not meaningful
// destinations for a protected secret. Pruning them keeps the one-time safety
// scan bounded without excluding source/configuration trees.
var movedLinkSearchExcludedDirectories = map[string]struct{}{
	".bzr":              {},
	".bundle":           {},
	".cache":            {},
	".dart_tool":        {},
	".git":              {},
	".gradle":           {},
	".hg":               {},
	".idea":             {},
	".ivy2":             {},
	".m2":               {},
	".next":             {},
	".nuget":            {},
	".npm":              {},
	".parcel-cache":     {},
	".pnpm-store":       {},
	".svn":              {},
	".svelte-kit":       {},
	".terraform":        {},
	".terragrunt-cache": {},
	".trash":            {},
	".turbo":            {},
	".venv":             {},
	".yarn":             {},
	"__pycache__":       {},
	"_build":            {},
	"bower_components":  {},
	"build":             {},
	"caches":            {},
	"carthage":          {},
	"cmakefiles":        {},
	"coverage":          {},
	"deriveddata":       {},
	"dist":              {},
	"generated":         {},
	"jspm_packages":     {},
	"node_modules":      {},
	"obj":               {},
	"pods":              {},
	"site-packages":     {},
	"target":            {},
	"third-party":       {},
	"third_party":       {},
	"vendor":            {},
	"vendors":           {},
	"venv":              {},
	"virtualenv":        {},
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
	if errors.Is(err, os.ErrNotExist) {
		// The entry was removed or renamed after Lstat. Reporting it as
		// absent lets reconciliation use its tracked kernel reference or
		// remove the corresponding ciphertext immediately.
		return protectedLink{}, nil
	}
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
