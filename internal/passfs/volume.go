package passfs

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"
	"passfs/internal/fsapi"
)

const (
	encryptedSuffix = ".age"
	temporaryPrefix = ".passfs-tmp-"
)

var ErrFileTooLarge = errors.New("plaintext file exceeds the configured maximum size")

type FileMeta struct {
	Size  uint64 `json:"size"`
	Mode  uint32 `json:"mode"`
	MTime int64  `json:"mtime"`
	ATime int64  `json:"atime,omitempty"`
	Inode uint64 `json:"inode,omitempty"`
}

type Metadata struct {
	Version int                 `json:"version"`
	Files   map[string]FileMeta `json:"files"`
	// Links maps an immutable object storage key to its current project-side
	// pathname. The symlink target is derived from the object ID and mount
	// point, so moving a link never moves ciphertext.
	Links         map[string]string `json:"links,omitempty"`
	Orphaned      map[string]int64  `json:"orphaned,omitempty"`
	LegacyTargets map[string]string `json:"legacyTargets,omitempty"`
	// DisplacedLinks is decoded only while migrating v1 metadata. New vaults
	// never write it.
	DisplacedLinks map[string]string `json:"displacedLinks,omitempty"`
}

type pathLockEntry struct {
	mutex sync.RWMutex
	users int
}

type authorizationSession struct {
	identity *age.X25519Identity
	ownerPID uint32
	done     chan struct{}
}

type Volume struct {
	root        string
	config      PublicConfig
	recipient   age.Recipient
	prompter    Prompter
	maxFileSize int64
	unlockFor   time.Duration
	uid         uint32
	gid         uint32

	unlockMu        sync.Mutex
	cachedIdentity  *age.X25519Identity
	authorized      map[string]time.Time
	editSessions    map[string]map[string]authorizationSession
	encryptSessions map[string]authorizationSession
	unlockTimer     *time.Timer

	metadataMu       sync.RWMutex
	metadata         Metadata
	pendingAccess    map[string]int64
	accessFlushTimer *time.Timer

	locksMu sync.Mutex
	locks   map[string]*pathLockEntry

	openHandlesMu sync.Mutex
	openHandles   map[string]map[*OpenFile]uint32

	linkSynchronizerMu sync.RWMutex
	linkSynchronizer   *LinkSynchronizer

	// Writable handles hold a read lock. Namespace changes take the write lock
	// so an editor cannot rename or remove a backing file before it is flushed.
	// Read handles use an in-memory snapshot and release the lock after open.
	namespaceMu sync.RWMutex
}

// VolumeID is the stable identifier stored with the encrypted vault.
func (v *Volume) VolumeID() string {
	return v.config.VolumeID
}

func LoadVolume(
	cipherDir string,
	prompter Prompter,
	maxFileSize int64,
	unlockFor time.Duration,
) (*Volume, error) {
	if prompter == nil {
		return nil, errors.New("prompter is required")
	}
	if maxFileSize <= 0 {
		return nil, errors.New("maximum file size must be greater than zero")
	}
	if unlockFor < 0 {
		return nil, errors.New("unlock duration cannot be negative")
	}

	root, err := filepath.Abs(cipherDir)
	if err != nil {
		return nil, err
	}
	public, err := loadPublicConfig(root)
	if err != nil {
		return nil, err
	}
	cleanupStaleTemporaryFiles(root, time.Now())
	recipient, err := age.ParseX25519Recipient(public.Recipient)
	if err != nil {
		return nil, fmt.Errorf("parse volume recipient: %w", err)
	}
	metadata, err := loadMetadata(root)
	if err != nil {
		return nil, err
	}

	return &Volume{
		root:            root,
		config:          public,
		recipient:       recipient,
		prompter:        prompter,
		maxFileSize:     maxFileSize,
		unlockFor:       unlockFor,
		uid:             uint32(os.Getuid()),
		gid:             uint32(os.Getgid()),
		authorized:      make(map[string]time.Time),
		editSessions:    make(map[string]map[string]authorizationSession),
		encryptSessions: make(map[string]authorizationSession),
		metadata:        metadata,
		pendingAccess:   make(map[string]int64),
		locks:           make(map[string]*pathLockEntry),
		openHandles:     make(map[string]map[*OpenFile]uint32),
	}, nil
}

func (v *Volume) Configure(maxFileSize int64, unlockFor time.Duration) error {
	if maxFileSize <= 0 {
		return errors.New("maximum file size must be greater than zero")
	}
	if unlockFor < 0 {
		return errors.New("unlock duration cannot be negative")
	}
	v.namespaceMu.Lock()
	defer v.namespaceMu.Unlock()
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	if v.unlockTimer != nil {
		v.unlockTimer.Stop()
		v.unlockTimer = nil
	}
	v.maxFileSize = maxFileSize
	v.unlockFor = unlockFor
	v.cachedIdentity = nil
	clear(v.authorized)
	return nil
}

func loadMetadata(root string) (Metadata, error) {
	var metadata Metadata
	err := withMetadataFileLock(root, func() error {
		var err error
		metadata, err = readMetadata(root)
		if err != nil {
			return err
		}
		changed, err := reconcileMetadata(root, &metadata)
		if err != nil {
			return fmt.Errorf("reconcile metadata: %w", err)
		}
		if changed {
			if err := saveMetadata(root, metadata); err != nil {
				return fmt.Errorf("save reconciled metadata: %w", err)
			}
		}
		return nil
	})
	return metadata, err
}

func readMetadata(root string) (Metadata, error) {
	metadata := Metadata{
		Version:       metadataFormatVersion,
		Files:         make(map[string]FileMeta),
		Links:         make(map[string]string),
		Orphaned:      make(map[string]int64),
		LegacyTargets: make(map[string]string),
	}
	file, err := os.Open(filepath.Join(root, internalDirName, metadataFileName))
	if err != nil {
		return metadata, fmt.Errorf("open metadata: %w", err)
	}
	defer file.Close()

	if err := decodeBoundedJSON(file, 16*1024*1024, &metadata); err != nil {
		return metadata, fmt.Errorf("parse metadata: %w", err)
	}
	if metadata.Version == legacyMetadataFormatVersion {
		migrated, err := migrateLegacyMetadata(root, metadata)
		if err != nil {
			return metadata, fmt.Errorf("migrate metadata: %w", err)
		}
		return migrated, nil
	}
	if metadata.Version != metadataFormatVersion {
		return metadata, fmt.Errorf("unsupported metadata format version %d", metadata.Version)
	}
	if metadata.Files == nil {
		metadata.Files = make(map[string]FileMeta)
	}
	if metadata.Links == nil {
		metadata.Links = make(map[string]string)
	}
	if metadata.Orphaned == nil {
		metadata.Orphaned = make(map[string]int64)
	}
	if metadata.LegacyTargets == nil {
		metadata.LegacyTargets = make(map[string]string)
	}
	return metadata, nil
}

func cloneMetadata(metadata Metadata) Metadata {
	return Metadata{
		Version:        metadata.Version,
		Files:          maps.Clone(metadata.Files),
		Links:          maps.Clone(metadata.Links),
		Orphaned:       maps.Clone(metadata.Orphaned),
		LegacyTargets:  maps.Clone(metadata.LegacyTargets),
		DisplacedLinks: maps.Clone(metadata.DisplacedLinks),
	}
}

// cleanupStaleTemporaryFiles removes only transaction files created by
// persistFile and removeProtectedFile. A one-day grace period keeps this safe
// when another PassFS process is still finishing an operation in the vault.
// Protected files whose user-visible names begin with temporaryPrefix end in
// encryptedSuffix and are deliberately excluded.
func cleanupStaleTemporaryFiles(root string, now time.Time) {
	objectsRoot := filepath.Join(root, objectStorageDirectory)
	_ = filepath.WalkDir(objectsRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == objectsRoot {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if !strings.HasPrefix(name, temporaryPrefix) ||
			strings.HasSuffix(name, encryptedSuffix) ||
			entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() ||
			now.Sub(info.ModTime()) < 24*time.Hour {
			return nil
		}
		_ = os.Remove(path)
		return nil
	})
}

// refreshMetadata imports control-plane changes made by another process, such
// as a protected-link registration performed by the CLI for a sandboxed
// filesystem extension. Every local mutation is persisted before publication,
// so replacing the in-memory snapshot cannot discard unpublished state.
func (v *Volume) refreshMetadata() error {
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()

	var current Metadata
	if err := withMetadataFileLock(v.root, func() error {
		var err error
		current, err = readMetadata(v.root)
		return err
	}); err != nil {
		return err
	}
	for key, accessedAt := range v.pendingAccess {
		meta, exists := current.Files[key]
		if exists && accessedAt > meta.ATime {
			meta.ATime = accessedAt
			current.Files[key] = meta
		}
	}
	v.metadata = current
	return nil
}

// updateMetadataLocked persists a complete replacement before publishing it
// in memory. A failed disk write therefore cannot leak a partial mutation into
// a later, otherwise unrelated metadata update.
func (v *Volume) updateMetadataLocked(update func(*Metadata) error) error {
	pendingAccess := maps.Clone(v.pendingAccess)
	var next Metadata
	if err := withMetadataFileLock(v.root, func() error {
		current, err := readMetadata(v.root)
		if err != nil {
			return err
		}
		next = cloneMetadata(current)
		for key, accessedAt := range pendingAccess {
			meta, exists := next.Files[key]
			if exists && accessedAt > meta.ATime {
				meta.ATime = accessedAt
				next.Files[key] = meta
			}
		}
		if err := update(&next); err != nil {
			return err
		}
		return saveMetadata(v.root, next)
	}); err != nil {
		return err
	}
	v.metadata = next
	for key, flushedAt := range pendingAccess {
		if v.pendingAccess[key] <= flushedAt {
			delete(v.pendingAccess, key)
		}
	}
	if len(v.pendingAccess) == 0 && v.accessFlushTimer != nil {
		v.accessFlushTimer.Stop()
		v.accessFlushTimer = nil
	}
	return nil
}

// Access time is presentation metadata used for UI ordering, not security or
// durability state. Minute resolution is sufficient for that purpose and
// prevents an editor, indexer, or shell completion loop from turning repeated
// reads into a steady stream of metadata writes and SSD wake-ups.
const (
	accessTimeFlushDelay     = time.Minute
	accessTimeMinimumAdvance = time.Minute
)

func (v *Volume) recordFileAccess(relative string, accessedAt int64) {
	key := metadataKey(relative)
	v.metadataMu.Lock()
	meta, exists := v.metadata.Files[key]
	if !exists || accessedAt <= meta.ATime ||
		accessedAt-meta.ATime < int64(accessTimeMinimumAdvance) {
		v.metadataMu.Unlock()
		return
	}
	meta.ATime = accessedAt
	v.metadata.Files[key] = meta
	v.pendingAccess[key] = accessedAt
	if v.accessFlushTimer == nil {
		v.accessFlushTimer = time.AfterFunc(
			accessTimeFlushDelay,
			v.flushAccessTimesInBackground,
		)
	}
	v.metadataMu.Unlock()
}

func (v *Volume) flushAccessTimesInBackground() {
	v.metadataMu.Lock()
	v.accessFlushTimer = nil
	if len(v.pendingAccess) == 0 {
		v.metadataMu.Unlock()
		return
	}
	err := v.updateMetadataLocked(func(*Metadata) error { return nil })
	if err != nil && len(v.pendingAccess) != 0 {
		v.accessFlushTimer = time.AfterFunc(
			accessTimeFlushDelay,
			v.flushAccessTimesInBackground,
		)
	}
	v.metadataMu.Unlock()
}

// FlushAccessTimes persists coalesced access metadata during graceful adapter
// shutdown. A crash can lose only recent UI ordering information; ciphertext
// and structural metadata are always persisted synchronously.
func (v *Volume) FlushAccessTimes() error {
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	if v.accessFlushTimer != nil {
		v.accessFlushTimer.Stop()
		v.accessFlushTimer = nil
	}
	if len(v.pendingAccess) == 0 {
		return nil
	}
	return v.updateMetadataLocked(func(*Metadata) error { return nil })
}

func saveMetadata(root string, metadata Metadata) error {
	return WriteJSONFileAtomic(
		filepath.Join(root, internalDirName, metadataFileName),
		metadata,
		0o600,
	)
}

// reconcileLegacyMetadata repairs the two crash windows around a v1 backing
// file operation and its metadata update. Link records are deliberately kept
// when ciphertext disappears so the synchronizer can remove only the exact
// symbolic link previously created by passfs.
func reconcileLegacyMetadata(root string, metadata *Metadata) (bool, error) {
	actual := make(map[string]FileMeta)
	type physicalFileID struct {
		device uint64
		inode  uint64
	}
	physicalIDs := make(map[string]physicalFileID)
	filesRoot := filepath.Join(root, "files")
	filesInfo, err := os.Lstat(filesRoot)
	if err != nil {
		return false, err
	}
	if !filesInfo.IsDir() {
		return false, fmt.Errorf("%s is not a directory", filesRoot)
	}
	err = filepath.WalkDir(filesRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !entry.Type().IsRegular() ||
			!strings.HasSuffix(entry.Name(), encryptedSuffix) {
			return nil
		}
		relative, err := filepath.Rel(root, strings.TrimSuffix(path, encryptedSuffix))
		if err != nil {
			return err
		}
		if err := validateRelativePath(relative); err != nil {
			return err
		}
		if isReservedStorageMetadataPath(relative) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		key := metadataKey(relative)
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			physicalIDs[key] = physicalFileID{
				device: uint64(stat.Dev),
				inode:  uint64(stat.Ino),
			}
		}
		actual[key] = FileMeta{
			Mode:  0o600,
			MTime: info.ModTime().UnixNano(),
			ATime: info.ModTime().UnixNano(),
			Inode: stableInode(key),
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	changed := false
	linkedPhysicalFiles := make(map[physicalFileID]struct{})
	for key, target := range metadata.Links {
		if target != "" {
			if identity, exists := physicalIDs[key]; exists {
				linkedPhysicalFiles[identity] = struct{}{}
			}
		}
	}
	for key, identity := range physicalIDs {
		if metadata.Links[key] != "" {
			continue
		}
		if _, duplicateOfLinkedFile := linkedPhysicalFiles[identity]; !duplicateOfLinkedFile {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(key)+encryptedSuffix)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		delete(actual, key)
		delete(physicalIDs, key)
		delete(metadata.Files, key)
		delete(metadata.DisplacedLinks, key)
		changed = true
	}
	for key, meta := range metadata.Files {
		if _, exists := actual[key]; !exists {
			delete(metadata.Files, key)
			delete(metadata.DisplacedLinks, key)
			changed = true
			continue
		}
		if meta.Inode < 2 {
			meta.Inode = stableInode(key)
			metadata.Files[key] = meta
			changed = true
		}
	}
	for key, fallback := range actual {
		if _, exists := metadata.Files[key]; !exists {
			metadata.Files[key] = fallback
			changed = true
		}
	}
	for key, target := range metadata.DisplacedLinks {
		_, protected := metadata.Files[key]
		if !protected || filepath.Clean(metadata.Links[key]) != filepath.Clean(target) {
			delete(metadata.DisplacedLinks, key)
			changed = true
		}
	}
	return changed, nil
}

func (v *Volume) fileMeta(relative string, encryptedInfo os.FileInfo) FileMeta {
	key := metadataKey(relative)
	v.metadataMu.RLock()
	meta, ok := v.metadata.Files[key]
	v.metadataMu.RUnlock()
	if ok {
		return meta
	}

	// The CLI-side link synchronizer can rename protected files while a
	// sandboxed FSKit extension keeps its own Volume instance alive. Refresh
	// only on a cache miss so a newly moved path immediately exposes the
	// persisted plaintext size instead of briefly looking like an empty file.
	if err := v.refreshMetadata(); err == nil {
		v.metadataMu.RLock()
		meta, ok = v.metadata.Files[key]
		v.metadataMu.RUnlock()
		if ok {
			return meta
		}
	}

	modTime := time.Now()
	if encryptedInfo != nil {
		modTime = encryptedInfo.ModTime()
	}
	return FileMeta{
		Mode:  0o600,
		MTime: modTime.UnixNano(),
		ATime: modTime.UnixNano(),
		Inode: inodeFromFileInfo(encryptedInfo, stableInode(relative)),
	}
}

func (v *Volume) setFileMeta(relative string, meta FileMeta) error {
	key := metadataKey(relative)
	meta.Mode &= 0o777
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		_, existed := metadata.Files[key]
		if meta.Inode < 2 {
			if current := metadata.Files[key]; current.Inode >= 2 {
				meta.Inode = current.Inode
			} else {
				meta.Inode = newVirtualInode(relative)
			}
		}
		metadata.Files[key] = meta
		if !existed && metadata.Links[key] == "" {
			metadata.Orphaned[key] = time.Now().UnixNano()
		}
		return nil
	})
}

func newVirtualInode(relative string) uint64 {
	var encoded [8]byte
	if _, err := cryptorand.Read(encoded[:]); err == nil {
		inode := binary.LittleEndian.Uint64(encoded[:]) | 1<<63
		if inode >= 2 {
			return inode
		}
	}
	return stableInode(fmt.Sprintf("%s:%d", relative, time.Now().UnixNano()))
}

func inodeFromFileInfo(info os.FileInfo, fallback uint64) uint64 {
	if info != nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Ino >= 2 {
			return uint64(stat.Ino)
		}
	}
	if fallback < 2 {
		return fallback + 2
	}
	return fallback
}

func inodeFromFileMeta(meta FileMeta, relative string) uint64 {
	if meta.Inode >= 2 {
		return meta.Inode
	}
	return stableInode(relative)
}

func (v *Volume) removeFileMeta(relative string) error {
	key := metadataKey(relative)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		deleteFileMetadata(metadata, key)
		return nil
	})
}

func deleteFileMetadata(metadata *Metadata, key string) {
	delete(metadata.Files, key)
	delete(metadata.Links, key)
	delete(metadata.Orphaned, key)
	delete(metadata.LegacyTargets, key)
	delete(metadata.DisplacedLinks, key)
}

type linkRecord struct {
	relative     string
	sourcePath   string
	protected    bool
	orphanedAt   int64
	legacyTarget string
}

// linkRecords returns a stable snapshot of protected files and persisted
// project-side links. Link records remain present briefly after a protected
// file is removed so the synchronizer can remove its dangling symbolic link.
func (v *Volume) linkRecords() []linkRecord {
	v.metadataMu.RLock()
	recordsByKey := make(map[string]linkRecord, len(v.metadata.Files)+len(v.metadata.Links))
	for key := range v.metadata.Files {
		record := recordsByKey[key]
		record.relative = filepath.FromSlash(key)
		record.protected = true
		record.sourcePath = v.metadata.Links[key]
		record.orphanedAt = v.metadata.Orphaned[key]
		record.legacyTarget = v.metadata.LegacyTargets[key]
		recordsByKey[key] = record
	}
	for key, source := range v.metadata.Links {
		if source == "" {
			continue
		}
		record := recordsByKey[key]
		record.relative = filepath.FromSlash(key)
		record.sourcePath = source
		recordsByKey[key] = record
	}
	v.metadataMu.RUnlock()

	keys := make([]string, 0, len(recordsByKey))
	for key := range recordsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	records := make([]linkRecord, 0, len(keys))
	for _, key := range keys {
		records = append(records, recordsByKey[key])
	}
	return records
}

func (v *Volume) setLinkSource(relative, source string) error {
	key := metadataKey(relative)
	resolved, err := ResolvePathEntry(source)
	if err != nil {
		return err
	}
	source = filepath.Clean(resolved)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		if _, protected := metadata.Files[key]; !protected {
			return os.ErrNotExist
		}
		metadata.Links[key] = source
		delete(metadata.Orphaned, key)
		delete(metadata.LegacyTargets, key)
		return nil
	})
}

func (v *Volume) markLinkOrphan(relative string, when time.Time) error {
	key := metadataKey(relative)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	if v.metadata.Orphaned[key] != 0 {
		return nil
	}
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		if _, protected := metadata.Files[key]; !protected {
			return os.ErrNotExist
		}
		if metadata.Orphaned[key] == 0 {
			metadata.Orphaned[key] = when.UnixNano()
		}
		return nil
	})
}

func (v *Volume) clearLinkOrphan(relative string) error {
	key := metadataKey(relative)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	if v.metadata.Orphaned[key] == 0 && v.metadata.LegacyTargets[key] == "" {
		return nil
	}
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		delete(metadata.Orphaned, key)
		delete(metadata.LegacyTargets, key)
		return nil
	})
}

func metadataKey(relative string) string {
	if relative == "" || relative == "." {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(relative))
}

func validateRelativePath(relative string) error {
	if relative == "" || relative == "." {
		return nil
	}
	if strings.ContainsRune(relative, 0) {
		return errors.New("virtual path contains a NUL byte")
	}
	if filepath.IsAbs(relative) {
		return errors.New("absolute virtual path is not allowed")
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return errors.New("virtual path escapes the volume")
	}
	first := strings.Split(filepath.ToSlash(clean), "/")[0]
	if first == internalDirName {
		return errors.New("reserved virtual path")
	}
	return nil
}

func validateName(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, 0) ||
		strings.ContainsRune(name, os.PathSeparator) {
		return errors.New("invalid virtual name")
	}
	return nil
}

func (v *Volume) directoryPath(relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	return filepath.Join(v.root, filepath.Clean(relative)), nil
}

func (v *Volume) encryptedPath(relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil || relative == "" || relative == "." {
		if err != nil {
			return "", err
		}
		return "", errors.New("root is not a file")
	}
	return filepath.Join(v.root, filepath.Clean(relative)+encryptedSuffix), nil
}

func (v *Volume) virtualType(relative string) (isDirectory bool, info os.FileInfo, err error) {
	directoryPath, err := v.directoryPath(relative)
	if err != nil {
		return false, nil, err
	}
	directoryInfo, directoryErr := os.Lstat(directoryPath)
	if directoryErr == nil {
		if directoryInfo.IsDir() {
			return true, directoryInfo, nil
		}
		if !directoryInfo.Mode().IsRegular() {
			return false, nil, syscall.EIO
		}
		// A regular path ending in .age can be the ciphertext backing the
		// sibling virtual file without the suffix. It must not hide an exact
		// virtual filename such as "config.age".
	} else if !errors.Is(directoryErr, os.ErrNotExist) {
		return false, nil, directoryErr
	}

	encryptedPath, err := v.encryptedPath(relative)
	if err != nil {
		return false, nil, err
	}
	fileInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		return false, nil, err
	}
	if !fileInfo.Mode().IsRegular() {
		return false, nil, syscall.EIO
	}
	return false, fileInfo, nil
}

func (v *Volume) acquirePathLock(relative string, writable bool) func() {
	key := metadataKey(relative)
	entry := v.registerPathLockUser(key)
	if writable {
		entry.mutex.Lock()
	} else {
		entry.mutex.RLock()
	}
	return func() {
		if writable {
			entry.mutex.Unlock()
		} else {
			entry.mutex.RUnlock()
		}
		v.unregisterPathLockUser(key, entry)
	}
}

func (v *Volume) tryPathLock(
	relative string,
	writable bool,
) (unlock func(), acquired bool) {
	key := metadataKey(relative)
	entry := v.registerPathLockUser(key)
	if writable {
		acquired = entry.mutex.TryLock()
	} else {
		acquired = entry.mutex.TryRLock()
	}
	if !acquired {
		v.unregisterPathLockUser(key, entry)
		return nil, false
	}
	return func() {
		if writable {
			entry.mutex.Unlock()
		} else {
			entry.mutex.RUnlock()
		}
		v.unregisterPathLockUser(key, entry)
	}, true
}

func (v *Volume) registerPathLockUser(key string) *pathLockEntry {
	v.locksMu.Lock()
	entry := v.locks[key]
	if entry == nil {
		entry = &pathLockEntry{}
		v.locks[key] = entry
	}
	entry.users++
	v.locksMu.Unlock()
	return entry
}

func (v *Volume) unregisterPathLockUser(key string, entry *pathLockEntry) {
	v.locksMu.Lock()
	entry.users--
	if entry.users == 0 && v.locks[key] == entry {
		delete(v.locks, key)
	}
	v.locksMu.Unlock()
}

func (v *Volume) acquireOpenLock(relative string, writable bool) func() {
	v.namespaceMu.RLock()
	unlockPath := v.acquirePathLock(relative, writable)
	return func() {
		unlockPath()
		v.namespaceMu.RUnlock()
	}
}

func (v *Volume) tryNamespaceLock() (func(), bool) {
	if !v.namespaceMu.TryLock() {
		return nil, false
	}
	return v.namespaceMu.Unlock, true
}

func (v *Volume) registerOpenHandle(handle *OpenFile, ownerPID uint32) {
	key := metadataKey(handle.relative)
	v.openHandlesMu.Lock()
	handles := v.openHandles[key]
	if handles == nil {
		handles = make(map[*OpenFile]uint32)
		v.openHandles[key] = handles
	}
	handles[handle] = ownerPID
	v.openHandlesMu.Unlock()
}

func (v *Volume) unregisterOpenHandle(handle *OpenFile) {
	key := metadataKey(handle.relative)
	v.openHandlesMu.Lock()
	handles := v.openHandles[key]
	delete(handles, handle)
	if len(handles) == 0 {
		delete(v.openHandles, key)
	}
	v.openHandlesMu.Unlock()
}

func (v *Volume) writableOpenHandle(
	relative string,
	ownerPID uint32,
) *OpenFile {
	key := metadataKey(relative)
	type candidate struct {
		handle *OpenFile
		pid    uint32
	}
	v.openHandlesMu.Lock()
	candidates := make([]candidate, 0, len(v.openHandles[key]))
	for handle, pid := range v.openHandles[key] {
		if handle.writable {
			candidates = append(candidates, candidate{handle: handle, pid: pid})
		}
	}
	v.openHandlesMu.Unlock()

	if ownerPID == 0 {
		if len(candidates) == 1 {
			return candidates[0].handle
		}
		return nil
	}
	for _, candidate := range candidates {
		pid := candidate.pid
		if pid == ownerPID ||
			processIsOrDescendsFrom(ownerPID, pid) ||
			processIsOrDescendsFrom(pid, ownerPID) {
			return candidate.handle
		}
	}
	return nil
}

func (v *Volume) unlockIdentity(
	ctx context.Context,
	relative string,
	operation string,
) (*age.X25519Identity, error) {
	cacheKey := metadataKey(relative)
	ownerPID := callerPID(ctx)
	displayPath := v.promptDisplayPath(relative)
	return v.unlockIdentityForRequest(ctx, cacheKey, PromptRequest{
		Path:      displayPath,
		Operation: operation,
		PID:       ownerPID,
	})
}

func (v *Volume) promptDisplayPath(relative string) string {
	key := metadataKey(relative)
	linkState := func() (string, bool) {
		v.metadataMu.RLock()
		defer v.metadataMu.RUnlock()
		_, protected := v.metadata.Files[key]
		return v.metadata.Links[key], protected
	}
	source, protected := linkState()
	if source != "" {
		return filepath.Clean(source)
	}

	// Sandboxed adapters and the CLI update the same metadata file from
	// different processes. Refresh an immutable object's link-index miss so an
	// adapter mounted before registration still names the user-visible alias.
	if _, err := objectIDFromStoragePath(relative); protected && err == nil {
		if err := v.refreshMetadata(); err == nil {
			if source, _ := linkState(); source != "" {
				return filepath.Clean(source)
			}
		}
	}

	displayPath := filepath.ToSlash(filepath.Clean(relative))
	displayPath = strings.TrimPrefix(displayPath, "files/")
	return "/" + strings.TrimPrefix(displayPath, "/")
}

func (v *Volume) unlockIdentityForRequest(
	ctx context.Context,
	cacheKey string,
	request PromptRequest,
) (*age.X25519Identity, error) {
	ownerPID := request.PID
	v.unlockMu.Lock()
	if identity := v.activeEncryptIdentityLocked(ownerPID); identity != nil {
		v.unlockMu.Unlock()
		return identity, nil
	}
	if identity := v.activeEditIdentityLocked(cacheKey, ownerPID); identity != nil {
		v.unlockMu.Unlock()
		return identity, nil
	}
	cacheLocked := v.unlockFor > 0
	if cacheLocked {
		defer v.unlockMu.Unlock()
		now := time.Now()
		v.removeExpiredAuthorizationsLocked(now)
		if v.cachedIdentity != nil {
			for _, until := range v.authorized {
				if now.Before(until) {
					return v.cachedIdentity, nil
				}
			}
		}
	} else {
		v.unlockMu.Unlock()
	}

	identity, err := v.requestIdentity(ctx, request)
	if err != nil {
		return nil, err
	}
	if cacheLocked {
		v.cachedIdentity = identity
		v.authorized[cacheKey] = time.Now().Add(v.unlockFor)
		v.scheduleIdentityExpiryLocked()
	}
	return identity, nil
}

func (v *Volume) requestIdentity(
	ctx context.Context,
	request PromptRequest,
) (*age.X25519Identity, error) {
	var identity *age.X25519Identity
	var err error
	if identityPrompter, ok := v.prompter.(IdentityPrompter); ok {
		identity, err = identityPrompter.PromptIdentity(ctx, request)
		if err != nil {
			return nil, err
		}
	} else {
		privateData, unlockErr := unlockPrivateConfig(
			ctx,
			v.root,
			v.config,
			v.prompter,
			request,
		)
		if unlockErr != nil {
			return nil, unlockErr
		}
		identity, err = parsePrivateIdentity(privateData)
		wipe(privateData)
		if err != nil {
			return nil, fmt.Errorf("parse volume identity: %w", err)
		}
	}
	if identity == nil {
		return nil, errors.New("prompter returned no volume identity")
	}
	if identity.Recipient().String() != v.config.Recipient {
		return nil, errors.New("unlocked identity does not match the volume recipient")
	}
	return identity, nil
}

func (v *Volume) beginEditSession(
	ctx context.Context,
	relative string,
	token string,
	ownerPID uint32,
) error {
	if err := validateSessionToken(token); err != nil {
		return err
	}
	if ownerPID == 0 {
		return errors.New("edit session caller is unavailable")
	}
	identity, err := v.unlockIdentity(ctx, relative, "edit")
	if err != nil {
		return err
	}

	cacheKey := metadataKey(relative)
	v.unlockMu.Lock()
	sessions := v.editSessions[cacheKey]
	if sessions == nil {
		sessions = make(map[string]authorizationSession)
		v.editSessions[cacheKey] = sessions
	}
	sessions[token] = authorizationSession{
		identity: identity,
		ownerPID: ownerPID,
		done:     make(chan struct{}),
	}
	done := sessions[token].done
	v.unlockMu.Unlock()

	go v.monitorEditSession(cacheKey, token, ownerPID, done)
	return nil
}

func (v *Volume) endEditSession(relative, token string, ownerPID uint32) error {
	if err := validateSessionToken(token); err != nil {
		return err
	}
	cacheKey := metadataKey(relative)
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	sessions := v.editSessions[cacheKey]
	session, exists := sessions[token]
	if !exists {
		return nil
	}
	if ownerPID == 0 || session.ownerPID != ownerPID {
		return syscall.EPERM
	}
	close(session.done)
	delete(sessions, token)
	if len(sessions) == 0 {
		delete(v.editSessions, cacheKey)
	}
	return nil
}

func (v *Volume) beginEncryptSession(
	ctx context.Context,
	token string,
	ownerPID uint32,
) error {
	if err := validateSessionToken(token); err != nil {
		return err
	}
	if ownerPID == 0 {
		return errors.New("encrypt session caller is unavailable")
	}
	identity, err := v.unlockIdentityForRequest(
		ctx,
		"",
		PromptRequest{
			Path:      "multiple files",
			Operation: "encrypt",
			PID:       ownerPID,
		},
	)
	if err != nil {
		return err
	}

	v.unlockMu.Lock()
	v.encryptSessions[token] = authorizationSession{
		identity: identity,
		ownerPID: ownerPID,
		done:     make(chan struct{}),
	}
	done := v.encryptSessions[token].done
	v.unlockMu.Unlock()

	go v.monitorEncryptSession(token, ownerPID, done)
	return nil
}

func (v *Volume) endEncryptSession(token string, ownerPID uint32) error {
	if err := validateSessionToken(token); err != nil {
		return err
	}
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	session, exists := v.encryptSessions[token]
	if !exists {
		return nil
	}
	if ownerPID == 0 || session.ownerPID != ownerPID {
		return syscall.EPERM
	}
	close(session.done)
	delete(v.encryptSessions, token)
	return nil
}

func (v *Volume) activeEncryptIdentityLocked(
	ownerPID uint32,
) *age.X25519Identity {
	if ownerPID == 0 {
		return nil
	}
	for token, session := range v.encryptSessions {
		if !processAlive(session.ownerPID) {
			close(session.done)
			delete(v.encryptSessions, token)
			continue
		}
		if session.ownerPID == ownerPID {
			return session.identity
		}
	}
	return nil
}

func (v *Volume) activeEditIdentityLocked(
	cacheKey string,
	callerPID uint32,
) *age.X25519Identity {
	sessions := v.editSessions[cacheKey]
	for token, session := range sessions {
		if !processAlive(session.ownerPID) {
			close(session.done)
			delete(sessions, token)
			continue
		}
		if callerPID == 0 ||
			processIsOrDescendsFrom(callerPID, session.ownerPID) {
			return session.identity
		}
	}
	if len(sessions) == 0 {
		delete(v.editSessions, cacheKey)
	}
	return nil
}

func (v *Volume) monitorEditSession(
	cacheKey, token string,
	ownerPID uint32,
	done <-chan struct{},
) {
	if !waitForProcessExit(ownerPID, done) {
		return
	}
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	sessions := v.editSessions[cacheKey]
	session, exists := sessions[token]
	if !exists || session.ownerPID != ownerPID {
		return
	}
	close(session.done)
	delete(sessions, token)
	if len(sessions) == 0 {
		delete(v.editSessions, cacheKey)
	}
}

func (v *Volume) monitorEncryptSession(
	token string,
	ownerPID uint32,
	done <-chan struct{},
) {
	if !waitForProcessExit(ownerPID, done) {
		return
	}
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	session, exists := v.encryptSessions[token]
	if !exists || session.ownerPID != ownerPID {
		return
	}
	close(session.done)
	delete(v.encryptSessions, token)
}

func waitForProcessExit(ownerPID uint32, done <-chan struct{}) bool {
	exited, cancel, err := watchProcessExit(ownerPID)
	if err == nil {
		defer cancel()
		select {
		case <-done:
			return false
		case <-exited:
			return true
		}
	}

	// Older Linux kernels may not support pidfds. Poll only in that fallback;
	// supported macOS and Linux systems otherwise sleep until an exit event.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return false
		case <-ticker.C:
			if !processAlive(ownerPID) {
				return true
			}
		}
	}
}

func callerPID(ctx context.Context) uint32 {
	if caller, ok := fsapi.CallerFromContext(ctx); ok {
		return platformProcessID(caller.PID)
	}
	return 0
}

func processAlive(pid uint32) bool {
	if pid == 0 {
		return false
	}
	err := syscall.Kill(int(pid), 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func (v *Volume) Lock() {
	v.unlockMu.Lock()
	if v.unlockTimer != nil {
		v.unlockTimer.Stop()
		v.unlockTimer = nil
	}
	v.cachedIdentity = nil
	clear(v.authorized)
	for _, sessions := range v.editSessions {
		for _, session := range sessions {
			close(session.done)
		}
	}
	for _, session := range v.encryptSessions {
		close(session.done)
	}
	clear(v.editSessions)
	clear(v.encryptSessions)
	v.unlockMu.Unlock()
}

func (v *Volume) removeExpiredAuthorizationsLocked(now time.Time) {
	for path, until := range v.authorized {
		if !now.Before(until) {
			delete(v.authorized, path)
		}
	}
	if len(v.authorized) == 0 {
		v.cachedIdentity = nil
	}
}

func (v *Volume) scheduleIdentityExpiryLocked() {
	if v.unlockTimer != nil {
		v.unlockTimer.Stop()
	}
	var latest time.Time
	for _, until := range v.authorized {
		if until.After(latest) {
			latest = until
		}
	}
	if latest.IsZero() {
		v.unlockTimer = nil
		v.cachedIdentity = nil
		return
	}
	delay := time.Until(latest)
	if delay < 0 {
		delay = 0
	}
	v.unlockTimer = time.AfterFunc(delay, v.expireCachedIdentity)
}

func (v *Volume) expireCachedIdentity() {
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	v.removeExpiredAuthorizationsLocked(time.Now())
	if len(v.authorized) == 0 {
		v.unlockTimer = nil
		return
	}
	v.scheduleIdentityExpiryLocked()
}

func (v *Volume) authorize(ctx context.Context, relative, operation string) error {
	identity, err := v.unlockIdentity(ctx, relative, operation)
	if err != nil {
		return err
	}
	// Keep the identity alive until authorization has completed, but never
	// retain it on the file handle.
	_ = identity
	return nil
}

func (v *Volume) decryptFile(ctx context.Context, relative, operation string) ([]byte, error) {
	identity, err := v.unlockIdentity(ctx, relative, operation)
	if err != nil {
		return nil, err
	}
	return v.decryptFileWithIdentity(relative, identity)
}

func (v *Volume) decryptFileWithIdentity(
	relative string,
	identity *age.X25519Identity,
) ([]byte, error) {
	path, err := v.encryptedPath(relative)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", relative, err)
	}
	data, err := io.ReadAll(io.LimitReader(reader, v.maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read decrypted %s: %w", relative, err)
	}
	if int64(len(data)) > v.maxFileSize {
		wipe(data)
		return nil, ErrFileTooLarge
	}
	return data, nil
}

func (v *Volume) persistFile(relative string, data []byte, meta FileMeta) error {
	if int64(len(data)) > v.maxFileSize {
		return ErrFileTooLarge
	}
	path, err := v.encryptedPath(relative)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if info, err := os.Stat(parent); err != nil {
		return err
	} else if !info.IsDir() {
		return syscall.ENOTDIR
	}

	file, err := os.CreateTemp(parent, temporaryPrefix+"*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}

	writer, err := age.Encrypt(file, v.recipient)
	if err != nil {
		file.Close()
		return err
	}
	if _, err := writer.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	meta.Size = uint64(len(data))
	if meta.MTime == 0 {
		meta.MTime = time.Now().UnixNano()
	}

	previousExists := false
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return syscall.EIO
		}
		previousExists = true
		if err := exchangePaths(tempPath, path); err != nil {
			return err
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		if err := renameNoReplace(tempPath, path); err != nil {
			return err
		}
	} else {
		return statErr
	}
	if err := syncDirectory(parent); err != nil {
		rollbackErr := rollbackPersistedFile(path, tempPath, previousExists)
		return errors.Join(err, rollbackErr)
	}

	if err := v.setFileMeta(relative, meta); err != nil {
		rollbackErr := rollbackPersistedFile(path, tempPath, previousExists)
		return errors.Join(err, rollbackErr)
	}
	if previousExists {
		if err := os.Remove(tempPath); err != nil {
			return fmt.Errorf("remove previous encrypted file: %w", err)
		}
	}
	return syncDirectory(parent)
}

func rollbackPersistedFile(path, temporaryPath string, previousExists bool) error {
	var err error
	if previousExists {
		err = exchangePaths(temporaryPath, path)
	} else {
		err = os.Remove(path)
	}
	if err != nil {
		return fmt.Errorf("rollback encrypted file: %w", err)
	}
	if syncErr := syncDirectory(filepath.Dir(path)); syncErr != nil {
		return fmt.Errorf("sync encrypted file rollback: %w", syncErr)
	}
	return nil
}

func (v *Volume) removeProtectedFile(relative string) error {
	unlock, ok := v.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()
	unlockPath, ok := v.tryPathLock(relative, true)
	if !ok {
		return syscall.EBUSY
	}
	defer unlockPath()
	return v.removeProtectedFileLocked(relative)
}

func (v *Volume) removeProtectedFileLocked(relative string) error {
	path, err := v.encryptedPath(relative)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return syscall.EIO
	}
	meta := v.fileMeta(relative, info)
	temporary, err := os.CreateTemp(parent, temporaryPrefix+"removed-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	if err := renameNoReplace(path, temporaryPath); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return errors.Join(err, restoreRemovedFile(temporaryPath, path))
	}
	if err := v.removeFileMeta(relative); err != nil {
		return errors.Join(err, restoreRemovedFile(temporaryPath, path))
	}
	if err := os.Remove(temporaryPath); err != nil {
		metadataErr := v.setFileMeta(relative, meta)
		restoreErr := restoreRemovedFile(temporaryPath, path)
		return errors.Join(err, metadataErr, restoreErr)
	}
	return syncDirectory(parent)
}

func restoreRemovedFile(temporaryPath, path string) error {
	if err := renameNoReplace(temporaryPath, path); err != nil {
		return fmt.Errorf("restore encrypted file after failed removal: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync restored encrypted file: %w", err)
	}
	return nil
}

func errnoFromError(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, ErrPromptCancelled):
		return syscall.ECANCELED
	case errors.Is(err, ErrAuthentication):
		return syscall.EACCES
	case errors.Is(err, ErrFileTooLarge):
		return syscall.EFBIG
	case errors.Is(err, os.ErrNotExist):
		return syscall.ENOENT
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}

	return syscall.EIO
}
