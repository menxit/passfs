package passfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
}

type Metadata struct {
	Version int                 `json:"version"`
	Files   map[string]FileMeta `json:"files"`
	Links   map[string]string   `json:"links,omitempty"`
}

type pathLockEntry struct {
	mutex sync.RWMutex
	users int
}

type authorizationSession struct {
	identity *age.X25519Identity
	ownerPID uint32
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

	metadataMu sync.RWMutex
	metadata   Metadata

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
		locks:           make(map[string]*pathLockEntry),
		openHandles:     make(map[string]map[*OpenFile]uint32),
	}, nil
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
		Version: formatVersion,
		Files:   make(map[string]FileMeta),
		Links:   make(map[string]string),
	}
	file, err := os.Open(filepath.Join(root, internalDirName, metadataFileName))
	if err != nil {
		return metadata, fmt.Errorf("open metadata: %w", err)
	}
	defer file.Close()

	if err := decodeBoundedJSON(file, 16*1024*1024, &metadata); err != nil {
		return metadata, fmt.Errorf("parse metadata: %w", err)
	}
	if metadata.Version != formatVersion {
		return metadata, fmt.Errorf("unsupported metadata format version %d", metadata.Version)
	}
	if metadata.Files == nil {
		metadata.Files = make(map[string]FileMeta)
	}
	if metadata.Links == nil {
		metadata.Links = make(map[string]string)
	}
	return metadata, nil
}

func cloneMetadata(metadata Metadata) Metadata {
	clone := Metadata{
		Version: metadata.Version,
		Files:   make(map[string]FileMeta, len(metadata.Files)),
		Links:   make(map[string]string, len(metadata.Links)),
	}
	for key, value := range metadata.Files {
		clone.Files[key] = value
	}
	for key, value := range metadata.Links {
		clone.Links[key] = value
	}
	return clone
}

// updateMetadataLocked persists a complete replacement before publishing it
// in memory. A failed disk write therefore cannot leak a partial mutation into
// a later, otherwise unrelated metadata update.
func (v *Volume) updateMetadataLocked(update func(*Metadata) error) error {
	var next Metadata
	if err := withMetadataFileLock(v.root, func() error {
		current, err := readMetadata(v.root)
		if err != nil {
			return err
		}
		next = cloneMetadata(current)
		if err := update(&next); err != nil {
			return err
		}
		return saveMetadata(v.root, next)
	}); err != nil {
		return err
	}
	v.metadata = next
	return nil
}

func saveMetadata(root string, metadata Metadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return WriteFileAtomic(filepath.Join(root, internalDirName, metadataFileName), data, 0o600)
}

// reconcileMetadata repairs the two crash windows around an atomic backing
// file operation and its metadata update. Link records are deliberately kept
// when ciphertext disappears so the synchronizer can remove only the exact
// symbolic link previously created by passfs.
func reconcileMetadata(root string, metadata *Metadata) (bool, error) {
	actual := make(map[string]FileMeta)
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
		actual[key] = FileMeta{
			Mode:  0o600,
			MTime: info.ModTime().UnixNano(),
			ATime: info.ModTime().UnixNano(),
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	changed := false
	for key := range metadata.Files {
		if _, exists := actual[key]; !exists {
			delete(metadata.Files, key)
			changed = true
		}
	}
	for key, fallback := range actual {
		if _, exists := metadata.Files[key]; !exists {
			metadata.Files[key] = fallback
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

	modTime := time.Now()
	if encryptedInfo != nil {
		modTime = encryptedInfo.ModTime()
	}
	return FileMeta{
		Mode:  0o600,
		MTime: modTime.UnixNano(),
		ATime: modTime.UnixNano(),
	}
}

func (v *Volume) setFileMeta(relative string, meta FileMeta) error {
	key := metadataKey(relative)
	meta.Mode &= 0o777
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		metadata.Files[key] = meta
		return nil
	})
}

func (v *Volume) removeFileMeta(relative string) error {
	key := metadataKey(relative)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		delete(metadata.Files, key)
		return nil
	})
}

type linkRecord struct {
	relative   string
	protected  bool
	linkTarget string
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
		record.linkTarget = v.metadata.Links[key]
		recordsByKey[key] = record
	}
	for key, target := range v.metadata.Links {
		if target == "" {
			continue
		}
		record := recordsByKey[key]
		record.relative = filepath.FromSlash(key)
		record.linkTarget = target
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

func (v *Volume) setLinkTarget(relative, target string) error {
	key := metadataKey(relative)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		if target != "" {
			if _, protected := metadata.Files[key]; !protected {
				return os.ErrNotExist
			}
			metadata.Links[key] = filepath.Clean(target)
		} else {
			delete(metadata.Links, key)
		}
		return nil
	})
}

func (v *Volume) renameMetadata(oldRelative, newRelative string, directory bool) error {
	return v.renameMetadataEntries(oldRelative, newRelative, directory, false)
}

func (v *Volume) renameProtectedMetadata(oldRelative, newRelative string) error {
	return v.renameMetadataEntries(oldRelative, newRelative, false, true)
}

// renameMetadataEntries moves link ownership only when the project-side link
// itself moved. A rename through the mounted namespace moves ciphertext but
// leaves project-side paths in place so the synchronizer can remove the old
// dangling link and retain any link already registered at the destination.
func (v *Volume) renameMetadataEntries(
	oldRelative string,
	newRelative string,
	directory bool,
	moveLinks bool,
) error {
	oldKey := metadataKey(oldRelative)
	newKey := metadataKey(newRelative)

	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	return v.updateMetadataLocked(func(metadata *Metadata) error {
		if !directory {
			if meta, ok := metadata.Files[oldKey]; ok {
				delete(metadata.Files, oldKey)
				metadata.Files[newKey] = meta
			}
			if moveLinks {
				linkTarget, ok := metadata.Links[oldKey]
				if !ok {
					return nil
				}
				delete(metadata.Links, oldKey)
				metadata.Links[newKey] = linkTarget
			}
			return nil
		}

		renameMetadataPrefix(metadata.Files, oldKey, newKey)
		if moveLinks {
			renameMetadataPrefix(metadata.Links, oldKey, newKey)
		}
		return nil
	})
}

func renameMetadataPrefix[T any](entries map[string]T, oldKey, newKey string) {
	prefix := oldKey + "/"
	keys := make([]string, 0)
	for key := range entries {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := entries[key]
		delete(entries, key)
		suffix := strings.TrimPrefix(key, prefix)
		targetKey := newKey + "/" + suffix
		entries[targetKey] = value
	}
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
		if until, ok := v.authorized[cacheKey]; ok &&
			v.cachedIdentity != nil &&
			now.Before(until) {
			return v.cachedIdentity, nil
		}
	} else {
		v.unlockMu.Unlock()
	}

	displayPath := filepath.ToSlash(filepath.Clean(relative))
	displayPath = strings.TrimPrefix(displayPath, "files/")
	displayPath = "/" + strings.TrimPrefix(displayPath, "/")
	request := PromptRequest{
		Path:      displayPath,
		Operation: operation,
		PID:       ownerPID,
	}
	identity, err := v.requestIdentity(ctx, request)
	if err != nil {
		return nil, err
	}
	if v.unlockFor > 0 {
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
	sessions[token] = authorizationSession{identity: identity, ownerPID: ownerPID}
	v.unlockMu.Unlock()

	go v.monitorEditSession(cacheKey, token, ownerPID)
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
	identity, err := v.requestIdentity(ctx, PromptRequest{
		Path:      "multiple files",
		Operation: "encrypt",
		PID:       ownerPID,
	})
	if err != nil {
		return err
	}

	v.unlockMu.Lock()
	v.encryptSessions[token] = authorizationSession{
		identity: identity,
		ownerPID: ownerPID,
	}
	v.unlockMu.Unlock()

	go v.monitorEncryptSession(token, ownerPID)
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

func (v *Volume) monitorEditSession(cacheKey, token string, ownerPID uint32) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		v.unlockMu.Lock()
		sessions := v.editSessions[cacheKey]
		session, exists := sessions[token]
		if !exists || session.ownerPID != ownerPID {
			v.unlockMu.Unlock()
			return
		}
		if !processAlive(ownerPID) {
			delete(sessions, token)
			if len(sessions) == 0 {
				delete(v.editSessions, cacheKey)
			}
			v.unlockMu.Unlock()
			return
		}
		v.unlockMu.Unlock()
	}
}

func (v *Volume) monitorEncryptSession(token string, ownerPID uint32) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		v.unlockMu.Lock()
		session, exists := v.encryptSessions[token]
		if !exists || session.ownerPID != ownerPID {
			v.unlockMu.Unlock()
			return
		}
		if !processAlive(ownerPID) {
			delete(v.encryptSessions, token)
			v.unlockMu.Unlock()
			return
		}
		v.unlockMu.Unlock()
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

func (v *Volume) renameProtectedFile(oldRelative, newRelative string) error {
	if err := validateRelativePath(oldRelative); err != nil {
		return err
	}
	if err := validateRelativePath(newRelative); err != nil {
		return err
	}
	unlock, ok := v.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()
	unlockPaths, ok := v.tryPathLocks(oldRelative, newRelative)
	if !ok {
		return syscall.EBUSY
	}
	defer unlockPaths()

	oldPath, err := v.encryptedPath(oldRelative)
	if err != nil {
		return err
	}
	newPath, err := v.encryptedPath(newRelative)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newPath), 0o700); err != nil {
		return err
	}
	if err := renameNoReplace(oldPath, newPath); err != nil {
		return err
	}
	if err := v.renameProtectedMetadata(oldRelative, newRelative); err != nil {
		rollbackErr := renameNoReplace(newPath, oldPath)
		return errors.Join(err, rollbackErr)
	}
	oldParent := filepath.Dir(oldPath)
	newParent := filepath.Dir(newPath)
	var newSyncErr error
	if newParent != oldParent {
		newSyncErr = syncDirectory(newParent)
	}
	return errors.Join(
		syncDirectory(oldParent),
		newSyncErr,
		pruneEmptyDirectories(oldParent, filepath.Join(v.root, "files")),
	)
}

func (v *Volume) cycleProtectedFiles(
	cycle []string,
) (committed bool, resultErr error) {
	if len(cycle) < 2 {
		return false, errors.New("protected file cycle requires at least two paths")
	}
	unlockNamespace, ok := v.tryNamespaceLock()
	if !ok {
		return false, syscall.EBUSY
	}
	defer unlockNamespace()
	unlockPaths, ok := v.tryPathLocks(cycle...)
	if !ok {
		return false, syscall.EBUSY
	}
	defer unlockPaths()

	paths := make([]string, len(cycle))
	for index, relative := range cycle {
		if err := validateRelativePath(relative); err != nil {
			return false, err
		}
		path, err := v.encryptedPath(relative)
		if err != nil {
			return false, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, syscall.EIO
		}
		paths[index] = path
	}

	exchanged := 0
	for index := 1; index < len(paths); index++ {
		if err := exchangePaths(paths[0], paths[index]); err != nil {
			rollbackErr := rollbackProtectedFileCycle(paths, exchanged)
			return false, errors.Join(err, rollbackErr)
		}
		exchanged = index
	}

	v.metadataMu.Lock()
	metadataErr := v.updateMetadataLocked(func(metadata *Metadata) error {
		return permuteProtectedMetadata(metadata, cycle)
	})
	v.metadataMu.Unlock()
	if metadataErr != nil {
		rollbackErr := rollbackProtectedFileCycle(paths, exchanged)
		return false, errors.Join(metadataErr, rollbackErr)
	}
	committed = true

	directories := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		directories[filepath.Dir(path)] = struct{}{}
	}
	for directory := range directories {
		resultErr = errors.Join(resultErr, syncDirectory(directory))
	}
	return committed, resultErr
}

func rollbackProtectedFileCycle(paths []string, exchanged int) error {
	var resultErr error
	for index := exchanged; index >= 1; index-- {
		resultErr = errors.Join(
			resultErr,
			exchangePaths(paths[0], paths[index]),
		)
	}
	return resultErr
}

func permuteProtectedMetadata(metadata *Metadata, cycle []string) error {
	files := make(map[string]FileMeta, len(cycle))
	links := make(map[string]string, len(cycle))
	for _, relative := range cycle {
		key := metadataKey(relative)
		meta, exists := metadata.Files[key]
		if !exists {
			return os.ErrNotExist
		}
		files[key] = meta
		if target, exists := metadata.Links[key]; exists {
			links[key] = target
		}
		delete(metadata.Files, key)
		delete(metadata.Links, key)
	}
	for index, relative := range cycle {
		oldKey := metadataKey(relative)
		newKey := metadataKey(cycle[(index+1)%len(cycle)])
		metadata.Files[newKey] = files[oldKey]
		if target, exists := links[oldKey]; exists {
			metadata.Links[newKey] = target
		}
	}
	return nil
}

func (v *Volume) tryPathLocks(relatives ...string) (func(), bool) {
	byKey := make(map[string]string, len(relatives))
	keys := make([]string, 0, len(relatives))
	for _, relative := range relatives {
		key := metadataKey(relative)
		if _, exists := byKey[key]; exists {
			continue
		}
		byKey[key] = relative
		keys = append(keys, key)
	}
	sort.Strings(keys)
	unlocks := make([]func(), 0, len(keys))
	for _, key := range keys {
		unlock, ok := v.tryPathLock(byKey[key], true)
		if !ok {
			for index := len(unlocks) - 1; index >= 0; index-- {
				unlocks[index]()
			}
			return nil, false
		}
		unlocks = append(unlocks, unlock)
	}
	return func() {
		for index := len(unlocks) - 1; index >= 0; index-- {
			unlocks[index]()
		}
	}, true
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
	return errors.Join(
		syncDirectory(parent),
		pruneEmptyDirectories(parent, filepath.Join(v.root, "files")),
	)
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
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}

	return syscall.EIO
}
