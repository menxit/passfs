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
	"github.com/hanwen/go-fuse/v2/fuse"
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

type editSession struct {
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

	unlockMu       sync.Mutex
	cachedIdentity *age.X25519Identity
	authorized     map[string]time.Time
	editSessions   map[string]map[string]editSession
	unlockTimer    *time.Timer

	metadataMu sync.RWMutex
	metadata   Metadata

	locksMu sync.Mutex
	locks   map[string]*pathLockEntry

	// Open handles hold a read lock. Namespace changes take the write lock so
	// an editor cannot rename or remove a backing file while it is being used.
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
		root:         root,
		config:       public,
		recipient:    recipient,
		prompter:     prompter,
		maxFileSize:  maxFileSize,
		unlockFor:    unlockFor,
		uid:          uint32(os.Getuid()),
		gid:          uint32(os.Getgid()),
		authorized:   make(map[string]time.Time),
		editSessions: make(map[string]map[string]editSession),
		metadata:     metadata,
		locks:        make(map[string]*pathLockEntry),
	}, nil
}

func loadMetadata(root string) (Metadata, error) {
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
	changed, err := reconcileMetadata(root, &metadata)
	if err != nil {
		return metadata, fmt.Errorf("reconcile metadata: %w", err)
	}
	if changed {
		if err := saveMetadata(root, metadata); err != nil {
			return metadata, fmt.Errorf("save reconciled metadata: %w", err)
		}
	}
	return metadata, nil
}

func (v *Volume) saveMetadataLocked() error {
	return saveMetadata(v.root, v.metadata)
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
		info, err := entry.Info()
		if err != nil {
			return err
		}
		key := metadataKey(relative)
		actual[key] = FileMeta{
			Mode:  0o600,
			MTime: info.ModTime().UnixNano(),
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
	return FileMeta{Mode: 0o600, MTime: modTime.UnixNano()}
}

func (v *Volume) setFileMeta(relative string, meta FileMeta) error {
	key := metadataKey(relative)
	meta.Mode &= 0o777
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	v.metadata.Files[key] = meta
	return v.saveMetadataLocked()
}

func (v *Volume) removeFileMeta(relative string) error {
	key := metadataKey(relative)
	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	delete(v.metadata.Files, key)
	return v.saveMetadataLocked()
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
	if target != "" {
		if _, protected := v.metadata.Files[key]; !protected {
			return os.ErrNotExist
		}
		v.metadata.Links[key] = filepath.Clean(target)
	} else {
		delete(v.metadata.Links, key)
	}
	return v.saveMetadataLocked()
}

func (v *Volume) renameMetadata(oldRelative, newRelative string, directory bool) error {
	oldKey := metadataKey(oldRelative)
	newKey := metadataKey(newRelative)

	v.metadataMu.Lock()
	defer v.metadataMu.Unlock()
	if !directory {
		if meta, ok := v.metadata.Files[oldKey]; ok {
			delete(v.metadata.Files, oldKey)
			v.metadata.Files[newKey] = meta
		}
		return v.saveMetadataLocked()
	}

	prefix := oldKey + "/"
	keys := make([]string, 0)
	for key := range v.metadata.Files {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		meta := v.metadata.Files[key]
		delete(v.metadata.Files, key)
		suffix := strings.TrimPrefix(key, prefix)
		targetKey := newKey + "/" + suffix
		v.metadata.Files[targetKey] = meta
	}
	return v.saveMetadataLocked()
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
	if directoryInfo, statErr := os.Lstat(directoryPath); statErr == nil {
		if directoryInfo.IsDir() {
			return true, directoryInfo, nil
		}
		return false, nil, syscall.EIO
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, nil, statErr
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
	v.locksMu.Lock()
	entry := v.locks[key]
	if entry == nil {
		entry = &pathLockEntry{}
		v.locks[key] = entry
	}
	entry.users++
	v.locksMu.Unlock()

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
		v.locksMu.Lock()
		entry.users--
		if entry.users == 0 && v.locks[key] == entry {
			delete(v.locks, key)
		}
		v.locksMu.Unlock()
	}
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

func (v *Volume) unlockIdentity(
	ctx context.Context,
	relative string,
	operation string,
) (*age.X25519Identity, error) {
	cacheKey := metadataKey(relative)
	v.unlockMu.Lock()
	if identity := v.activeEditIdentityLocked(cacheKey); identity != nil {
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

	var pid uint32
	if caller, ok := fuse.FromContext(ctx); ok {
		pid = caller.Pid
	}
	displayPath := filepath.ToSlash(filepath.Clean(relative))
	displayPath = strings.TrimPrefix(displayPath, "files/")
	displayPath = "/" + strings.TrimPrefix(displayPath, "/")
	request := PromptRequest{
		Path:      displayPath,
		Operation: operation,
		PID:       pid,
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
	if err := validateEditSessionToken(token); err != nil {
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
		sessions = make(map[string]editSession)
		v.editSessions[cacheKey] = sessions
	}
	sessions[token] = editSession{identity: identity, ownerPID: ownerPID}
	v.unlockMu.Unlock()

	go v.monitorEditSession(cacheKey, token, ownerPID)
	return nil
}

func (v *Volume) endEditSession(relative, token string, ownerPID uint32) error {
	if err := validateEditSessionToken(token); err != nil {
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

func (v *Volume) activeEditIdentityLocked(cacheKey string) *age.X25519Identity {
	sessions := v.editSessions[cacheKey]
	for token, session := range sessions {
		if processAlive(session.ownerPID) {
			return session.identity
		}
		delete(sessions, token)
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
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}

	meta.Size = uint64(len(data))
	if meta.MTime == 0 {
		meta.MTime = time.Now().UnixNano()
	}
	return v.setFileMeta(relative, meta)
}

func (v *Volume) removeProtectedFile(relative string) error {
	unlock, ok := v.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()
	return v.removeProtectedFileLocked(relative)
}

func (v *Volume) removeProtectedFileLocked(relative string) error {
	path, err := v.encryptedPath(relative)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return v.removeFileMeta(relative)
}

func errnoFromError(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, ErrAuthentication), errors.Is(err, ErrPromptCancelled):
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
