package passfs

import (
	"context"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"passfs/internal/fsapi"
)

// FileSystem exposes a Volume through the adapter-neutral fsapi contract.
// Platform adapters own mount lifecycle and translate their native request
// types into calls on this value.
type FileSystem struct {
	volume *Volume
}

// NewFileSystem creates the adapter-neutral view of a loaded encrypted volume.
func NewFileSystem(volume *Volume) *FileSystem {
	return &FileSystem{volume: volume}
}

func childPath(parent, name string) (string, error) {
	if err := validateName(name); err != nil {
		return "", err
	}
	if parent != "" {
		return filepath.Join(parent, name), nil
	}
	return name, nil
}

func storagePath(relative string) string {
	clean := filepath.Clean(relative)
	if clean == "." || clean == objectNamespaceDirectory {
		return objectStorageDirectory
	}
	prefix := objectNamespaceDirectory + string(filepath.Separator)
	if !strings.HasPrefix(clean, prefix) {
		return filepath.Join(objectStorageDirectory, ".invalid")
	}
	objectID, err := normalizeObjectID(strings.TrimPrefix(clean, prefix))
	if err != nil {
		return filepath.Join(objectStorageDirectory, ".invalid")
	}
	storage, _ := objectStoragePath(objectID)
	return storage
}

func virtualObjectID(relative string) (string, bool) {
	clean := filepath.Clean(relative)
	prefix := objectNamespaceDirectory + string(filepath.Separator)
	if !strings.HasPrefix(clean, prefix) {
		return "", false
	}
	objectID, err := normalizeObjectID(strings.TrimPrefix(clean, prefix))
	return objectID, err == nil
}

// stableInode maps an identity string to the persistent object identifier
// exposed by FSKit and FUSE. Callers deliberately namespace identities as
// storage paths ("files/..."), metadata keys, or unique "path:timestamp"
// values for newly created objects. Changing this normalization or hash would
// require an object-ID migration for existing FSKit volumes.
func stableInode(relative string) uint64 {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(filepath.ToSlash(filepath.Clean(relative))))
	inode := hasher.Sum64()
	if inode < 2 {
		inode += 2
	}
	return inode
}

var reservedRootMetadataNames = map[string]struct{}{
	".DocumentRevisions-V100":             {},
	".Spotlight-V100":                     {},
	".TemporaryItems":                     {},
	".Trash":                              {},
	".Trashes":                            {},
	".fseventsd":                          {},
	".metadata_never_index":               {},
	".metadata_never_index_unless_rootfs": {},
	".vol":                                {},
	".xdg-volume-info":                    {},
	"System Volume Information":           {},
	"lost+found":                          {},
}

// isReservedFilesystemMetadataPath identifies files created or probed by the
// host operating system for volume bookkeeping. They are not user secrets and
// must never enter the protected namespace or trigger authorization.
func isReservedFilesystemMetadataPath(relative string) bool {
	clean := filepath.Clean(relative)
	if clean == "." || clean == "" {
		return false
	}
	components := strings.Split(filepath.ToSlash(clean), "/")
	first := components[0]
	if _, reserved := reservedRootMetadataNames[first]; reserved {
		return true
	}
	if strings.HasPrefix(first, ".com.apple.timemachine.") ||
		strings.HasPrefix(first, ".Trash-") {
		return true
	}
	for _, component := range components {
		if component == ".DS_Store" || strings.HasPrefix(component, "._") {
			return true
		}
	}
	return false
}

func isReservedStorageMetadataPath(storage string) bool {
	relative, err := filepath.Rel(objectStorageDirectory, filepath.Clean(storage))
	if err != nil || relative == "." ||
		relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return false
	}
	return isReservedFilesystemMetadataPath(relative)
}

func (f *FileSystem) Lookup(
	_ context.Context,
	relative string,
) (fsapi.Entry, syscall.Errno) {
	if err := validateRelativePath(relative); err != nil {
		return fsapi.Entry{}, syscall.ENOENT
	}
	if isReservedFilesystemMetadataPath(relative) {
		return fsapi.Entry{}, syscall.ENOENT
	}
	clean := filepath.Clean(relative)
	if clean != "." && clean != objectNamespaceDirectory {
		if _, valid := virtualObjectID(clean); !valid {
			return fsapi.Entry{}, syscall.ENOENT
		}
	}
	storage := storagePath(relative)
	isDirectory, info, err := f.volume.virtualType(storage)
	if err != nil {
		return fsapi.Entry{}, errnoFromError(err)
	}
	meta := f.volume.fileMeta(storage, info)
	attributes := fileAttributes(
		meta,
		f.volume.uid,
		f.volume.gid,
		inodeFromFileMeta(meta, storage),
	)
	if isDirectory {
		directoryInode := stableInode("/")
		if clean == objectNamespaceDirectory {
			directoryInode = stableInode(objectNamespaceDirectory)
		}
		attributes = directoryAttributes(
			info,
			directoryInode,
		)
	}
	parentInode, err := f.parentInode(relative, attributes.Inode)
	if err != nil {
		return fsapi.Entry{}, errnoFromError(err)
	}
	attributes.ParentInode = parentInode
	return fsapi.Entry{Attributes: attributes}, 0
}

func (f *FileSystem) parentInode(relative string, ownInode uint64) (uint64, error) {
	if relative == "" || relative == "." {
		return ownInode, nil
	}
	if filepath.Clean(relative) == objectNamespaceDirectory {
		return stableInode("/"), nil
	}
	return stableInode(objectNamespaceDirectory), nil
}

func (f *FileSystem) ReadDirectory(
	_ context.Context,
	relative string,
) ([]fsapi.DirectoryEntry, syscall.Errno) {
	if err := validateRelativePath(relative); err != nil {
		return nil, syscall.EINVAL
	}
	clean := filepath.Clean(relative)
	if clean == "." {
		info, err := os.Lstat(filepath.Join(f.volume.root, objectStorageDirectory))
		if err != nil {
			return nil, errnoFromError(err)
		}
		attributes := directoryAttributes(info, stableInode(objectNamespaceDirectory))
		attributes.ParentInode = stableInode("/")
		return []fsapi.DirectoryEntry{{
			Name:       objectNamespaceDirectory,
			Type:       fsapi.TypeDirectory,
			Inode:      attributes.Inode,
			Attributes: attributes,
		}}, 0
	}
	if clean != objectNamespaceDirectory {
		return nil, syscall.ENOTDIR
	}
	storage := objectStorageDirectory
	isDirectory, directoryInfo, err := f.volume.virtualType(storage)
	if err != nil {
		return nil, errnoFromError(err)
	}
	if !isDirectory {
		return nil, syscall.ENOTDIR
	}
	parentInode := inodeFromFileInfo(directoryInfo, stableInode(storage))
	path, err := f.volume.directoryPath(storage)
	if err != nil {
		return nil, errnoFromError(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, errnoFromError(err)
	}

	virtualEntries := make([]fsapi.DirectoryEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		entryInfo, entryErr := entry.Info()
		if entryErr != nil {
			return nil, errnoFromError(entryErr)
		}
		if entry.Type().IsRegular() && strings.HasSuffix(name, encryptedSuffix) {
			virtualName := strings.TrimSuffix(name, encryptedSuffix)
			if _, err := normalizeObjectID(virtualName); err != nil {
				continue
			}
			virtualStorage := filepath.Join(storage, virtualName)
			meta := f.volume.fileMeta(virtualStorage, entryInfo)
			attributes := fileAttributes(
				meta,
				f.volume.uid,
				f.volume.gid,
				inodeFromFileMeta(meta, virtualStorage),
			)
			attributes.ParentInode = parentInode
			virtualEntries = append(virtualEntries, fsapi.DirectoryEntry{
				Name:       virtualName,
				Type:       attributes.Type,
				Inode:      attributes.Inode,
				Attributes: attributes,
			})
		}
	}
	return virtualEntries, 0
}

func (f *FileSystem) GetAttributes(
	ctx context.Context,
	relative string,
	handle fsapi.Handle,
) (fsapi.Attributes, syscall.Errno) {
	if handle != nil {
		return handle.Attributes(ctx)
	}
	entry, errno := f.Lookup(ctx, relative)
	return entry.Attributes, errno
}

func (f *FileSystem) Open(
	ctx context.Context,
	relative string,
	flags uint32,
) (fsapi.Handle, syscall.Errno) {
	entry, errno := f.Lookup(ctx, relative)
	if errno != 0 {
		return nil, errno
	}
	if entry.Attributes.Type == fsapi.TypeDirectory {
		return nil, syscall.EISDIR
	}
	handle, err := f.volume.openFile(ctx, storagePath(relative), flags)
	if err != nil {
		return nil, errnoFromError(err)
	}
	return handle, 0
}

func (f *FileSystem) Create(
	ctx context.Context,
	parent string,
	name string,
	flags uint32,
	mode uint32,
) (fsapi.Entry, fsapi.Handle, syscall.Errno) {
	if filepath.Clean(parent) != objectNamespaceDirectory {
		return fsapi.Entry{}, nil, syscall.EPERM
	}
	if _, err := normalizeObjectID(name); err != nil {
		return fsapi.Entry{}, nil, syscall.EINVAL
	}
	parentEntry, errno := f.Lookup(ctx, parent)
	if errno != 0 {
		return fsapi.Entry{}, nil, errno
	}
	if parentEntry.Attributes.Type != fsapi.TypeDirectory {
		return fsapi.Entry{}, nil, syscall.ENOTDIR
	}
	relative, err := childPath(parent, name)
	if err != nil {
		return fsapi.Entry{}, nil, syscall.EINVAL
	}
	if isReservedFilesystemMetadataPath(relative) {
		return fsapi.Entry{}, nil, syscall.EPERM
	}
	handle, err := f.volume.createFile(ctx, storagePath(relative), flags, mode)
	if err != nil {
		return fsapi.Entry{}, nil, errnoFromError(err)
	}
	attributes, errno := handle.Attributes(ctx)
	if errno != 0 {
		_ = handle.Close(ctx)
		return fsapi.Entry{}, nil, errno
	}
	attributes.ParentInode = parentEntry.Attributes.Inode
	return fsapi.Entry{Attributes: attributes}, handle, 0
}

func (f *FileSystem) MakeDirectory(
	ctx context.Context,
	parent string,
	name string,
	mode uint32,
) (fsapi.Entry, syscall.Errno) {
	_ = ctx
	_ = parent
	_ = name
	_ = mode
	return fsapi.Entry{}, syscall.EPERM
}

func (f *FileSystem) Unlink(
	_ context.Context,
	parent string,
	name string,
) syscall.Errno {
	relative, err := childPath(parent, name)
	if err != nil {
		return syscall.EINVAL
	}
	if isReservedFilesystemMetadataPath(relative) {
		return syscall.EPERM
	}
	storage := storagePath(relative)
	unlock, ok := f.volume.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()

	isDirectory, _, err := f.volume.virtualType(storage)
	if err != nil {
		return errnoFromError(err)
	}
	if isDirectory {
		return syscall.EISDIR
	}
	return errnoFromError(f.volume.removeProtectedFileLocked(storage))
}

func (f *FileSystem) RemoveDirectory(
	_ context.Context,
	parent string,
	name string,
) syscall.Errno {
	_ = parent
	_ = name
	return syscall.EPERM
}

func (f *FileSystem) Rename(
	_ context.Context,
	oldParent string,
	oldName string,
	newParent string,
	newName string,
	flags uint32,
) syscall.Errno {
	_ = oldParent
	_ = oldName
	_ = newParent
	_ = newName
	_ = flags
	return syscall.EPERM
}

func (f *FileSystem) SetAttributes(
	ctx context.Context,
	relative string,
	handle fsapi.Handle,
	input fsapi.SetAttributes,
) (fsapi.Attributes, syscall.Errno) {
	if handle != nil {
		return handle.SetAttributes(ctx, input)
	}
	if input.UID != nil && *input.UID != f.volume.uid {
		return fsapi.Attributes{}, syscall.EPERM
	}
	if input.GID != nil && *input.GID != f.volume.gid {
		return fsapi.Attributes{}, syscall.EPERM
	}

	entry, errno := f.Lookup(ctx, relative)
	if errno != 0 {
		return fsapi.Attributes{}, errno
	}
	storage := storagePath(relative)
	if entry.Attributes.Type == fsapi.TypeDirectory {
		path, err := f.volume.directoryPath(storage)
		if err != nil {
			return fsapi.Attributes{}, errnoFromError(err)
		}
		if input.Mode != nil {
			if err := os.Chmod(path, os.FileMode(*input.Mode&0o777)); err != nil {
				return fsapi.Attributes{}, errnoFromError(err)
			}
		}
		if input.ModifyTime != nil || input.AccessTime != nil {
			info, err := os.Stat(path)
			if err != nil {
				return fsapi.Attributes{}, errnoFromError(err)
			}
			mtime := info.ModTime()
			atime := info.ModTime()
			if input.ModifyTime != nil {
				mtime = *input.ModifyTime
			}
			if input.AccessTime != nil {
				atime = *input.AccessTime
			}
			if err := os.Chtimes(path, atime, mtime); err != nil {
				return fsapi.Attributes{}, errnoFromError(err)
			}
		}
		return f.GetAttributes(ctx, relative, nil)
	}

	if openHandle := f.volume.writableOpenHandle(storage, callerPID(ctx)); openHandle != nil {
		return openHandle.SetAttributes(ctx, input)
	}

	if input.Size != nil {
		openHandle, err := f.volume.openFile(ctx, storage, syscall.O_RDWR)
		if err != nil {
			return fsapi.Attributes{}, errnoFromError(err)
		}
		attributes, errno := openHandle.SetAttributes(ctx, input)
		if errno == 0 {
			errno = openHandle.Flush(ctx)
		}
		_ = openHandle.Close(ctx)
		return attributes, errno
	}

	unlock := f.volume.acquireOpenLock(storage, true)
	defer unlock()
	path, err := f.volume.encryptedPath(storage)
	if err != nil {
		return fsapi.Attributes{}, errnoFromError(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fsapi.Attributes{}, errnoFromError(err)
	}
	meta := f.volume.fileMeta(storage, info)
	if input.Mode != nil {
		meta.Mode = *input.Mode & 0o777
	}
	if input.ModifyTime != nil {
		meta.MTime = input.ModifyTime.UnixNano()
	}
	if input.AccessTime != nil {
		meta.ATime = input.AccessTime.UnixNano()
	}
	if err := f.volume.setFileMeta(storage, meta); err != nil {
		return fsapi.Attributes{}, errnoFromError(err)
	}
	return fileAttributes(
		meta,
		f.volume.uid,
		f.volume.gid,
		inodeFromFileMeta(meta, storage),
	), 0
}

func (f *FileSystem) SetExtendedAttribute(
	ctx context.Context,
	relative string,
	name string,
	data []byte,
	_ uint32,
) syscall.Errno {
	entry, errno := f.Lookup(ctx, relative)
	if errno != 0 {
		return errno
	}
	switch name {
	case encryptSessionMarkerName:
		if entry.Attributes.Type != fsapi.TypeDirectory || relative != "" {
			return syscall.EPERM
		}
		return f.setEncryptSession(ctx, data)
	case editSessionMarkerName:
		if entry.Attributes.Type == fsapi.TypeDirectory {
			return syscall.EINVAL
		}
		return f.setEditSession(ctx, relative, data)
	default:
		return syscall.ENOTSUP
	}
}

func (f *FileSystem) setEditSession(
	ctx context.Context,
	relative string,
	data []byte,
) syscall.Errno {
	operation, token, err := parseSessionCommand(data)
	if err != nil {
		return syscall.EINVAL
	}
	ownerPID := callerPID(ctx)
	if ownerPID == 0 {
		return syscall.EPERM
	}
	storage := storagePath(relative)
	switch operation {
	case "begin":
		return errnoFromError(
			f.volume.beginEditSession(ctx, storage, token, ownerPID),
		)
	case "end":
		return errnoFromError(
			f.volume.endEditSession(storage, token, ownerPID),
		)
	default:
		return syscall.EINVAL
	}
}

func (f *FileSystem) setEncryptSession(
	ctx context.Context,
	data []byte,
) syscall.Errno {
	operation, token, err := parseSessionCommand(data)
	if err != nil {
		return syscall.EINVAL
	}
	ownerPID := callerPID(ctx)
	if ownerPID == 0 {
		return syscall.EPERM
	}
	switch operation {
	case "begin":
		return errnoFromError(
			f.volume.beginEncryptSession(ctx, token, ownerPID),
		)
	case "end":
		return errnoFromError(
			f.volume.endEncryptSession(token, ownerPID),
		)
	default:
		return syscall.EINVAL
	}
}

func (f *FileSystem) Statistics(
	_ context.Context,
) (fsapi.Statistics, syscall.Errno) {
	stats := syscall.Statfs_t{}
	if err := syscall.Statfs(f.volume.root, &stats); err != nil {
		return fsapi.Statistics{}, errnoFromError(err)
	}
	blockSize := uint64(stats.Bsize)
	return fsapi.Statistics{
		BlockSize:       blockSize,
		IOSize:          blockSize,
		TotalBlocks:     uint64(stats.Blocks),
		AvailableBlocks: uint64(stats.Bavail),
		FreeBlocks:      uint64(stats.Bfree),
		TotalFiles:      uint64(stats.Files),
		FreeFiles:       uint64(stats.Ffree),
	}, 0
}

func directoryAttributes(info os.FileInfo, inode uint64) fsapi.Attributes {
	modTime := info.ModTime()
	return fsapi.Attributes{
		Type:       fsapi.TypeDirectory,
		Inode:      inode,
		Size:       uint64(info.Size()),
		Blocks:     (uint64(info.Size()) + 511) / 512,
		Mode:       uint32(info.Mode().Perm()),
		UID:        uint32(os.Getuid()),
		GID:        uint32(os.Getgid()),
		LinkCount:  1,
		AccessTime: modTime,
		ChangeTime: modTime,
		ModifyTime: modTime,
		BirthTime:  modTime,
	}
}

func fileAttributes(
	meta FileMeta,
	uid uint32,
	gid uint32,
	inode uint64,
) fsapi.Attributes {
	modTime := time.Unix(0, meta.MTime)
	if meta.MTime == 0 {
		modTime = time.Now()
	}
	accessTime := modTime
	if meta.ATime != 0 {
		accessTime = time.Unix(0, meta.ATime)
	}
	return fsapi.Attributes{
		Type:       fsapi.TypeFile,
		Inode:      inode,
		Size:       meta.Size,
		Blocks:     (meta.Size + 511) / 512,
		Mode:       meta.Mode & 0o777,
		UID:        uid,
		GID:        gid,
		LinkCount:  1,
		AccessTime: accessTime,
		ChangeTime: modTime,
		ModifyTime: modTime,
		BirthTime:  modTime,
	}
}

var _ fsapi.FileSystem = (*FileSystem)(nil)
