package passfs

import (
	"context"
	"errors"
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
	if relative == "" || relative == "." {
		return "files"
	}
	return filepath.Join("files", relative)
}

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
	relative, err := filepath.Rel("files", filepath.Clean(storage))
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
	storage := storagePath(relative)
	isDirectory, info, err := f.volume.virtualType(storage)
	if err != nil {
		return fsapi.Entry{}, errnoFromError(err)
	}
	attributes := fileAttributes(
		f.volume.fileMeta(storage, info),
		f.volume.uid,
		f.volume.gid,
		stableInode(storage),
	)
	if isDirectory {
		attributes = directoryAttributes(info, stableInode(storage))
	}
	return fsapi.Entry{Path: relative, Attributes: attributes}, 0
}

func (f *FileSystem) ReadDirectory(
	_ context.Context,
	relative string,
) ([]fsapi.DirectoryEntry, syscall.Errno) {
	if err := validateRelativePath(relative); err != nil {
		return nil, syscall.EINVAL
	}
	storage := storagePath(relative)
	isDirectory, _, err := f.volume.virtualType(storage)
	if err != nil {
		return nil, errnoFromError(err)
	}
	if !isDirectory {
		return nil, syscall.ENOTDIR
	}
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
		switch {
		case entry.IsDir():
			// Directory names ending in .age would be ambiguous with the
			// backing name of a regular virtual file, so they are not exposed.
			if strings.HasSuffix(name, encryptedSuffix) {
				continue
			}
			if isReservedFilesystemMetadataPath(filepath.Join(relative, name)) {
				continue
			}
			virtualEntries = append(virtualEntries, fsapi.DirectoryEntry{
				Name:  name,
				Type:  fsapi.TypeDirectory,
				Inode: stableInode(filepath.Join(storage, name)),
			})
		case entry.Type().IsRegular() && strings.HasSuffix(name, encryptedSuffix):
			virtualName := strings.TrimSuffix(name, encryptedSuffix)
			if isReservedFilesystemMetadataPath(
				filepath.Join(relative, virtualName),
			) {
				continue
			}
			virtualEntries = append(virtualEntries, fsapi.DirectoryEntry{
				Name:  virtualName,
				Type:  fsapi.TypeFile,
				Inode: stableInode(filepath.Join(storage, virtualName)),
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
	return fsapi.Entry{Path: relative, Attributes: attributes}, handle, 0
}

func (f *FileSystem) MakeDirectory(
	ctx context.Context,
	parent string,
	name string,
	mode uint32,
) (fsapi.Entry, syscall.Errno) {
	parentEntry, errno := f.Lookup(ctx, parent)
	if errno != 0 {
		return fsapi.Entry{}, errno
	}
	if parentEntry.Attributes.Type != fsapi.TypeDirectory {
		return fsapi.Entry{}, syscall.ENOTDIR
	}
	if strings.HasSuffix(name, encryptedSuffix) {
		return fsapi.Entry{}, syscall.EINVAL
	}
	relative, err := childPath(parent, name)
	if err != nil {
		return fsapi.Entry{}, syscall.EINVAL
	}
	if isReservedFilesystemMetadataPath(relative) {
		return fsapi.Entry{}, syscall.EPERM
	}
	storage := storagePath(relative)
	unlock, ok := f.volume.tryNamespaceLock()
	if !ok {
		return fsapi.Entry{}, syscall.EBUSY
	}
	defer unlock()

	if _, _, err := f.volume.virtualType(storage); err == nil {
		return fsapi.Entry{}, syscall.EEXIST
	} else if !errors.Is(err, os.ErrNotExist) {
		return fsapi.Entry{}, errnoFromError(err)
	}
	path, err := f.volume.directoryPath(storage)
	if err != nil {
		return fsapi.Entry{}, errnoFromError(err)
	}
	if err := os.Mkdir(path, os.FileMode(mode&0o777)); err != nil {
		return fsapi.Entry{}, errnoFromError(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = os.Remove(path)
		return fsapi.Entry{}, errnoFromError(err)
	}
	return fsapi.Entry{
		Path:       relative,
		Attributes: directoryAttributes(info, stableInode(storage)),
	}, 0
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
	if !isDirectory {
		return syscall.ENOTDIR
	}
	path, err := f.volume.directoryPath(storage)
	if err != nil {
		return errnoFromError(err)
	}
	return errnoFromError(os.Remove(path))
}

func (f *FileSystem) Rename(
	_ context.Context,
	oldParent string,
	oldName string,
	newParent string,
	newName string,
	flags uint32,
) syscall.Errno {
	if flags != 0 {
		return syscall.ENOTSUP
	}
	oldRelative, err := childPath(oldParent, oldName)
	if err != nil {
		return syscall.EINVAL
	}
	newRelative, err := childPath(newParent, newName)
	if err != nil {
		return syscall.EINVAL
	}
	if isReservedFilesystemMetadataPath(oldRelative) ||
		isReservedFilesystemMetadataPath(newRelative) {
		return syscall.EPERM
	}
	if oldRelative == newRelative {
		return 0
	}
	oldStorage := storagePath(oldRelative)
	newStorage := storagePath(newRelative)

	unlock, ok := f.volume.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()

	isDirectory, _, err := f.volume.virtualType(oldStorage)
	if err != nil {
		return errnoFromError(err)
	}
	if isDirectory && strings.HasSuffix(newName, encryptedSuffix) {
		return syscall.EINVAL
	}
	if targetDirectory, _, targetErr := f.volume.virtualType(newStorage); targetErr == nil {
		if isDirectory && !targetDirectory {
			return syscall.ENOTDIR
		}
		if !isDirectory && targetDirectory {
			return syscall.EISDIR
		}
	} else if !errors.Is(targetErr, os.ErrNotExist) {
		return errnoFromError(targetErr)
	}

	var oldPath, newPath string
	if isDirectory {
		oldPath, err = f.volume.directoryPath(oldStorage)
		if err == nil {
			newPath, err = f.volume.directoryPath(newStorage)
		}
	} else {
		oldPath, err = f.volume.encryptedPath(oldStorage)
		if err == nil {
			newPath, err = f.volume.encryptedPath(newStorage)
		}
	}
	if err != nil {
		return errnoFromError(err)
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return errnoFromError(err)
	}
	return errnoFromError(f.volume.renameMetadata(oldStorage, newStorage, isDirectory))
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
		stableInode(storage),
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
	case linkMarkerName:
		if entry.Attributes.Type == fsapi.TypeDirectory {
			return syscall.EINVAL
		}
		return f.setLinkMarker(relative, data)
	case editSessionMarkerName:
		if entry.Attributes.Type == fsapi.TypeDirectory {
			return syscall.EINVAL
		}
		return f.setEditSession(ctx, relative, data)
	default:
		return syscall.ENOTSUP
	}
}

func (f *FileSystem) setLinkMarker(relative string, data []byte) syscall.Errno {
	if len(data) == 0 || len(data) > 4096 ||
		strings.ContainsRune(string(data), 0) {
		return syscall.EINVAL
	}
	storage := storagePath(relative)
	sourcePath, err := OriginalPath(storage)
	if err != nil {
		return errnoFromError(err)
	}
	targetPath := filepath.Clean(string(data))
	link, err := inspectProtectedLink(sourcePath)
	if err != nil {
		return errnoFromError(err)
	}
	if !link.isSymlink || link.target != targetPath {
		return syscall.EINVAL
	}
	return errnoFromError(f.volume.registerProtectedLink(storage, targetPath))
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
