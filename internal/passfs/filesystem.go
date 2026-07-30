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

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type Node struct {
	fs.Inode
	volume *Volume
	isDir  bool
}

func NewRootNode(volume *Volume) *Node {
	return &Node{volume: volume, isDir: true}
}

func (n *Node) relativePath() string {
	relative := n.Path(n.Root())
	if relative == "." {
		return ""
	}
	return filepath.Clean(relative)
}

func (n *Node) childPath(name string) (string, error) {
	if err := validateName(name); err != nil {
		return "", err
	}
	if relative := n.relativePath(); relative != "" {
		return filepath.Join(relative, name), nil
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

func (n *Node) Lookup(
	ctx context.Context,
	name string,
	out *fuse.EntryOut,
) (*fs.Inode, syscall.Errno) {
	relative, err := n.childPath(name)
	if err != nil {
		return nil, syscall.ENOENT
	}
	storage := storagePath(relative)
	isDirectory, info, err := n.volume.virtualType(storage)
	if err != nil {
		return nil, errnoFromError(err)
	}

	child := &Node{volume: n.volume, isDir: isDirectory}
	inode := stableInode(storage)
	stable := fs.StableAttr{Mode: fuse.S_IFREG, Ino: inode}
	if isDirectory {
		stable.Mode = fuse.S_IFDIR
		fillDirectoryAttr(&out.Attr, info, inode)
	} else {
		fillFileAttr(
			&out.Attr,
			n.volume.fileMeta(storage, info),
			n.volume.uid,
			n.volume.gid,
			inode,
		)
	}
	return n.NewInode(ctx, child, stable), 0
}

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if !n.isDir {
		return nil, syscall.ENOTDIR
	}
	path, err := n.volume.directoryPath(storagePath(n.relativePath()))
	if err != nil {
		return nil, errnoFromError(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, errnoFromError(err)
	}

	virtualEntries := make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case entry.IsDir():
			// Directory names ending in .age would be ambiguous with the
			// backing name of a regular virtual file, so they are not exposed.
			if strings.HasSuffix(name, encryptedSuffix) {
				continue
			}
			virtualEntries = append(virtualEntries, fuse.DirEntry{
				Name: name,
				Mode: fuse.S_IFDIR,
			})
		case entry.Type().IsRegular() && strings.HasSuffix(name, encryptedSuffix):
			virtualEntries = append(virtualEntries, fuse.DirEntry{
				Name: strings.TrimSuffix(name, encryptedSuffix),
				Mode: fuse.S_IFREG,
			})
		}
	}
	return fs.NewListDirStream(virtualEntries), 0
}

func (n *Node) Getattr(
	ctx context.Context,
	handle fs.FileHandle,
	out *fuse.AttrOut,
) syscall.Errno {
	if handle != nil {
		if getter, ok := handle.(fs.FileGetattrer); ok {
			return getter.Getattr(ctx, out)
		}
	}

	relative := n.relativePath()
	storage := storagePath(relative)
	if n.isDir {
		path, err := n.volume.directoryPath(storage)
		if err != nil {
			return errnoFromError(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return errnoFromError(err)
		}
		fillDirectoryAttr(&out.Attr, info, stableInode(storage))
		return 0
	}

	path, err := n.volume.encryptedPath(storage)
	if err != nil {
		return errnoFromError(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errnoFromError(err)
	}
	fillFileAttr(
		&out.Attr,
		n.volume.fileMeta(storage, info),
		n.volume.uid,
		n.volume.gid,
		stableInode(storage),
	)
	return 0
}

func (n *Node) Open(
	ctx context.Context,
	flags uint32,
) (fs.FileHandle, uint32, syscall.Errno) {
	if n.isDir {
		return nil, 0, syscall.EISDIR
	}
	handle, err := n.volume.openFile(ctx, storagePath(n.relativePath()), flags)
	if err != nil {
		return nil, 0, errnoFromError(err)
	}
	return handle, fuse.FOPEN_DIRECT_IO, 0
}

func (n *Node) Create(
	ctx context.Context,
	name string,
	flags uint32,
	mode uint32,
	out *fuse.EntryOut,
) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if !n.isDir {
		return nil, nil, 0, syscall.ENOTDIR
	}
	relative, err := n.childPath(name)
	if err != nil {
		return nil, nil, 0, syscall.EINVAL
	}
	handle, err := n.volume.createFile(ctx, storagePath(relative), flags, mode)
	if err != nil {
		return nil, nil, 0, errnoFromError(err)
	}

	child := &Node{volume: n.volume}
	inode := n.NewInode(ctx, child, fs.StableAttr{
		Mode: fuse.S_IFREG,
		Ino:  stableInode(storagePath(relative)),
	})
	var attributes fuse.AttrOut
	if errno := handle.Getattr(ctx, &attributes); errno != 0 {
		_ = handle.Release(ctx)
		return nil, nil, 0, errno
	}
	out.Attr = attributes.Attr
	return inode, handle, fuse.FOPEN_DIRECT_IO, 0
}

func (n *Node) Mkdir(
	ctx context.Context,
	name string,
	mode uint32,
	out *fuse.EntryOut,
) (*fs.Inode, syscall.Errno) {
	if !n.isDir {
		return nil, syscall.ENOTDIR
	}
	if strings.HasSuffix(name, encryptedSuffix) {
		return nil, syscall.EINVAL
	}
	relative, err := n.childPath(name)
	if err != nil {
		return nil, syscall.EINVAL
	}
	storage := storagePath(relative)
	unlock, ok := n.volume.tryNamespaceLock()
	if !ok {
		return nil, syscall.EBUSY
	}
	defer unlock()

	if _, _, err := n.volume.virtualType(storage); err == nil {
		return nil, syscall.EEXIST
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errnoFromError(err)
	}
	path, err := n.volume.directoryPath(storage)
	if err != nil {
		return nil, errnoFromError(err)
	}
	if err := os.Mkdir(path, os.FileMode(mode&0o777)); err != nil {
		return nil, errnoFromError(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, errnoFromError(err)
	}
	inodeNumber := stableInode(storage)
	fillDirectoryAttr(&out.Attr, info, inodeNumber)
	child := &Node{volume: n.volume, isDir: true}
	return n.NewInode(ctx, child, fs.StableAttr{
		Mode: fuse.S_IFDIR,
		Ino:  inodeNumber,
	}), 0
}

func (n *Node) Unlink(ctx context.Context, name string) syscall.Errno {
	relative, err := n.childPath(name)
	if err != nil {
		return syscall.EINVAL
	}
	storage := storagePath(relative)
	unlock, ok := n.volume.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()

	isDirectory, _, err := n.volume.virtualType(storage)
	if err != nil {
		return errnoFromError(err)
	}
	if isDirectory {
		return syscall.EISDIR
	}
	return errnoFromError(n.volume.removeProtectedFileLocked(storage))
}

func (n *Node) Rmdir(ctx context.Context, name string) syscall.Errno {
	relative, err := n.childPath(name)
	if err != nil {
		return syscall.EINVAL
	}
	storage := storagePath(relative)
	unlock, ok := n.volume.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()

	isDirectory, _, err := n.volume.virtualType(storage)
	if err != nil {
		return errnoFromError(err)
	}
	if !isDirectory {
		return syscall.ENOTDIR
	}
	path, err := n.volume.directoryPath(storage)
	if err != nil {
		return errnoFromError(err)
	}
	return errnoFromError(os.Remove(path))
}

func (n *Node) Rename(
	ctx context.Context,
	name string,
	newParent fs.InodeEmbedder,
	newName string,
	flags uint32,
) syscall.Errno {
	if flags != 0 {
		return syscall.ENOTSUP
	}
	targetParent, ok := newParent.(*Node)
	if !ok || targetParent.volume != n.volume {
		return syscall.EXDEV
	}
	oldRelative, err := n.childPath(name)
	if err != nil {
		return syscall.EINVAL
	}
	newRelative, err := targetParent.childPath(newName)
	if err != nil {
		return syscall.EINVAL
	}
	if oldRelative == newRelative {
		return 0
	}
	oldStorage := storagePath(oldRelative)
	newStorage := storagePath(newRelative)

	unlock, ok := n.volume.tryNamespaceLock()
	if !ok {
		return syscall.EBUSY
	}
	defer unlock()

	isDirectory, _, err := n.volume.virtualType(oldStorage)
	if err != nil {
		return errnoFromError(err)
	}
	if isDirectory && strings.HasSuffix(newName, encryptedSuffix) {
		return syscall.EINVAL
	}
	if targetDirectory, _, targetErr := n.volume.virtualType(newStorage); targetErr == nil {
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
		oldPath, err = n.volume.directoryPath(oldStorage)
		if err == nil {
			newPath, err = n.volume.directoryPath(newStorage)
		}
	} else {
		oldPath, err = n.volume.encryptedPath(oldStorage)
		if err == nil {
			newPath, err = n.volume.encryptedPath(newStorage)
		}
	}
	if err != nil {
		return errnoFromError(err)
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return errnoFromError(err)
	}
	return errnoFromError(n.volume.renameMetadata(oldStorage, newStorage, isDirectory))
}

func (n *Node) Setattr(
	ctx context.Context,
	handle fs.FileHandle,
	input *fuse.SetAttrIn,
	out *fuse.AttrOut,
) syscall.Errno {
	if setter, ok := handle.(fs.FileSetattrer); ok && setter != nil {
		return setter.Setattr(ctx, input, out)
	}
	if uid, ok := input.GetUID(); ok && uid != n.volume.uid {
		return syscall.EPERM
	}
	if gid, ok := input.GetGID(); ok && gid != n.volume.gid {
		return syscall.EPERM
	}

	relative := n.relativePath()
	storage := storagePath(relative)
	if n.isDir {
		path, err := n.volume.directoryPath(storage)
		if err != nil {
			return errnoFromError(err)
		}
		if mode, ok := input.GetMode(); ok {
			if err := os.Chmod(path, os.FileMode(mode&0o777)); err != nil {
				return errnoFromError(err)
			}
		}
		mtime, mtimeSet := input.GetMTime()
		atime, atimeSet := input.GetATime()
		if mtimeSet || atimeSet {
			info, err := os.Stat(path)
			if err != nil {
				return errnoFromError(err)
			}
			if !mtimeSet {
				mtime = info.ModTime()
			}
			if !atimeSet {
				atime = info.ModTime()
			}
			if err := os.Chtimes(path, atime, mtime); err != nil {
				return errnoFromError(err)
			}
		}
		return n.Getattr(ctx, nil, out)
	}

	if openHandle := n.volume.writableOpenHandle(
		storage,
		callerPID(ctx),
	); openHandle != nil {
		return openHandle.Setattr(ctx, input, out)
	}

	if _, resize := input.GetSize(); resize {
		handle, err := n.volume.openFile(ctx, storage, syscall.O_RDWR)
		if err != nil {
			return errnoFromError(err)
		}
		errno := handle.Setattr(ctx, input, out)
		if errno == 0 {
			errno = handle.Flush(ctx)
		}
		_ = handle.Release(ctx)
		return errno
	}

	unlock := n.volume.acquireOpenLock(storage, true)
	defer unlock()
	path, err := n.volume.encryptedPath(storage)
	if err != nil {
		return errnoFromError(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return errnoFromError(err)
	}
	meta := n.volume.fileMeta(storage, info)
	if mode, ok := input.GetMode(); ok {
		meta.Mode = mode & 0o777
	}
	if mtime, ok := input.GetMTime(); ok {
		meta.MTime = mtime.UnixNano()
	}
	if err := n.volume.setFileMeta(storage, meta); err != nil {
		return errnoFromError(err)
	}
	fillFileAttr(
		&out.Attr,
		meta,
		n.volume.uid,
		n.volume.gid,
		stableInode(storage),
	)
	return 0
}

func (n *Node) Setxattr(
	ctx context.Context,
	name string,
	data []byte,
	flags uint32,
) syscall.Errno {
	switch name {
	case encryptSessionMarkerName:
		if !n.isDir || !n.IsRoot() {
			return syscall.EPERM
		}
		return n.setEncryptSession(ctx, data)
	case linkMarkerName:
		if n.isDir {
			return syscall.EINVAL
		}
		return n.setLinkMarker(data)
	case editSessionMarkerName:
		if n.isDir {
			return syscall.EINVAL
		}
		return n.setEditSession(ctx, data)
	default:
		return syscall.ENOTSUP
	}
}

func (n *Node) setLinkMarker(data []byte) syscall.Errno {
	if len(data) == 0 || len(data) > 4096 ||
		strings.ContainsRune(string(data), 0) {
		return syscall.EINVAL
	}
	storage := storagePath(n.relativePath())
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
	return errnoFromError(n.volume.registerProtectedLink(storage, targetPath))
}

func (n *Node) setEditSession(ctx context.Context, data []byte) syscall.Errno {
	operation, token, err := parseSessionCommand(data)
	if err != nil {
		return syscall.EINVAL
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok || caller.Pid == 0 {
		return syscall.EPERM
	}
	ownerPID := callerPID(ctx)
	if ownerPID == 0 {
		return syscall.EPERM
	}
	storage := storagePath(n.relativePath())
	switch operation {
	case "begin":
		return errnoFromError(
			n.volume.beginEditSession(ctx, storage, token, ownerPID),
		)
	case "end":
		return errnoFromError(
			n.volume.endEditSession(storage, token, ownerPID),
		)
	default:
		return syscall.EINVAL
	}
}

func (n *Node) setEncryptSession(ctx context.Context, data []byte) syscall.Errno {
	operation, token, err := parseSessionCommand(data)
	if err != nil {
		return syscall.EINVAL
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok || caller.Pid == 0 {
		return syscall.EPERM
	}
	ownerPID := callerPID(ctx)
	if ownerPID == 0 {
		return syscall.EPERM
	}
	switch operation {
	case "begin":
		return errnoFromError(
			n.volume.beginEncryptSession(ctx, token, ownerPID),
		)
	case "end":
		return errnoFromError(
			n.volume.endEncryptSession(token, ownerPID),
		)
	default:
		return syscall.EINVAL
	}
}

func (n *Node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	stats := syscall.Statfs_t{}
	if err := syscall.Statfs(n.volume.root, &stats); err != nil {
		return errnoFromError(err)
	}
	out.FromStatfsT(&stats)
	return 0
}

func fillDirectoryAttr(out *fuse.Attr, info os.FileInfo, inode uint64) {
	if attr := fuse.ToAttr(info); attr != nil {
		*out = *attr
		out.Ino = inode
		return
	}
	now := info.ModTime()
	out.Mode = fuse.S_IFDIR | uint32(info.Mode().Perm())
	out.Ino = inode
	out.Nlink = 1
	out.SetTimes(&now, &now, &now)
}

func fillFileAttr(out *fuse.Attr, meta FileMeta, uid, gid uint32, inode uint64) {
	modTime := time.Unix(0, meta.MTime)
	if meta.MTime == 0 {
		modTime = time.Now()
	}
	out.Mode = fuse.S_IFREG | (meta.Mode & 0o777)
	out.Ino = inode
	out.Size = meta.Size
	out.Blocks = (meta.Size + 511) / 512
	out.Nlink = 1
	out.Owner.Uid = uid
	out.Owner.Gid = gid
	out.SetTimes(&modTime, &modTime, &modTime)
}

var (
	_ fs.NodeLookuper   = (*Node)(nil)
	_ fs.NodeReaddirer  = (*Node)(nil)
	_ fs.NodeGetattrer  = (*Node)(nil)
	_ fs.NodeOpener     = (*Node)(nil)
	_ fs.NodeCreater    = (*Node)(nil)
	_ fs.NodeMkdirer    = (*Node)(nil)
	_ fs.NodeUnlinker   = (*Node)(nil)
	_ fs.NodeRmdirer    = (*Node)(nil)
	_ fs.NodeRenamer    = (*Node)(nil)
	_ fs.NodeSetattrer  = (*Node)(nil)
	_ fs.NodeSetxattrer = (*Node)(nil)
	_ fs.NodeStatfser   = (*Node)(nil)
)
