// Package fuseadapter exposes an fsapi.FileSystem through go-fuse.
package fuseadapter

import (
	"context"
	"path/filepath"
	"syscall"

	"passfs/internal/fsapi"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Node adapts one fsapi path to the go-fuse inode API.
type Node struct {
	fs.Inode
	fileSystem fsapi.FileSystem
	itemType   fsapi.ItemType
}

// NewRootNode creates a FUSE root backed by fileSystem.
func NewRootNode(fileSystem fsapi.FileSystem) *Node {
	return &Node{fileSystem: fileSystem, itemType: fsapi.TypeDirectory}
}

func (n *Node) relativePath() string {
	relative := n.Path(n.Root())
	if relative == "." {
		return ""
	}
	return filepath.Clean(relative)
}

func (n *Node) childPath(name string) string {
	if relative := n.relativePath(); relative != "" {
		return filepath.Join(relative, name)
	}
	return name
}

func requestContext(ctx context.Context) context.Context {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return ctx
	}
	return fsapi.WithCaller(ctx, fsapi.Caller{
		PID: caller.Pid,
		UID: caller.Uid,
		GID: caller.Gid,
	})
}

func (n *Node) Lookup(
	ctx context.Context,
	name string,
	out *fuse.EntryOut,
) (*fs.Inode, syscall.Errno) {
	ctx = requestContext(ctx)
	entry, errno := n.fileSystem.Lookup(ctx, n.childPath(name))
	if errno != 0 {
		return nil, errno
	}
	fillFuseAttributes(&out.Attr, entry.Attributes)
	child := &Node{
		fileSystem: n.fileSystem,
		itemType:   entry.Attributes.Type,
	}
	return n.NewInode(ctx, child, stableAttributes(entry.Attributes)), 0
}

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	ctx = requestContext(ctx)
	entries, errno := n.fileSystem.ReadDirectory(ctx, n.relativePath())
	if errno != 0 {
		return nil, errno
	}
	fuseEntries := make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		fuseEntries = append(fuseEntries, fuse.DirEntry{
			Name: entry.Name,
			Mode: fuseMode(entry.Type, 0),
			Ino:  entry.Inode,
		})
	}
	return fs.NewListDirStream(fuseEntries), 0
}

func (n *Node) Getattr(
	ctx context.Context,
	handle fs.FileHandle,
	out *fuse.AttrOut,
) syscall.Errno {
	ctx = requestContext(ctx)
	attributes, errno := n.fileSystem.GetAttributes(
		ctx,
		n.relativePath(),
		coreHandle(handle),
	)
	if errno == 0 {
		fillFuseAttributes(&out.Attr, attributes)
	}
	return errno
}

func (n *Node) Open(
	ctx context.Context,
	flags uint32,
) (fs.FileHandle, uint32, syscall.Errno) {
	ctx = requestContext(ctx)
	handle, errno := n.fileSystem.Open(ctx, n.relativePath(), flags)
	if errno != 0 {
		return nil, 0, errno
	}
	return &FileHandle{handle: handle}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *Node) Create(
	ctx context.Context,
	name string,
	flags uint32,
	mode uint32,
	out *fuse.EntryOut,
) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	ctx = requestContext(ctx)
	entry, handle, errno := n.fileSystem.Create(
		ctx,
		n.relativePath(),
		name,
		flags,
		mode,
	)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	fillFuseAttributes(&out.Attr, entry.Attributes)
	child := &Node{
		fileSystem: n.fileSystem,
		itemType:   entry.Attributes.Type,
	}
	inode := n.NewInode(ctx, child, stableAttributes(entry.Attributes))
	return inode, &FileHandle{handle: handle}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *Node) Mkdir(
	ctx context.Context,
	name string,
	mode uint32,
	out *fuse.EntryOut,
) (*fs.Inode, syscall.Errno) {
	ctx = requestContext(ctx)
	entry, errno := n.fileSystem.MakeDirectory(
		ctx,
		n.relativePath(),
		name,
		mode,
	)
	if errno != 0 {
		return nil, errno
	}
	fillFuseAttributes(&out.Attr, entry.Attributes)
	child := &Node{
		fileSystem: n.fileSystem,
		itemType:   entry.Attributes.Type,
	}
	return n.NewInode(ctx, child, stableAttributes(entry.Attributes)), 0
}

func (n *Node) Unlink(ctx context.Context, name string) syscall.Errno {
	return n.fileSystem.Unlink(
		requestContext(ctx),
		n.relativePath(),
		name,
	)
}

func (n *Node) Rmdir(ctx context.Context, name string) syscall.Errno {
	return n.fileSystem.RemoveDirectory(
		requestContext(ctx),
		n.relativePath(),
		name,
	)
}

func (n *Node) Rename(
	ctx context.Context,
	name string,
	newParent fs.InodeEmbedder,
	newName string,
	flags uint32,
) syscall.Errno {
	targetParent, ok := newParent.(*Node)
	if !ok || targetParent.fileSystem != n.fileSystem {
		return syscall.EXDEV
	}
	return n.fileSystem.Rename(
		requestContext(ctx),
		n.relativePath(),
		name,
		targetParent.relativePath(),
		newName,
		flags,
	)
}

func (n *Node) Setattr(
	ctx context.Context,
	handle fs.FileHandle,
	input *fuse.SetAttrIn,
	out *fuse.AttrOut,
) syscall.Errno {
	attributes, errno := n.fileSystem.SetAttributes(
		requestContext(ctx),
		n.relativePath(),
		coreHandle(handle),
		setAttributes(input),
	)
	if errno == 0 {
		fillFuseAttributes(&out.Attr, attributes)
	}
	return errno
}

func (n *Node) Setxattr(
	ctx context.Context,
	name string,
	data []byte,
	flags uint32,
) syscall.Errno {
	return n.fileSystem.SetExtendedAttribute(
		requestContext(ctx),
		n.relativePath(),
		name,
		data,
		flags,
	)
}

func (n *Node) Statfs(
	ctx context.Context,
	out *fuse.StatfsOut,
) syscall.Errno {
	statistics, errno := n.fileSystem.Statistics(requestContext(ctx))
	if errno != 0 {
		return errno
	}
	out.Blocks = statistics.TotalBlocks
	out.Bfree = statistics.FreeBlocks
	out.Bavail = statistics.AvailableBlocks
	out.Files = statistics.TotalFiles
	out.Ffree = statistics.FreeFiles
	out.Bsize = uint32(statistics.IOSize)
	out.Frsize = uint32(statistics.BlockSize)
	out.NameLen = 255
	return 0
}

func stableAttributes(attributes fsapi.Attributes) fs.StableAttr {
	return fs.StableAttr{
		Mode: fuseMode(attributes.Type, attributes.Mode),
		Ino:  attributes.Inode,
	}
}

func fuseMode(itemType fsapi.ItemType, permissions uint32) uint32 {
	mode := permissions & 0o7777
	switch itemType {
	case fsapi.TypeDirectory:
		return fuse.S_IFDIR | mode
	case fsapi.TypeSymlink:
		return fuse.S_IFLNK | mode
	default:
		return fuse.S_IFREG | mode
	}
}

func fillFuseAttributes(out *fuse.Attr, attributes fsapi.Attributes) {
	out.Ino = attributes.Inode
	out.Size = attributes.Size
	out.Blocks = attributes.Blocks
	out.Mode = fuseMode(attributes.Type, attributes.Mode)
	out.Nlink = attributes.LinkCount
	out.Owner.Uid = attributes.UID
	out.Owner.Gid = attributes.GID
	out.Blksize = 4096
	out.SetTimes(
		&attributes.AccessTime,
		&attributes.ModifyTime,
		&attributes.ChangeTime,
	)
}

func setAttributes(input *fuse.SetAttrIn) fsapi.SetAttributes {
	var attributes fsapi.SetAttributes
	if value, ok := input.GetSize(); ok {
		attributes.Size = &value
	}
	if value, ok := input.GetMode(); ok {
		attributes.Mode = &value
	}
	if value, ok := input.GetUID(); ok {
		attributes.UID = &value
	}
	if value, ok := input.GetGID(); ok {
		attributes.GID = &value
	}
	if value, ok := input.GetATime(); ok {
		attributes.AccessTime = &value
	}
	if value, ok := input.GetMTime(); ok {
		attributes.ModifyTime = &value
	}
	return attributes
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
