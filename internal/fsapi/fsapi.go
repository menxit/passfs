// Package fsapi defines the platform-neutral contract between the passfs
// encrypted storage engine and file-system frontends such as FUSE and FSKit.
package fsapi

import (
	"context"
	"syscall"
	"time"
)

// ItemType identifies the kind of an item exposed by a file system.
type ItemType uint8

const (
	TypeUnknown ItemType = iota
	TypeFile
	TypeDirectory
	TypeSymlink
)

// Caller describes the process on whose behalf an adapter is performing an
// operation. A zero PID means that the platform did not expose the caller.
type Caller struct {
	PID uint32
}

type callerContextKey struct{}

// WithCaller attaches adapter-provided caller information to a request.
func WithCaller(ctx context.Context, caller Caller) context.Context {
	return context.WithValue(ctx, callerContextKey{}, caller)
}

// CallerFromContext returns adapter-provided caller information.
func CallerFromContext(ctx context.Context) (Caller, bool) {
	caller, ok := ctx.Value(callerContextKey{}).(Caller)
	return caller, ok
}

// Attributes contains the portable metadata exposed for an item.
type Attributes struct {
	Type        ItemType
	Inode       uint64
	ParentInode uint64
	Size        uint64
	Blocks      uint64
	Mode        uint32
	UID         uint32
	GID         uint32
	LinkCount   uint32
	AccessTime  time.Time
	ChangeTime  time.Time
	ModifyTime  time.Time
	BirthTime   time.Time
}

// SetAttributes contains only the metadata fields requested by the caller.
type SetAttributes struct {
	Size       *uint64
	Mode       *uint32
	UID        *uint32
	GID        *uint32
	AccessTime *time.Time
	ModifyTime *time.Time
}

// Entry is an item returned by a lookup or create operation.
type Entry struct {
	Attributes Attributes
}

// DirectoryEntry is one item returned while enumerating a directory.
type DirectoryEntry struct {
	Name       string
	Type       ItemType
	Inode      uint64
	Attributes Attributes
}

// Statistics describes capacity and inode information for a mounted volume.
type Statistics struct {
	BlockSize       uint64
	IOSize          uint64
	TotalBlocks     uint64
	AvailableBlocks uint64
	FreeBlocks      uint64
	TotalFiles      uint64
	FreeFiles       uint64
}

// Handle is an open regular file. Implementations must be safe for the access
// patterns permitted by the adapter that owns the handle.
type Handle interface {
	Read(context.Context, []byte, int64) (int, syscall.Errno)
	Write(context.Context, []byte, int64) (int, syscall.Errno)
	Flush(context.Context) syscall.Errno
	Close(context.Context) syscall.Errno
	Attributes(context.Context) (Attributes, syscall.Errno)
	SetAttributes(context.Context, SetAttributes) (Attributes, syscall.Errno)
}

// FileSystem is the adapter-facing view of a passfs volume. Paths are clean,
// root-relative paths; the empty string identifies the root directory.
type FileSystem interface {
	Lookup(context.Context, string) (Entry, syscall.Errno)
	ReadDirectory(context.Context, string) ([]DirectoryEntry, syscall.Errno)
	GetAttributes(context.Context, string, Handle) (Attributes, syscall.Errno)
	Open(context.Context, string, uint32) (Handle, syscall.Errno)
	Create(context.Context, string, string, uint32, uint32) (Entry, Handle, syscall.Errno)
	MakeDirectory(context.Context, string, string, uint32) (Entry, syscall.Errno)
	Unlink(context.Context, string, string) syscall.Errno
	RemoveDirectory(context.Context, string, string) syscall.Errno
	Rename(context.Context, string, string, string, string, uint32) syscall.Errno
	SetAttributes(context.Context, string, Handle, SetAttributes) (Attributes, syscall.Errno)
	SetExtendedAttribute(context.Context, string, string, []byte, uint32) syscall.Errno
	Statistics(context.Context) (Statistics, syscall.Errno)
}
