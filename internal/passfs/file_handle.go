package passfs

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type OpenFile struct {
	mu                    sync.Mutex
	pendingWrites         atomic.Int32
	appendCandidateOffset int64
	volume                *Volume
	relative              string
	data                  []byte
	meta                  FileMeta
	writable              bool
	append                bool
	dirty                 bool
	released              bool
	unlock                func()
	unlockPath            func()
}

func (v *Volume) openFile(ctx context.Context, relative string, flags uint32) (*OpenFile, error) {
	if err := validateRelativePath(relative); err != nil {
		return nil, err
	}
	accessMode := flags & syscall.O_ACCMODE
	writable := accessMode == syscall.O_WRONLY || accessMode == syscall.O_RDWR
	v.namespaceMu.RLock()
	success := false
	defer func() {
		if !success {
			v.namespaceMu.RUnlock()
		}
	}()
	unlockPath := v.acquirePathLock(relative, writable)
	pathLockHeld := true
	defer func() {
		if pathLockHeld {
			unlockPath()
		}
	}()

	isDirectory, info, err := v.virtualType(relative)
	if err != nil {
		return nil, err
	}
	if isDirectory {
		return nil, syscall.EISDIR
	}

	meta := v.fileMeta(relative, info)
	var data []byte
	if writable && flags&syscall.O_TRUNC != 0 {
		if err := v.authorize(ctx, relative, "truncate"); err != nil {
			return nil, err
		}
		data = make([]byte, 0)
		meta.Size = 0
		meta.MTime = time.Now().UnixNano()
	} else {
		operation := "read"
		if writable {
			operation = "read/write"
		}
		data, err = v.decryptFile(ctx, relative, operation)
		if err != nil {
			return nil, err
		}
		meta.Size = uint64(len(data))
	}

	handle := &OpenFile{
		volume:                v,
		relative:              relative,
		data:                  data,
		meta:                  meta,
		writable:              writable,
		append:                flags&syscall.O_APPEND != 0,
		dirty:                 writable && flags&syscall.O_TRUNC != 0,
		appendCandidateOffset: -1,
		unlockPath:            unlockPath,
	}
	pathLockHeld = false
	if writable {
		handle.unlock = v.namespaceMu.RUnlock
	} else {
		v.namespaceMu.RUnlock()
	}
	v.registerOpenHandle(handle, callerPID(ctx))
	success = true
	return handle, nil
}

func (v *Volume) createFile(
	ctx context.Context,
	relative string,
	flags uint32,
	mode uint32,
) (*OpenFile, error) {
	if err := validateRelativePath(relative); err != nil {
		return nil, err
	}
	v.namespaceMu.RLock()
	success := false
	defer func() {
		if !success {
			v.namespaceMu.RUnlock()
		}
	}()
	unlockPath := v.acquirePathLock(relative, true)
	pathLockHeld := true
	defer func() {
		if pathLockHeld {
			unlockPath()
		}
	}()

	isDirectory, info, lookupErr := v.virtualType(relative)
	exists := lookupErr == nil
	if exists && isDirectory {
		return nil, syscall.EISDIR
	}
	if lookupErr != nil && !errors.Is(lookupErr, os.ErrNotExist) {
		return nil, lookupErr
	}
	if exists && flags&syscall.O_EXCL != 0 {
		return nil, syscall.EEXIST
	}

	accessMode := flags & syscall.O_ACCMODE
	writable := accessMode == syscall.O_WRONLY || accessMode == syscall.O_RDWR
	meta := FileMeta{
		Mode:  mode & 0o777,
		MTime: time.Now().UnixNano(),
	}
	var data []byte
	var dirty bool

	if exists {
		meta = v.fileMeta(relative, info)
		if flags&syscall.O_TRUNC != 0 {
			if !writable {
				return nil, syscall.EACCES
			}
			if err := v.authorize(ctx, relative, "truncate"); err != nil {
				return nil, err
			}
			data = make([]byte, 0)
			meta.Size = 0
			meta.MTime = time.Now().UnixNano()
			dirty = true
		} else {
			operation := "read"
			if writable {
				operation = "read/write"
			}
			var err error
			data, err = v.decryptFile(ctx, relative, operation)
			if err != nil {
				return nil, err
			}
			meta.Size = uint64(len(data))
		}
	} else {
		if err := v.authorize(ctx, relative, "create"); err != nil {
			return nil, err
		}
		data = make([]byte, 0)
		if err := v.persistFile(relative, data, meta); err != nil {
			return nil, err
		}
	}

	handle := &OpenFile{
		volume:                v,
		relative:              relative,
		data:                  data,
		meta:                  meta,
		writable:              writable,
		append:                flags&syscall.O_APPEND != 0,
		dirty:                 dirty,
		appendCandidateOffset: -1,
		unlockPath:            unlockPath,
	}
	pathLockHeld = false
	if writable {
		handle.unlock = v.namespaceMu.RUnlock
	} else {
		v.namespaceMu.RUnlock()
	}
	v.registerOpenHandle(handle, callerPID(ctx))
	success = true
	return handle, nil
}

func (f *OpenFile) Read(
	ctx context.Context,
	destination []byte,
	offset int64,
) (fuse.ReadResult, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return nil, syscall.EBADF
	}
	if offset < 0 {
		return nil, syscall.EINVAL
	}
	if offset >= int64(len(f.data)) {
		return fuse.ReadResultData(destination[:0]), 0
	}
	count := copy(destination, f.data[offset:])
	return fuse.ReadResultData(destination[:count]), 0
}

func (f *OpenFile) Write(
	ctx context.Context,
	data []byte,
	offset int64,
) (uint32, syscall.Errno) {
	overlappingWrite := f.pendingWrites.Add(1) > 1
	defer f.pendingWrites.Add(-1)

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return 0, syscall.EBADF
	}
	if !f.writable {
		return 0, syscall.EBADF
	}
	if f.append {
		offset = int64(len(f.data))
	} else if concurrentAppendWorkaround {
		currentSize := int64(len(f.data))
		switch {
		case overlappingWrite &&
			offset == f.appendCandidateOffset &&
			offset < currentSize:
			offset = currentSize
		case offset == currentSize:
			f.appendCandidateOffset = offset
		default:
			f.appendCandidateOffset = -1
		}
	}
	if offset < 0 || offset > f.volume.maxFileSize {
		return 0, syscall.EFBIG
	}
	end := offset + int64(len(data))
	if end < offset || end > f.volume.maxFileSize {
		return 0, syscall.EFBIG
	}
	if end > int64(len(f.data)) {
		f.data = append(f.data, make([]byte, int(end)-len(f.data))...)
	}
	copy(f.data[int(offset):int(end)], data)
	f.meta.Size = uint64(len(f.data))
	f.meta.MTime = time.Now().UnixNano()
	f.dirty = true
	return uint32(len(data)), 0
}

func (f *OpenFile) Flush(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return syscall.EBADF
	}
	return errnoFromError(f.flushLocked())
}

func (f *OpenFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	return f.Flush(ctx)
}

func (f *OpenFile) flushLocked() error {
	if !f.dirty {
		return nil
	}
	if f.unlockPath == nil {
		unlockPath := f.volume.acquirePathLock(f.relative, true)
		defer unlockPath()
	}
	if err := f.volume.persistFile(f.relative, f.data, f.meta); err != nil {
		return err
	}
	f.meta.Size = uint64(len(f.data))
	f.dirty = false
	return nil
}

func (f *OpenFile) Release(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	if f.released {
		f.mu.Unlock()
		return 0
	}
	err := f.flushLocked()
	wipe(f.data)
	f.data = nil
	f.released = true
	unlock := f.unlock
	f.unlock = nil
	unlockPath := f.unlockPath
	f.unlockPath = nil
	f.mu.Unlock()

	f.volume.unregisterOpenHandle(f)
	if unlockPath != nil {
		unlockPath()
	}
	if unlock != nil {
		unlock()
	}
	return errnoFromError(err)
}

func (f *OpenFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return syscall.EBADF
	}
	meta := f.meta
	meta.Size = uint64(len(f.data))
	fillFileAttr(
		&out.Attr,
		meta,
		f.volume.uid,
		f.volume.gid,
		stableInode(f.relative),
	)
	return 0
}

func (f *OpenFile) Setattr(
	ctx context.Context,
	input *fuse.SetAttrIn,
	out *fuse.AttrOut,
) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return syscall.EBADF
	}
	if uid, ok := input.GetUID(); ok && uid != f.volume.uid {
		return syscall.EPERM
	}
	if gid, ok := input.GetGID(); ok && gid != f.volume.gid {
		return syscall.EPERM
	}
	if size, ok := input.GetSize(); ok {
		if !f.writable {
			return syscall.EBADF
		}
		if size > uint64(f.volume.maxFileSize) {
			return syscall.EFBIG
		}
		if size < uint64(len(f.data)) {
			wipe(f.data[size:])
			f.data = f.data[:size]
		} else if size > uint64(len(f.data)) {
			f.data = append(f.data, make([]byte, int(size)-len(f.data))...)
		}
		f.meta.Size = size
		f.meta.MTime = time.Now().UnixNano()
		f.dirty = true
	}
	if mode, ok := input.GetMode(); ok {
		f.meta.Mode = mode & 0o777
		f.dirty = true
	}
	if mtime, ok := input.GetMTime(); ok {
		f.meta.MTime = mtime.UnixNano()
		f.dirty = true
	}
	meta := f.meta
	meta.Size = uint64(len(f.data))
	fillFileAttr(
		&out.Attr,
		meta,
		f.volume.uid,
		f.volume.gid,
		stableInode(f.relative),
	)
	return 0
}

var (
	_ fs.FileReader    = (*OpenFile)(nil)
	_ fs.FileWriter    = (*OpenFile)(nil)
	_ fs.FileFlusher   = (*OpenFile)(nil)
	_ fs.FileFsyncer   = (*OpenFile)(nil)
	_ fs.FileReleaser  = (*OpenFile)(nil)
	_ fs.FileGetattrer = (*OpenFile)(nil)
	_ fs.FileSetattrer = (*OpenFile)(nil)
)
