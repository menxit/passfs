package passfs

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"passfs/internal/fsapi"
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
	accessedAt := time.Now().UnixNano()
	if writable && flags&syscall.O_TRUNC != 0 {
		if err := v.authorize(ctx, relative, "truncate"); err != nil {
			return nil, err
		}
		data = make([]byte, 0)
		meta.Size = 0
		meta.MTime = time.Now().UnixNano()
		meta.ATime = accessedAt
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
		meta.ATime = accessedAt
		if err := v.setFileMeta(relative, meta); err != nil {
			wipe(data)
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
		ATime: time.Now().UnixNano(),
	}
	var data []byte
	var dirty bool

	if exists {
		meta = v.fileMeta(relative, info)
		meta.ATime = time.Now().UnixNano()
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
			if err := v.setFileMeta(relative, meta); err != nil {
				wipe(data)
				return nil, err
			}
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
	_ context.Context,
	destination []byte,
	offset int64,
) (int, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return 0, syscall.EBADF
	}
	if offset < 0 {
		return 0, syscall.EINVAL
	}
	if offset >= int64(len(f.data)) {
		return 0, 0
	}
	return copy(destination, f.data[offset:]), 0
}

func (f *OpenFile) Write(
	_ context.Context,
	data []byte,
	offset int64,
) (int, syscall.Errno) {
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
	return len(data), 0
}

func (f *OpenFile) Flush(_ context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return syscall.EBADF
	}
	return errnoFromError(f.flushLocked())
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

func (f *OpenFile) Close(_ context.Context) syscall.Errno {
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

func (f *OpenFile) Attributes(
	_ context.Context,
) (fsapi.Attributes, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return fsapi.Attributes{}, syscall.EBADF
	}
	meta := f.meta
	meta.Size = uint64(len(f.data))
	return fileAttributes(
		meta,
		f.volume.uid,
		f.volume.gid,
		stableInode(f.relative),
	), 0
}

func (f *OpenFile) SetAttributes(
	_ context.Context,
	input fsapi.SetAttributes,
) (fsapi.Attributes, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return fsapi.Attributes{}, syscall.EBADF
	}
	if input.UID != nil && *input.UID != f.volume.uid {
		return fsapi.Attributes{}, syscall.EPERM
	}
	if input.GID != nil && *input.GID != f.volume.gid {
		return fsapi.Attributes{}, syscall.EPERM
	}
	if input.Size != nil {
		if !f.writable {
			return fsapi.Attributes{}, syscall.EBADF
		}
		size := *input.Size
		if size > uint64(f.volume.maxFileSize) {
			return fsapi.Attributes{}, syscall.EFBIG
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
	if input.Mode != nil {
		f.meta.Mode = *input.Mode & 0o777
		f.dirty = true
	}
	if input.ModifyTime != nil {
		f.meta.MTime = input.ModifyTime.UnixNano()
		f.dirty = true
	}
	if input.AccessTime != nil {
		f.meta.ATime = input.AccessTime.UnixNano()
		f.dirty = true
	}
	meta := f.meta
	meta.Size = uint64(len(f.data))
	return fileAttributes(
		meta,
		f.volume.uid,
		f.volume.gid,
		stableInode(f.relative),
	), 0
}

var _ fsapi.Handle = (*OpenFile)(nil)
