package fuseadapter

import (
	"context"
	"syscall"

	"passfs/internal/fsapi"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// FileHandle adapts an fsapi.Handle to go-fuse's handle interfaces.
type FileHandle struct {
	handle fsapi.Handle
}

func coreHandle(handle fs.FileHandle) fsapi.Handle {
	if handle == nil {
		return nil
	}
	adapter, ok := handle.(*FileHandle)
	if !ok {
		return nil
	}
	return adapter.handle
}

func (f *FileHandle) Read(
	ctx context.Context,
	destination []byte,
	offset int64,
) (fuse.ReadResult, syscall.Errno) {
	count, errno := f.handle.Read(
		requestContext(ctx),
		destination,
		offset,
	)
	if errno != 0 {
		return nil, errno
	}
	if count < 0 || count > len(destination) {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(destination[:count]), 0
}

func (f *FileHandle) Write(
	ctx context.Context,
	data []byte,
	offset int64,
) (uint32, syscall.Errno) {
	count, errno := f.handle.Write(requestContext(ctx), data, offset)
	if errno == 0 && (count < 0 || count > len(data)) {
		return 0, syscall.EIO
	}
	return uint32(count), errno
}

func (f *FileHandle) Flush(ctx context.Context) syscall.Errno {
	return f.handle.Flush(requestContext(ctx))
}

func (f *FileHandle) Fsync(
	ctx context.Context,
	_ uint32,
) syscall.Errno {
	return f.handle.Flush(requestContext(ctx))
}

func (f *FileHandle) Release(ctx context.Context) syscall.Errno {
	return f.handle.Close(requestContext(ctx))
}

func (f *FileHandle) Getattr(
	ctx context.Context,
	out *fuse.AttrOut,
) syscall.Errno {
	attributes, errno := f.handle.Attributes(requestContext(ctx))
	if errno == 0 {
		fillFuseAttributes(&out.Attr, attributes)
	}
	return errno
}

func (f *FileHandle) Setattr(
	ctx context.Context,
	input *fuse.SetAttrIn,
	out *fuse.AttrOut,
) syscall.Errno {
	attributes, errno := f.handle.SetAttributes(
		requestContext(ctx),
		setAttributes(input),
	)
	if errno == 0 {
		fillFuseAttributes(&out.Attr, attributes)
	}
	return errno
}

var (
	_ fs.FileReader    = (*FileHandle)(nil)
	_ fs.FileWriter    = (*FileHandle)(nil)
	_ fs.FileFlusher   = (*FileHandle)(nil)
	_ fs.FileFsyncer   = (*FileHandle)(nil)
	_ fs.FileReleaser  = (*FileHandle)(nil)
	_ fs.FileGetattrer = (*FileHandle)(nil)
	_ fs.FileSetattrer = (*FileHandle)(nil)
)
