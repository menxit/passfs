package fuseadapter

import (
	"context"
	"syscall"
	"testing"

	"passfs/internal/fsapi"
)

type countHandle struct {
	readCount  int
	writeCount int
}

func (handle *countHandle) Read(
	context.Context,
	[]byte,
	int64,
) (int, syscall.Errno) {
	return handle.readCount, 0
}

func (handle *countHandle) Write(
	context.Context,
	[]byte,
	int64,
) (int, syscall.Errno) {
	return handle.writeCount, 0
}

func (*countHandle) Flush(context.Context) syscall.Errno {
	return 0
}

func (*countHandle) Close(context.Context) syscall.Errno {
	return 0
}

func (*countHandle) Attributes(
	context.Context,
) (fsapi.Attributes, syscall.Errno) {
	return fsapi.Attributes{}, 0
}

func (*countHandle) SetAttributes(
	context.Context,
	fsapi.SetAttributes,
) (fsapi.Attributes, syscall.Errno) {
	return fsapi.Attributes{}, 0
}

func TestFileHandleRejectsInvalidReadCount(t *testing.T) {
	handle := &FileHandle{
		handle: &countHandle{readCount: 5},
	}
	if _, errno := handle.Read(context.Background(), make([]byte, 4), 0); errno != syscall.EIO {
		t.Fatalf("Read errno = %v, want EIO", errno)
	}
}

func TestFileHandleRejectsInvalidWriteCount(t *testing.T) {
	handle := &FileHandle{
		handle: &countHandle{writeCount: 5},
	}
	if _, errno := handle.Write(context.Background(), make([]byte, 4), 0); errno != syscall.EIO {
		t.Fatalf("Write errno = %v, want EIO", errno)
	}
}
