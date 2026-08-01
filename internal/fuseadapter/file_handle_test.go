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

func TestFileHandleRejectsInvalidCounts(t *testing.T) {
	tests := []struct {
		name string
		core *countHandle
		call func(*FileHandle) syscall.Errno
	}{
		{
			name: "read",
			core: &countHandle{readCount: 5},
			call: func(handle *FileHandle) syscall.Errno {
				_, errno := handle.Read(context.Background(), make([]byte, 4), 0)
				return errno
			},
		},
		{
			name: "write",
			core: &countHandle{writeCount: 5},
			call: func(handle *FileHandle) syscall.Errno {
				_, errno := handle.Write(context.Background(), make([]byte, 4), 0)
				return errno
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handle := &FileHandle{handle: test.core}
			if errno := test.call(handle); errno != syscall.EIO {
				t.Fatalf("errno = %v, want EIO", errno)
			}
		})
	}
}
