//go:build darwin && cgo

package passfs

/*
#cgo LDFLAGS: -framework AppKit -framework Foundation

#include <stdlib.h>

typedef struct passfs_system_sleep_watcher passfs_system_sleep_watcher;

passfs_system_sleep_watcher *passfs_system_sleep_watcher_create(
	int *read_file_descriptor,
	char **error_message
);
void passfs_system_sleep_watcher_close(
	passfs_system_sleep_watcher *watcher
);
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"unsafe"
)

// SystemSleepMonitor clears all in-memory authorization state immediately
// before sleep and again after wake as a defensive fallback.
type SystemSleepMonitor struct {
	events     io.ReadCloser
	stopNative func()
	done       chan struct{}
	closed     sync.Once
}

func NewSystemSleepMonitor(volume *Volume) (*SystemSleepMonitor, error) {
	if volume == nil {
		return nil, errors.New("system sleep monitor requires a volume")
	}
	var readFileDescriptor C.int
	var errorMessage *C.char
	watcher := C.passfs_system_sleep_watcher_create(
		&readFileDescriptor,
		&errorMessage,
	)
	if errorMessage != nil {
		defer C.free(unsafe.Pointer(errorMessage))
	}
	if watcher == nil || readFileDescriptor < 0 {
		if errorMessage != nil {
			return nil, errors.New(C.GoString(errorMessage))
		}
		return nil, errors.New("could not start the system sleep watcher")
	}
	events := os.NewFile(
		uintptr(readFileDescriptor),
		"passfs-system-sleep-events",
	)
	if events == nil {
		C.passfs_system_sleep_watcher_close(watcher)
		return nil, errors.New("could not open the system sleep event channel")
	}
	return newSystemSleepMonitor(volume, events, func() {
		C.passfs_system_sleep_watcher_close(watcher)
	}), nil
}

func newSystemSleepMonitor(
	volume *Volume,
	events io.ReadCloser,
	stopNative func(),
) *SystemSleepMonitor {
	monitor := &SystemSleepMonitor{
		events:     events,
		stopNative: stopNative,
		done:       make(chan struct{}),
	}
	go monitor.run(volume)
	return monitor
}

func (monitor *SystemSleepMonitor) run(volume *Volume) {
	defer close(monitor.done)
	events := make([]byte, 16)
	for {
		count, err := monitor.events.Read(events)
		if count > 0 {
			volume.Lock()
		}
		if err != nil {
			return
		}
	}
}

func (monitor *SystemSleepMonitor) Close() error {
	if monitor == nil {
		return nil
	}
	var closeErr error
	monitor.closed.Do(func() {
		monitor.stopNative()
		<-monitor.done
		if err := monitor.events.Close(); err != nil &&
			!errors.Is(err, os.ErrClosed) {
			closeErr = fmt.Errorf("close system sleep event channel: %w", err)
		}
	})
	return closeErr
}
