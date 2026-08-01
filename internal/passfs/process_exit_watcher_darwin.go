//go:build darwin

package passfs

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

func watchProcessExit(pid uint32) (<-chan struct{}, func(), error) {
	kqueue, err := unix.Kqueue()
	if err != nil {
		return nil, nil, err
	}
	event := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(kqueue, []unix.Kevent_t{event}, nil, nil); err != nil {
		_ = unix.Close(kqueue)
		return nil, nil, err
	}

	exited := make(chan struct{})
	var closeEvent sync.Once
	closeExited := func() { closeEvent.Do(func() { close(exited) }) }
	go func() {
		events := make([]unix.Kevent_t, 1)
		for {
			_, waitErr := unix.Kevent(kqueue, nil, events, nil)
			if errors.Is(waitErr, unix.EINTR) {
				continue
			}
			if !errors.Is(waitErr, unix.EBADF) {
				closeExited()
			}
			return
		}
	}()
	var closeQueue sync.Once
	cancel := func() {
		closeQueue.Do(func() { _ = unix.Close(kqueue) })
	}
	return exited, cancel, nil
}
