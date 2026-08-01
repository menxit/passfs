//go:build darwin

package main

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

type mountLifecycleWatcher struct {
	kqueue int
	file   int
	change chan error
	done   chan struct{}
	once   sync.Once
}

func newMountLifecycleWatcher(path string) (*mountLifecycleWatcher, error) {
	file, err := unix.Open(path, unix.O_EVTONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	kqueue, err := unix.Kqueue()
	if err != nil {
		_ = unix.Close(file)
		return nil, err
	}
	watcher := &mountLifecycleWatcher{
		kqueue: kqueue,
		file:   file,
		change: make(chan error, 1),
		done:   make(chan struct{}),
	}
	change := []unix.Kevent_t{{
		Ident:  uint64(file),
		Filter: unix.EVFILT_VNODE,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
		Fflags: unix.NOTE_DELETE | unix.NOTE_RENAME | unix.NOTE_REVOKE,
	}}
	if _, err := unix.Kevent(kqueue, change, nil, nil); err != nil {
		watcher.close()
		return nil, err
	}
	go watcher.run()
	return watcher, nil
}

func (watcher *mountLifecycleWatcher) run() {
	events := make([]unix.Kevent_t, 1)
	_, err := unix.Kevent(watcher.kqueue, nil, events, nil)
	select {
	case <-watcher.done:
		return
	default:
	}
	watcher.change <- err
}

func (watcher *mountLifecycleWatcher) close() error {
	var result error
	watcher.once.Do(func() {
		close(watcher.done)
		result = errors.Join(
			unix.Close(watcher.file),
			unix.Close(watcher.kqueue),
		)
	})
	return result
}
