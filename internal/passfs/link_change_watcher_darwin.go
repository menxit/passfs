//go:build darwin

package passfs

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type darwinLinkChangeWatcher struct {
	kqueue int
	files  []int
	event  chan struct{}
	err    chan error
	done   chan struct{}
	once   sync.Once
}

func newLinkChangeWatcher(paths []string) (linkChangeWatcher, error) {
	kqueue, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	watcher := &darwinLinkChangeWatcher{
		kqueue: kqueue,
		event:  make(chan struct{}, 1),
		err:    make(chan error, 1),
		done:   make(chan struct{}),
	}
	changes := make([]unix.Kevent_t, 0, len(paths))
	for _, path := range uniqueExistingDirectories(paths) {
		fd, openErr := unix.Open(path, unix.O_EVTONLY|unix.O_CLOEXEC, 0)
		if openErr != nil {
			watcher.close()
			return nil, openErr
		}
		watcher.files = append(watcher.files, fd)
		changes = append(changes, unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_VNODE,
			Flags:  unix.EV_ADD | unix.EV_CLEAR,
			Fflags: unix.NOTE_WRITE | unix.NOTE_DELETE | unix.NOTE_EXTEND |
				unix.NOTE_LINK | unix.NOTE_RENAME |
				unix.NOTE_REVOKE,
		})
	}
	if len(changes) == 0 {
		watcher.close()
		return nil, os.ErrNotExist
	}
	if _, err := unix.Kevent(kqueue, changes, nil, nil); err != nil {
		watcher.close()
		return nil, err
	}
	go watcher.run()
	return watcher, nil
}

func (watcher *darwinLinkChangeWatcher) run() {
	events := make([]unix.Kevent_t, 8)
	for {
		count, err := unix.Kevent(watcher.kqueue, nil, events, nil)
		if err != nil {
			select {
			case <-watcher.done:
				return
			default:
			}
			if !errors.Is(err, unix.EINTR) {
				select {
				case watcher.err <- err:
				default:
				}
				return
			}
			continue
		}
		if count > 0 {
			select {
			case watcher.event <- struct{}{}:
			default:
			}
		}
	}
}

func (watcher *darwinLinkChangeWatcher) events() <-chan struct{} {
	return watcher.event
}

func (watcher *darwinLinkChangeWatcher) errors() <-chan error {
	return watcher.err
}

func (watcher *darwinLinkChangeWatcher) close() error {
	var result error
	watcher.once.Do(func() {
		close(watcher.done)
		for _, fd := range watcher.files {
			result = errors.Join(result, unix.Close(fd))
		}
		result = errors.Join(result, unix.Close(watcher.kqueue))
	})
	return result
}
