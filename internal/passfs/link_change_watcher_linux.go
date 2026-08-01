//go:build linux

package passfs

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type linuxLinkChangeWatcher struct {
	inotify int
	wake    [2]int
	event   chan struct{}
	err     chan error
	done    chan struct{}
	once    sync.Once
}

func newLinkChangeWatcher(paths []string) (linkChangeWatcher, error) {
	inotify, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	watcher := &linuxLinkChangeWatcher{
		inotify: inotify,
		event:   make(chan struct{}, 1),
		err:     make(chan error, 1),
		done:    make(chan struct{}),
	}
	if err := unix.Pipe2(watcher.wake[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(inotify)
		return nil, err
	}
	count := 0
	for _, path := range uniqueExistingDirectories(paths) {
		_, watchErr := unix.InotifyAddWatch(
			inotify,
			path,
			unix.IN_CLOSE_WRITE|unix.IN_CREATE|unix.IN_DELETE|
				unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_MOVED_FROM|
				unix.IN_MOVED_TO,
		)
		if watchErr != nil {
			watcher.close()
			return nil, watchErr
		}
		count++
	}
	if count == 0 {
		watcher.close()
		return nil, os.ErrNotExist
	}
	go watcher.run()
	return watcher, nil
}

func (watcher *linuxLinkChangeWatcher) run() {
	poll := []unix.PollFd{
		{Fd: int32(watcher.inotify), Events: unix.POLLIN},
		{Fd: int32(watcher.wake[0]), Events: unix.POLLIN},
	}
	buffer := make([]byte, 16*1024)
	for {
		_, err := unix.Poll(poll, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			select {
			case watcher.err <- err:
			default:
			}
			return
		}
		if poll[1].Revents != 0 {
			return
		}
		if poll[0].Revents == 0 {
			continue
		}
		if _, err := unix.Read(watcher.inotify, buffer); err != nil &&
			!errors.Is(err, unix.EAGAIN) {
			select {
			case watcher.err <- err:
			default:
			}
			return
		}
		select {
		case watcher.event <- struct{}{}:
		default:
		}
	}
}

func (watcher *linuxLinkChangeWatcher) events() <-chan struct{} {
	return watcher.event
}

func (watcher *linuxLinkChangeWatcher) errors() <-chan error {
	return watcher.err
}

func (watcher *linuxLinkChangeWatcher) close() error {
	var result error
	watcher.once.Do(func() {
		close(watcher.done)
		_, _ = unix.Write(watcher.wake[1], []byte{1})
		result = errors.Join(result, unix.Close(watcher.inotify))
		result = errors.Join(result, unix.Close(watcher.wake[0]))
		result = errors.Join(result, unix.Close(watcher.wake[1]))
	})
	return result
}
