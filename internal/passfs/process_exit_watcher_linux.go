//go:build linux

package passfs

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

func watchProcessExit(pid uint32) (<-chan struct{}, func(), error) {
	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return nil, nil, err
	}
	wake := [2]int{}
	if err := unix.Pipe2(wake[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(pidfd)
		return nil, nil, err
	}
	exited := make(chan struct{})
	var closeEvent sync.Once
	closeExited := func() { closeEvent.Do(func() { close(exited) }) }
	var closeFiles sync.Once
	cleanup := func() {
		closeFiles.Do(func() {
			_ = unix.Close(pidfd)
			_ = unix.Close(wake[0])
			_ = unix.Close(wake[1])
		})
	}
	go func() {
		defer cleanup()
		poll := []unix.PollFd{
			{Fd: int32(pidfd), Events: unix.POLLIN},
			{Fd: int32(wake[0]), Events: unix.POLLIN},
		}
		for {
			_, waitErr := unix.Poll(poll, -1)
			if errors.Is(waitErr, unix.EINTR) {
				continue
			}
			if waitErr == nil && poll[0].Revents != 0 {
				closeExited()
			} else if waitErr != nil {
				closeExited()
			}
			return
		}
	}()
	var cancelOnce sync.Once
	cancel := func() {
		cancelOnce.Do(func() { _, _ = unix.Write(wake[1], []byte{1}) })
	}
	return exited, cancel, nil
}
