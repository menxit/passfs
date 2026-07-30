//go:build darwin

package main

import (
	"os"
	"syscall"
	"time"
)

func scanFileLastOpened(info os.FileInfo) time.Time {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return info.ModTime()
	}
	return time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
}
