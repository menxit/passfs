//go:build darwin

package passfs

import (
	"golang.org/x/sys/unix"
)

func platformProcessName(pid uint32) string {
	process, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return ""
	}
	return unix.ByteSliceToString(process.Proc.P_comm[:])
}

func platformProcessID(pid uint32) uint32 {
	return pid
}

func platformParentProcessID(pid uint32) uint32 {
	process, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return 0
	}
	if process.Eproc.Ppid <= 0 {
		return 0
	}
	return uint32(process.Eproc.Ppid)
}
