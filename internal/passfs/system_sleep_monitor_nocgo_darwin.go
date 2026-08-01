//go:build darwin && !cgo

package passfs

import "errors"

type SystemSleepMonitor struct{}

func NewSystemSleepMonitor(*Volume) (*SystemSleepMonitor, error) {
	return nil, errors.New("system sleep monitoring requires a native macOS build")
}

func (*SystemSleepMonitor) Close() error {
	return nil
}
