//go:build darwin && !cgo

package passfs

import "errors"

func validateSignedPassFSProcess(int, string) error {
	return errors.New("PassFS authorization peer verification requires a signed macOS build")
}
