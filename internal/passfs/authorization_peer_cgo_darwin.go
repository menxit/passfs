//go:build darwin && cgo

package passfs

/*
#cgo LDFLAGS: -framework Foundation -framework Security

#include <stdlib.h>

int passfs_validate_signed_process(
	int pid,
	const char *expected_identifier,
	char **error_message
);
*/
import "C"

import (
	"errors"
	"unsafe"
)

func validateSignedPassFSProcess(pid int, expectedIdentifier string) error {
	identifier := C.CString(expectedIdentifier)
	defer C.free(unsafe.Pointer(identifier))
	var errorMessage *C.char
	status := C.passfs_validate_signed_process(
		C.int(pid),
		identifier,
		&errorMessage,
	)
	if errorMessage != nil {
		defer C.free(unsafe.Pointer(errorMessage))
	}
	if status == 0 {
		return nil
	}
	if errorMessage == nil {
		return errors.New("PassFS authorization peer has an invalid code signature")
	}
	return errors.New(C.GoString(errorMessage))
}
