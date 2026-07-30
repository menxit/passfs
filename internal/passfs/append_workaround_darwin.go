//go:build darwin

package passfs

// macFUSE does not include O_APPEND in OPEN requests and can submit concurrent
// direct writes for one descriptor with the same end-of-file offset. Preserve
// both writes when the kernel repeats the last observed sequential end.
const concurrentAppendWorkaround = true
