package passfs

// BeginEncryptSession authorizes one CLI process to encrypt multiple files
// through the mounted filesystem with one identity prompt.
func BeginEncryptSession(mountPoint string) (string, error) {
	return beginControlSession(
		mountPoint,
		encryptSessionMarkerName,
		"encrypt session",
	)
}

// EndEncryptSession removes the in-memory authorization created by
// BeginEncryptSession.
func EndEncryptSession(mountPoint, token string) error {
	return endControlSession(mountPoint, encryptSessionMarkerName, token)
}
