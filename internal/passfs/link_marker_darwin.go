//go:build darwin

package passfs

const (
	linkMarkerName           = "com.menxit.passfs.link-target"
	editSessionMarkerName    = "com.menxit.passfs.edit-session"
	encryptSessionMarkerName = "com.menxit.passfs.encrypt-session"
)
