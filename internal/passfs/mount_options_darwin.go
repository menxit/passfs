//go:build darwin

package passfs

func PlatformMountOptions() []string {
	return []string{
		"default_permissions",
		"local",
		"volname=passfs",
		"noappledouble",
	}
}
