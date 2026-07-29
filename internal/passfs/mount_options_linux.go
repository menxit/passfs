//go:build linux

package passfs

func PlatformMountOptions() []string {
	return []string{"default_permissions"}
}
