//go:build linux

package passfs

import "testing"

func TestMountInfoPathMatchesDoesNotTraverseUnrelatedMount(t *testing.T) {
	matches, err := mountInfoPathMatches(
		"/run/docker/netns",
		"/home/federico/.config/passfs/mnt",
	)
	if err != nil {
		t.Fatal(err)
	}
	if matches {
		t.Fatal("unrelated Docker mount matched the passfs mount point")
	}
}

func TestMountInfoPathMatchesDecodesEscapedPath(t *testing.T) {
	matches, err := mountInfoPathMatches(
		"/home/federico/passfs\\040mount",
		"/home/federico/passfs mount",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Fatal("escaped mountinfo path did not match")
	}
}
