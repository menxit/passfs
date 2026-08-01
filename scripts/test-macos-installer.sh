#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
common="$project_root/packaging/macos/installer-scripts/common.sh"
preinstall="$project_root/packaging/macos/installer-scripts/preinstall"
postinstall="$project_root/packaging/macos/installer-scripts/postinstall"

/bin/sh -n "$common"
/bin/sh -n "$preinstall"
/bin/sh -n "$postinstall"

if ! grep -Fq 'passfs_stop_existing_mount "$config"' "$preinstall"; then
	echo "preinstall does not fall back when the installed CLI rejects newer settings" >&2
	exit 1
fi

# Exercise the fallback with a version 3 settings file and a simulated older
# CLI environment. Command execution is replaced after sourcing common.sh;
# production uses only the absolute macOS command paths in that file.
# shellcheck source=../packaging/macos/installer-scripts/common.sh
. "$common"

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/passfs-installer-test.XXXXXX")
cleanup()
{
	rm -rf "$test_directory"
}
trap cleanup EXIT HUP INT TERM

config="$test_directory/config.json"
printf '%s\n' \
	'{"version":3,"mountPoint":"/Users/test/.passfs/mnt","vault":"/Users/test/.passfs/vault"}' \
	>"$config"

passfs_console_user=test
passfs_user_id=501
passfs_user_home=/Users/test
mock_mount_point=/Users/test/.passfs/mnt
mock_mounted=true
command_log="$test_directory/commands"

passfs_run_as_user()
{
	case "$1" in
	/usr/bin/plutil)
		printf '%s\n' "$mock_mount_point"
		;;
	/sbin/umount)
		mock_mounted=false
		printf '%s\n' "$*" >>"$command_log"
		;;
	*)
		printf '%s\n' "$*" >>"$command_log"
		;;
	esac
}

passfs_mount_info()
{
	if [ "$mock_mounted" = true ]; then
		printf 'passfs\t%s\n' "file:///Users/test/.passfs/vault/"
	fi
}

passfs_stop_existing_mount "$config"
if [ "$mock_mounted" != false ]; then
	echo "installer fallback did not unmount PassFS" >&2
	exit 1
fi
for expected in \
	"/bin/launchctl bootout gui/501/com.menxit.passfs" \
	"/bin/rm -f /Users/test/Library/LaunchAgents/com.menxit.passfs.plist" \
	"/sbin/umount /Users/test/.passfs/mnt"; do
	if ! grep -Fq "$expected" "$command_log"; then
		echo "installer fallback did not execute: $expected" >&2
		exit 1
	fi
done

# Never unmount a different filesystem if the settings path was repurposed.
mock_mounted=true
: >"$command_log"
passfs_mount_info()
{
	printf 'apfs\t%s\n' /dev/disk9s1
}
if passfs_stop_existing_mount "$config"; then
	echo "installer fallback accepted a non-PassFS mount" >&2
	exit 1
fi
if [ -s "$command_log" ]; then
	echo "installer fallback mutated state for a non-PassFS mount" >&2
	exit 1
fi

# Reject root and relative mount points before attempting any mutation.
for unsafe_mount_point in / relative/path; do
	mock_mount_point=$unsafe_mount_point
	: >"$command_log"
	if passfs_stop_existing_mount "$config"; then
		echo "installer fallback accepted unsafe mount point: $unsafe_mount_point" >&2
		exit 1
	fi
	if [ -s "$command_log" ]; then
		echo "installer fallback mutated state for unsafe mount point: $unsafe_mount_point" >&2
		exit 1
	fi
done

printf 'macOS installer checks passed\n'
