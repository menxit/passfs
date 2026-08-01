#!/bin/sh

passfs_load_console_user()
{
	passfs_console_user=$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)
	case "$passfs_console_user" in
		"" | root | loginwindow | _mbsetupuser)
			return 1
			;;
	esac

	passfs_user_id=$(/usr/bin/id -u "$passfs_console_user" 2>/dev/null || true)
	passfs_user_home=$(
		/usr/bin/dscl . -read "/Users/$passfs_console_user" NFSHomeDirectory \
			2>/dev/null |
			/usr/bin/sed 's/^NFSHomeDirectory: //'
	)
	[ -n "$passfs_user_id" ] && [ -n "$passfs_user_home" ]
}

passfs_run_as_user()
{
	/bin/launchctl asuser "$passfs_user_id" \
		/usr/bin/sudo -H -u "$passfs_console_user" "$@"
}

passfs_mount_info()
{
	mount_point=$1
	/sbin/mount | /usr/bin/awk -v target="$mount_point" '
		{
			marker = " on " target " ("
			position = index($0, marker)
		}
		position > 0 {
			details = substr($0, position + length(marker))
			separator = index(details, ",")
			if (separator == 0) {
				separator = index(details, ")")
			}
			if (separator > 1) {
				filesystem = substr(details, 1, separator - 1)
				source = substr($0, 1, position - 1)
				print filesystem "\t" source
			}
			exit
		}
	'
}

passfs_mount_info_is_passfs()
{
	mount_info=$1
	tab='	'
	filesystem=${mount_info%%"$tab"*}
	source=${mount_info#*"$tab"}
	case "$filesystem" in
	passfs)
		return 0
		;;
	*fuse* | *FUSE*)
		[ "$source" = passfs ]
		return
		;;
	esac
	return 1
}

# Stop a mount without asking the installed CLI to parse the settings. This is
# needed when an upgrade follows a development build or another newer build:
# the older installed CLI may reject the settings version before it can stop
# its LaunchAgent. Every mutating command still runs as the console user, and
# the mount is touched only after its mount-table entry identifies PassFS.
passfs_stop_existing_mount()
{
	config=$1
	mount_point=$(
		passfs_run_as_user /usr/bin/plutil \
			-extract mountPoint raw -o - "$config" 2>/dev/null
	) || return 1
	newline='
'
	case "$mount_point" in
	"" | / | *"$newline"*)
		return 1
		;;
	/*)
		;;
	*)
		return 1
		;;
	esac

	mount_info=$(passfs_mount_info "$mount_point")
	if [ -n "$mount_info" ] &&
		! passfs_mount_info_is_passfs "$mount_info"; then
		return 1
	fi

	# bootout also prevents KeepAlive from immediately recreating the mount.
	passfs_run_as_user /bin/launchctl bootout \
		"gui/$passfs_user_id/com.menxit.passfs" \
		>/dev/null 2>&1 || true
	passfs_run_as_user /bin/rm -f \
		"$passfs_user_home/Library/LaunchAgents/com.menxit.passfs.plist" \
		>/dev/null 2>&1 || return 1

	# Re-read the mount table after stopping launchd so a path that changed
	# underneath the installer is never unmounted based on stale information.
	mount_info=$(passfs_mount_info "$mount_point")
	if [ -z "$mount_info" ]; then
		return 0
	fi
	if ! passfs_mount_info_is_passfs "$mount_info"; then
		return 1
	fi

	if ! passfs_run_as_user /sbin/umount "$mount_point" \
		>/dev/null 2>&1; then
		passfs_run_as_user /sbin/umount -f "$mount_point" \
			>/dev/null 2>&1 || return 1
	fi

	attempt=0
	while [ -n "$(passfs_mount_info "$mount_point")" ]; do
		if [ "$attempt" -ge 50 ]; then
			return 1
		fi
		/bin/sleep 0.1
		attempt=$((attempt + 1))
	done
	return 0
}
