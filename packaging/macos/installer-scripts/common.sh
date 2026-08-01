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
