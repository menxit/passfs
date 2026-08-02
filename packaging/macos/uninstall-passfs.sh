#!/bin/sh

set -u

app_bundle_id="com.menxit.passfs"
extension_bundle_id="com.menxit.passfs.filesystem"
package_id="com.menxit.passfs.pkg"
launch_agent_label="com.menxit.passfs"
control_agent_label="com.menxit.passfs.control-agent"
app_group_identifier="3943PK2P39.com.menxit.passfs.shared"
purge_data=false
authorized=false
config_path=""

usage()
{
	cat <<'EOF'
Usage: uninstall-passfs.sh [--purge-data] [--config PATH]

Removes the installed PassFS application, command-line link, agents, FSKit
registration and enablement state, package receipt, preferences, sandbox
containers, and non-secret shared runtime state.

The PassFS vault under ~/.passfs is preserved by default. Use
--purge-data only when you also want to move that vault to the Trash.
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--purge-data)
		purge_data=true
		shift
		;;
	--config)
		if [ "$#" -lt 2 ] || [ -z "$2" ]; then
			echo "uninstall-passfs: --config requires a path" >&2
			exit 2
		fi
		config_path=$2
		shift 2
		;;
	--authorized)
		authorized=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "uninstall-passfs: unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

script_path=$(
	cd "$(dirname "$0")" 2>/dev/null &&
		pwd -P
)/$(basename "$0")

if [ "$(id -u)" -ne 0 ]; then
	if [ "$authorized" = true ]; then
		echo "uninstall-passfs: administrator authorization failed" >&2
		exit 1
	fi
	/usr/bin/osascript - "$script_path" "$purge_data" "$config_path" <<'APPLESCRIPT'
on run arguments
	set scriptPath to item 1 of arguments
	set purgeData to item 2 of arguments
	set configPath to item 3 of arguments
	set commandText to quoted form of scriptPath & " --authorized"
	if purgeData is "true" then
		set commandText to commandText & " --purge-data"
	end if
	if configPath is not "" then
		set commandText to commandText & " --config " & quoted form of configPath
	end if
	do shell script commandText with administrator privileges
end run
APPLESCRIPT
	exit $?
fi

console_user=$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)
case "$console_user" in
"" | root | loginwindow | _mbsetupuser)
	if [ -n "${SUDO_USER-}" ] && [ "$SUDO_USER" != "root" ]; then
		console_user=$SUDO_USER
	else
		echo "uninstall-passfs: no logged-in macOS user was found" >&2
		exit 1
	fi
	;;
esac

user_id=$(/usr/bin/id -u "$console_user" 2>/dev/null || true)
user_group=$(/usr/bin/id -gn "$console_user" 2>/dev/null || true)
user_home=$(
	/usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory \
		2>/dev/null |
		/usr/bin/sed 's/^NFSHomeDirectory: //'
)
if [ -z "$user_id" ] || [ -z "$user_group" ] ||
	[ -z "$user_home" ] || [ ! -d "$user_home" ]; then
	echo "uninstall-passfs: could not resolve the logged-in user" >&2
	exit 1
fi
if [ -z "$config_path" ]; then
	if [ -f "$user_home/.passfs/config.json" ]; then
		config_path="$user_home/.passfs/config.json"
	else
		config_path="$user_home/.config/passfs/config.json"
	fi
fi

run_as_user()
{
	/bin/launchctl asuser "$user_id" \
		/usr/bin/sudo -H -u "$console_user" "$@"
}

warn()
{
	printf 'uninstall-passfs: warning: %s\n' "$*" >&2
}

derived_bundle=$(
	cd "$(dirname "$script_path")/../.." 2>/dev/null &&
		pwd -P
) || derived_bundle=""
app_bundle=""
for candidate in \
	"$derived_bundle" \
	"/Applications/PassFS.app" \
	"$user_home/Applications/PassFS.app"; do
	if [ -z "$candidate" ] || [ ! -d "$candidate" ]; then
		continue
	fi
	case "$candidate" in
	"/Applications/PassFS.app" | "$user_home/Applications/PassFS.app")
		;;
	*)
		continue
		;;
	esac
	identifier=$(
		/usr/libexec/PlistBuddy \
			-c "Print :CFBundleIdentifier" \
			"$candidate/Contents/Info.plist" 2>/dev/null || true
	)
	if [ "$identifier" = "$app_bundle_id" ]; then
		app_bundle=$candidate
		break
	fi
done

cli_binary=""
control_service=""
extension_bundle=""
if [ -n "$app_bundle" ]; then
	control_service="$app_bundle/Contents/Helpers/PassFSControlService.app/Contents/MacOS/passfs-control-service"
	cli_binary="$app_bundle/Contents/Helpers/PassFSControlService.app/Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli"
	if [ ! -x "$cli_binary" ]; then
		cli_binary="$app_bundle/Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli"
	fi
	extension_bundle="$app_bundle/Contents/Extensions/PassFSFileSystem.appex"
fi

if [ -x "$cli_binary" ] && [ -f "$config_path" ]; then
	run_as_user "$cli_binary" unmount --config "$config_path" \
		>/dev/null 2>&1 ||
		warn "the filesystem could not be cleanly unmounted"
fi

if [ -x "$control_service" ]; then
	run_as_user "$control_service" unregister >/dev/null 2>&1 ||
		warn "the control agent could not be unregistered from Login Items"
fi

launch_agent="$user_home/Library/LaunchAgents/$launch_agent_label.plist"
/bin/launchctl bootout "gui/$user_id/$launch_agent_label" \
	>/dev/null 2>&1 || true
/bin/launchctl asuser "$user_id" \
	/usr/bin/sudo -H -u "$console_user" \
	/bin/launchctl remove "$launch_agent_label" \
	>/dev/null 2>&1 || true
/bin/launchctl asuser "$user_id" \
	/usr/bin/sudo -H -u "$console_user" \
	/bin/launchctl remove "$launch_agent_label.postinstall" \
	>/dev/null 2>&1 || true
/bin/launchctl bootout "gui/$user_id/$control_agent_label" \
	>/dev/null 2>&1 || true
/bin/launchctl asuser "$user_id" \
	/usr/bin/sudo -H -u "$console_user" \
	/bin/launchctl remove "$control_agent_label" \
	>/dev/null 2>&1 || true

if [ "$purge_data" = true ] &&
	[ -x "$cli_binary" ] &&
	[ -f "$config_path" ]; then
	run_as_user "$cli_binary" touchid disable --config "$config_path" \
		>/dev/null 2>&1 ||
		warn "the persisted Touch ID identity could not be removed"
fi

run_as_user /usr/bin/pkill -x PassFS >/dev/null 2>&1 || true
run_as_user /usr/bin/pkill -x PassFSMenu >/dev/null 2>&1 || true
run_as_user /usr/bin/pkill -x PassFSFileSystem >/dev/null 2>&1 || true
run_as_user /usr/bin/pkill -x passfs-cli >/dev/null 2>&1 || true

if [ -n "$extension_bundle" ] && [ -d "$extension_bundle" ]; then
	run_as_user /usr/bin/pluginkit -r "$extension_bundle" \
		>/dev/null 2>&1 || true
fi
launch_services_register="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [ -n "$app_bundle" ] && [ -x "$launch_services_register" ]; then
	run_as_user "$launch_services_register" -u "$app_bundle" \
		>/dev/null 2>&1 || true
fi

remaining=false
enabled_modules="$user_home/Library/Group Containers/group.com.apple.fskit.settings/enabledModules.plist"
if [ -f "$enabled_modules" ]; then
	module_index=0
	while module=$(
		run_as_user /usr/bin/plutil \
			-extract "$module_index" raw -o - "$enabled_modules" \
			2>/dev/null
	); do
		if [ "$module" = "$extension_bundle_id" ]; then
			if run_as_user /usr/bin/plutil \
				-remove "$module_index" "$enabled_modules"; then
				continue
			fi
			warn "could not remove the PassFS FSKit enablement entry"
			remaining=true
		fi
		module_index=$((module_index + 1))
	done
fi

trash_dir=$(
	/usr/bin/mktemp -d "$user_home/.Trash/PassFS-uninstall.XXXXXX"
) || {
	echo "uninstall-passfs: could not create a Trash staging directory" >&2
	exit 1
}
/usr/sbin/chown "$console_user:$user_group" "$trash_dir" 2>/dev/null || true

move_to_trash()
{
	source=$1
	name=$2
	if [ ! -e "$source" ] && [ ! -L "$source" ]; then
		return
	fi
	if /bin/mv -f "$source" "$trash_dir/$name" 2>/dev/null; then
		printf 'Moved to Trash: %s\n' "$source"
	else
		warn "could not move $source to the Trash"
		remaining=true
	fi
}

move_to_trash "$launch_agent" "$launch_agent_label.plist"
move_to_trash \
	"$user_home/Library/Preferences/com.menxit.passfs.menu.plist" \
	"com.menxit.passfs.menu.plist"
move_to_trash \
	"$user_home/Library/Caches/com.menxit.passfs" \
	"com.menxit.passfs-cache"
move_to_trash \
	"$user_home/Library/Application Support/PassFS" \
	"PassFS-Application-Support"

fskit_settings_dir="$user_home/Library/Group Containers/group.com.apple.fskit.settings"
for backup in "$fskit_settings_dir"/enabledModules*passfs*; do
	move_to_trash "$backup" "$(basename "$backup")"
done

move_to_trash \
	"$user_home/Library/Containers/$extension_bundle_id" \
	"$extension_bundle_id"
move_to_trash \
	"$user_home/Library/Containers/$app_bundle_id" \
	"$app_bundle_id"
move_to_trash \
	"$user_home/Library/Group Containers/$app_group_identifier" \
	"$app_group_identifier"

if [ "$purge_data" = true ]; then
	config_directory=$(dirname "$config_path")
	case "$config_directory" in
	"$user_home"/*)
		move_to_trash "$config_directory" "passfs-vault"
		;;
	*)
		warn "refusing to purge config outside $user_home: $config_directory"
		remaining=true
		;;
	esac
fi

if [ "$remaining" = false ]; then
	for cli_link in /usr/local/bin/passfs /opt/homebrew/bin/passfs; do
		if [ -L "$cli_link" ]; then
			link_target=$(/usr/bin/readlink "$cli_link" 2>/dev/null || true)
			case "$link_target" in
			*/PassFS.app/Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli | \
			*/PassFS.app/Contents/Helpers/PassFSControlService.app/Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli)
				case "$cli_link" in
				/usr/local/*)
					trash_name="usr-local-passfs-cli-link"
					;;
				*)
					trash_name="opt-homebrew-passfs-cli-link"
					;;
				esac
				move_to_trash "$cli_link" "$trash_name"
				;;
			esac
		fi
	done
fi

# Move the app last because this script is running from inside its bundle.
# Keep it installed if a protected residue remains so the command can be
# rerun after granting Terminal Full Disk Access.
if [ "$remaining" = false ] && [ -n "$app_bundle" ]; then
	move_to_trash "$app_bundle" "PassFS.app"
fi
if [ "$remaining" = false ]; then
	/usr/sbin/pkgutil --forget "$package_id" >/dev/null 2>&1 || true
fi
/usr/sbin/chown -R "$console_user:$user_group" "$trash_dir" 2>/dev/null || true

if [ "$remaining" = true ]; then
	echo
	echo "PassFS was unregistered, but one or more protected files remain."
	echo "Grant Terminal Full Disk Access and run this uninstaller again."
	exit 1
fi

echo
echo "PassFS was uninstalled successfully."
echo "Recoverable items are in: $trash_dir"
if [ "$purge_data" = false ]; then
	echo "Vault data was preserved at: $(dirname "$config_path")"
fi
