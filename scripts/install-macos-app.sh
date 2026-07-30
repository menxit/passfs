#!/bin/sh

set -eu

source_app=${1-}
destination_app=${2-}
command_path=${3-}

if [ -z "$source_app" ] || [ -z "$destination_app" ] ||
	[ -z "$command_path" ]; then
	echo "usage: $0 SOURCE_APP DESTINATION_APP COMMAND_PATH" >&2
	exit 2
fi
if [ "$(basename "$source_app")" != "PassFS.app" ] ||
	[ "$(basename "$destination_app")" != "PassFS.app" ] ||
	[ "$(basename "$command_path")" != "passfs" ]; then
	echo "refusing unexpected passfs installation path" >&2
	exit 1
fi
if [ ! -d "$source_app/Contents/MacOS" ]; then
	echo "signed passfs app bundle not found: $source_app" >&2
	exit 1
fi
codesign --verify --strict --verbose=2 "$source_app"

app_parent=$(dirname "$destination_app")
command_parent=$(dirname "$command_path")
mkdir -p "$app_parent" "$command_parent"
transaction_directory=$(
	mktemp -d "$app_parent/.passfs-install.XXXXXX"
)
staged_app="$transaction_directory/PassFS.app"
previous_app="$transaction_directory/PreviousPassFS.app"
previous_command="$transaction_directory/previous-passfs"

cleanup()
{
	rm -rf "$transaction_directory"
}
trap cleanup EXIT HUP INT TERM

ditto "$source_app" "$staged_app"
codesign --verify --strict --verbose=2 "$staged_app"

had_app=false
had_command=false
if [ -e "$destination_app" ] || [ -L "$destination_app" ]; then
	mv "$destination_app" "$previous_app"
	had_app=true
fi
if ! mv "$staged_app" "$destination_app"; then
	if [ "$had_app" = true ]; then
		mv "$previous_app" "$destination_app"
	fi
	exit 1
fi

if [ -e "$command_path" ] || [ -L "$command_path" ]; then
	mv "$command_path" "$previous_command"
	had_command=true
fi
if ! ln -s "$destination_app/Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli" \
	"$command_path"; then
	if [ "$had_command" = true ]; then
		mv "$previous_command" "$command_path"
	fi
	mv "$destination_app" "$staged_app"
	if [ "$had_app" = true ]; then
		mv "$previous_app" "$destination_app"
	fi
	exit 1
fi

printf 'Installed signed app: %s\n' "$destination_app"
printf 'Installed command:    %s\n' "$command_path"
/usr/bin/open "$destination_app"
