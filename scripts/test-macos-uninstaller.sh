#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
uninstaller="$project_root/packaging/macos/uninstall-passfs.sh"

/bin/sh -n "$uninstaller"
/bin/sh -n "$project_root/scripts/macos-signing-common.sh"
/bin/sh -n "$project_root/scripts/build-fskit-bridge.sh"
/bin/sh -n "$project_root/scripts/build-macos-app.sh"
/bin/sh -n "$project_root/scripts/build-fskit-extension.sh"
test -x "$uninstaller"

for expected in \
	"com.menxit.passfs.pkg" \
	"com.menxit.passfs.filesystem" \
	"com.menxit.passfs.control-agent" \
	"PassFSControlService.app" \
	"3943PK2P39.com.menxit.passfs.shared" \
	"/usr/local/bin/passfs" \
	"Library/Containers" \
	"Library/LaunchAgents" \
	"lsregister" \
	"enabledModules.plist" \
	"--purge-data"; do
	if ! grep -Fq -- "$expected" "$uninstaller"; then
		echo "uninstaller does not cover $expected" >&2
		exit 1
	fi
done

printf 'macOS uninstaller checks passed\n'
