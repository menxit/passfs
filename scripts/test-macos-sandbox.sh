#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
app_entitlements="$project_root/packaging/macos/passfs.entitlements.in"
helper_entitlements="$project_root/packaging/macos/passfs-helper.entitlements.in"
extension_entitlements="$project_root/native/fskit/PassFSFileSystem/PassFSFileSystem.entitlements"
agent_plist="$project_root/packaging/macos/com.menxit.passfs.control-agent.plist"
control_service="$project_root/native/macos/PassFSControlService.swift"
menu_app="$project_root/native/menubar/PassFSMenuApp.swift"
build_app="$project_root/scripts/build-macos-app.sh"
verify_app="$project_root/scripts/verify-macos-app.sh"

require_text()
{
	file=$1
	text=$2
	if ! grep -Fq "$text" "$file"; then
		echo "$file does not contain required text: $text" >&2
		exit 1
	fi
}

reject_text()
{
	file=$1
	text=$2
	if grep -Fq "$text" "$file"; then
		echo "$file contains forbidden text: $text" >&2
		exit 1
	fi
}

require_text "$app_entitlements" "com.apple.security.app-sandbox"
require_text "$app_entitlements" "com.apple.security.files.user-selected.read-write"
require_text "$app_entitlements" "__TEAM_IDENTIFIER__.com.menxit.passfs.shared"
require_text "$helper_entitlements" "__TEAM_IDENTIFIER__.com.menxit.passfs.shared"
reject_text "$helper_entitlements" "com.apple.security.app-sandbox"
require_text "$extension_entitlements" "com.apple.security.app-sandbox"
require_text "$extension_entitlements" "com.menxit.passfs.shared"
reject_text "$extension_entitlements" "com.apple.security.network.client"
require_text "$agent_plist" "com.menxit.passfs.control-agent"
require_text "$agent_plist" "Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli"
require_text "$agent_plist" "__app-agent"
require_text "$control_service" "SMAppService.agent"
require_text "$control_service" "try service.register()"
require_text "$control_service" "try service.unregister()"
reject_text "$menu_app" "SMAppService.agent"
reject_text "$menu_app" "registerControlAgentIfNeeded"
require_text "$menu_app" "PassFSControlService.app"
require_text "$menu_app" "containerURL("
require_text "$menu_app" 'case uiSnapshot = "ui-snapshot"'
require_text "$menu_app" 'case backupCreate = "backup-create"'
require_text "$menu_app" 'case backupRestore = "backup-restore"'
reject_text "$menu_app" "let arguments: [String]"
reject_text "$menu_app" "homeDirectoryForCurrentUser"
reject_text "$menu_app" "MDItemCreate"
reject_text "$menu_app" "O_EVTONLY"
reject_text "$menu_app" "The PassFS control agent is missing from the application bundle."
require_text "$build_app" 'verify-macos-app.sh'
require_text "$build_app" 'PassFSControlService.app'
require_text "$verify_app" 'codesign --verify --deep --strict'
require_text "$verify_app" 'com.apple.security.app-sandbox'
require_text "$verify_app" 'com.apple.security.network.client'
require_text "$verify_app" 'TeamIdentifier'

if [ "$(uname -s)" = "Darwin" ]; then
	plutil -lint \
		"$app_entitlements" \
		"$helper_entitlements" \
		"$extension_entitlements" \
		"$agent_plist" >/dev/null
fi

echo "macOS sandbox packaging tests passed"
