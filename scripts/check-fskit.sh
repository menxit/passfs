#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)

build_directory=$(mktemp -d "${TMPDIR:-/tmp}/passfs-fskit-check.XXXXXX")
cleanup()
{
	rm -rf "$build_directory"
}
trap cleanup EXIT HUP INT TERM

if [ -z "${DEVELOPER_DIR:-}" ] &&
	[ -d /Applications/Xcode.app/Contents/Developer ]; then
	DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
	export DEVELOPER_DIR
fi
if ! xcrun --find xcodebuild >/dev/null 2>&1; then
	echo "Xcode with the macOS 26 SDK is required to check FSKit" >&2
	exit 1
fi

xcode_architecture=$(
	"$project_root/scripts/build-fskit-bridge.sh" \
		"$build_directory/libpassfs_bridge.a" "$(uname -m)"
)

xcrun swiftc \
	-parse-as-library \
	-target "$xcode_architecture-apple-macos13.0" \
	-framework AppKit \
	-framework CoreServices \
	-Xlinker -weak_framework \
	-Xlinker FSKit \
	-framework ServiceManagement \
	-framework SwiftUI \
	-o "$build_directory/PassFS" \
	"$project_root/native/menubar/PassFSMenuApp.swift"
DEVELOPER_DIR=${DEVELOPER_DIR:-$(xcode-select -p)} \
xcodebuild \
	-project "$project_root/native/fskit/PassFSFileSystem.xcodeproj" \
	-scheme PassFSFileSystem \
	-configuration Debug \
	-derivedDataPath "$build_directory/DerivedData" \
	ARCHS="$xcode_architecture" \
	ONLY_ACTIVE_ARCH=YES \
	PASSFS_BRIDGE_ARCHIVE="$build_directory/libpassfs_bridge.a" \
	CODE_SIGNING_ALLOWED=NO \
	build

built_info="$build_directory/DerivedData/Build/Products/Debug/PassFSFileSystem.appex/Contents/Info.plist"
/usr/libexec/PlistBuddy \
	-c "Print :EXAppExtensionAttributes:EXExtensionPointIdentifier" \
	"$built_info" |
	grep -Fx "com.apple.fskit.fsmodule" >/dev/null
/usr/libexec/PlistBuddy \
	-c "Print :EXAppExtensionAttributes:FSShortName" \
	"$built_info" |
	grep -Fx "passfs" >/dev/null
/usr/libexec/PlistBuddy \
	-c "Print :CFBundleDisplayName" \
	"$built_info" |
	grep -Fx "passfs" >/dev/null

printf 'FSKit extension check passed (%s)\n' "$xcode_architecture"
