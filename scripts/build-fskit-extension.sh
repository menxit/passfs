#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
profile=${1-}
signing_identity=${2-}
output=${3-}
bundle_id="com.menxit.passfs.filesystem"
keychain_group_id="com.menxit.passfs"
release_version=${PASSFS_VERSION:-0.1.0}
build_number=${PASSFS_BUILD_NUMBER:-1}
architectures=${PASSFS_MACOS_ARCHES:-$(uname -m)}

if [ -z "$profile" ] || [ -z "$signing_identity" ] || [ -z "$output" ]; then
	echo "usage: $0 FSKIT_PROVISIONING_PROFILE SIGNING_IDENTITY OUTPUT_APPEX" >&2
	exit 2
fi
if [ ! -f "$profile" ]; then
	echo "FSKit provisioning profile not found: $profile" >&2
	exit 1
fi
if [ "$(basename "$output")" != "PassFSFileSystem.appex" ]; then
	echo "refusing unexpected FSKit extension output: $output" >&2
	exit 1
fi

output_parent=$(dirname "$output")
mkdir -p "$output_parent"
output_parent=$(
	cd "$output_parent" &&
		pwd
)
output="$output_parent/$(basename "$output")"
build_directory=$(mktemp -d "$output_parent/.passfs-fskit-build.XXXXXX")
profile_plist="$build_directory/profile.plist"
entitlements="$build_directory/extension.entitlements"
archive_directory="$build_directory/archives"
derived_data="$build_directory/DerivedData"
universal_archive="$build_directory/libpassfs_bridge.a"

cleanup()
{
	rm -rf "$build_directory"
}
trap cleanup EXIT HUP INT TERM

security cms -D -i "$profile" >"$profile_plist"
team_identifier=$(
	/usr/libexec/PlistBuddy \
		-c "Print :TeamIdentifier:0" \
		"$profile_plist"
)
application_identifier=$(
	/usr/libexec/PlistBuddy \
		-c "Print :Entitlements:com.apple.application-identifier" \
		"$profile_plist"
)
if [ "$application_identifier" != "$team_identifier.$bundle_id" ]; then
	echo "FSKit profile App ID is $application_identifier, want $team_identifier.$bundle_id" >&2
	exit 1
fi
if [ "$(
	/usr/libexec/PlistBuddy \
		-c "Print :Entitlements:com.apple.developer.fskit.fsmodule" \
		"$profile_plist" 2>/dev/null || true
)" != "true" ]; then
	echo "FSKit profile does not authorize com.apple.developer.fskit.fsmodule" >&2
	exit 1
fi
if ! /usr/libexec/PlistBuddy \
	-c "Print :Entitlements:keychain-access-groups" \
	"$profile_plist" |
	grep -Eq "$team_identifier\\.\\*|$team_identifier\\.$keychain_group_id"; then
	echo "FSKit profile does not authorize the passfs Keychain access group" >&2
	exit 1
fi
plutil -extract Entitlements xml1 -o "$entitlements" "$profile_plist"
/usr/libexec/PlistBuddy \
	-c "Delete :keychain-access-groups" \
	"$entitlements"
/usr/libexec/PlistBuddy \
	-c "Add :keychain-access-groups array" \
	"$entitlements"
/usr/libexec/PlistBuddy \
	-c "Add :keychain-access-groups:0 string $team_identifier.$keychain_group_id" \
	"$entitlements"
if /usr/libexec/PlistBuddy \
	-c "Print :com.apple.security.app-sandbox" \
	"$entitlements" >/dev/null 2>&1; then
	/usr/libexec/PlistBuddy \
		-c "Set :com.apple.security.app-sandbox true" \
		"$entitlements"
else
	/usr/libexec/PlistBuddy \
		-c "Add :com.apple.security.app-sandbox bool true" \
		"$entitlements"
fi

mkdir -p "$archive_directory"
archive_count=0
xcode_architectures=
for architecture in $architectures; do
	case "$architecture" in
		arm64)
			go_architecture=arm64
			xcode_architecture=arm64
			;;
		amd64 | x86_64)
			go_architecture=amd64
			xcode_architecture=x86_64
			;;
		*)
			echo "unsupported macOS architecture: $architecture" >&2
			exit 1
			;;
	esac
	archive_count=$((archive_count + 1))
	xcode_architectures="${xcode_architectures}${xcode_architectures:+ }$xcode_architecture"
	(
		cd "$project_root"
		CGO_ENABLED=1 \
		GOOS=darwin \
		GOARCH="$go_architecture" \
		CGO_CFLAGS="-arch $xcode_architecture" \
		CGO_LDFLAGS="-arch $xcode_architecture" \
			env -u GOROOT GOWORK=off go build \
			-trimpath \
			-buildmode=c-archive \
			-o "$archive_directory/libpassfs_bridge-$xcode_architecture.a" \
			./cmd/passfs-fskit-bridge
	)
done

if [ "$archive_count" -eq 1 ]; then
	cp "$archive_directory"/libpassfs_bridge-*.a "$universal_archive"
else
	lipo -create "$archive_directory"/libpassfs_bridge-*.a \
		-output "$universal_archive"
fi

if [ -z "${DEVELOPER_DIR:-}" ] &&
	[ -d /Applications/Xcode.app/Contents/Developer ]; then
	DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
	export DEVELOPER_DIR
fi
if ! xcrun --find xcodebuild >/dev/null 2>&1; then
	echo "Xcode with the macOS 26 SDK is required to build the FSKit extension" >&2
	exit 1
fi

DEVELOPER_DIR=${DEVELOPER_DIR:-$(xcode-select -p)} \
xcodebuild \
	-project "$project_root/native/fskit/PassFSFileSystem.xcodeproj" \
	-scheme PassFSFileSystem \
	-configuration Release \
	-derivedDataPath "$derived_data" \
	ARCHS="$xcode_architectures" \
	ONLY_ACTIVE_ARCH=NO \
	PASSFS_BRIDGE_ARCHIVE="$universal_archive" \
	MARKETING_VERSION="$release_version" \
	CURRENT_PROJECT_VERSION="$build_number" \
	CODE_SIGNING_ALLOWED=NO \
	build

built_extension="$derived_data/Build/Products/Release/PassFSFileSystem.appex"
if [ ! -d "$built_extension" ]; then
	echo "Xcode did not produce the FSKit extension" >&2
	exit 1
fi
ditto "$built_extension" "$output"
COPYFILE_DISABLE=1 cp "$profile" "$output/Contents/embedded.provisionprofile"
/usr/bin/xattr -c "$output/Contents/embedded.provisionprofile"
chmod 0644 "$output/Contents/embedded.provisionprofile"

codesign \
	--force \
	--identifier "$bundle_id" \
	--options runtime \
	--timestamp \
	--entitlements "$entitlements" \
	--sign "$signing_identity" \
	"$output"
codesign --verify --strict --verbose=2 "$output"

/usr/libexec/PlistBuddy \
	-c "Print :EXAppExtensionAttributes:EXExtensionPointIdentifier" \
	"$output/Contents/Info.plist" |
	grep -Fx "com.apple.fskit.fsmodule" >/dev/null
/usr/libexec/PlistBuddy \
	-c "Print :EXAppExtensionAttributes:FSShortName" \
	"$output/Contents/Info.plist" |
	grep -Fx "passfs" >/dev/null
/usr/libexec/PlistBuddy \
	-c "Print :CFBundleDisplayName" \
	"$output/Contents/Info.plist" |
	grep -Fx "passfs" >/dev/null

printf 'Built signed FSKit extension: %s\n' "$output"
printf 'Architectures:               %s\n' "$xcode_architectures"
