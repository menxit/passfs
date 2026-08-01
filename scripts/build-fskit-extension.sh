#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
# shellcheck source=macos-signing-common.sh
. "$project_root/scripts/macos-signing-common.sh"
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
profile_certificate="$build_directory/profile-certificate.der"
entitlements="$build_directory/extension.entitlements"
derived_data="$build_directory/DerivedData"
universal_archive="$build_directory/libpassfs_bridge.a"

cleanup()
{
	rm -rf "$build_directory"
}
trap cleanup EXIT HUP INT TERM

passfs_decode_provisioning_profile "$profile" "$profile_plist"
team_identifier=$(passfs_profile_team_identifier "$profile_plist")
passfs_assert_profile_app_id \
	"$profile_plist" "$team_identifier" "$bundle_id" "FSKit profile"
passfs_assert_profile_boolean_entitlement \
	"$profile_plist" "com.apple.developer.fskit.fsmodule" "FSKit profile"
passfs_assert_profile_keychain_group \
	"$profile_plist" "$team_identifier" "$keychain_group_id" "FSKit profile"
signing_identity=$(passfs_resolve_signing_identity \
	"$profile_plist" "$signing_identity" "$profile_certificate")
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
if /usr/libexec/PlistBuddy \
	-c "Print :com.apple.security.network.client" \
	"$entitlements" >/dev/null 2>&1; then
	/usr/libexec/PlistBuddy \
		-c "Set :com.apple.security.network.client true" \
		"$entitlements"
else
	/usr/libexec/PlistBuddy \
		-c "Add :com.apple.security.network.client bool true" \
		"$entitlements"
fi

xcode_architectures=$(
	"$project_root/scripts/build-fskit-bridge.sh" \
		"$universal_archive" "$architectures"
)

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
