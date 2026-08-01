#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
# shellcheck source=macos-signing-common.sh
. "$project_root/scripts/macos-signing-common.sh"
bundle_id="com.menxit.passfs"
profile=${1-}
signing_identity=${2-}
output=${3-}
fskit_profile=${4-}
release_version=${PASSFS_VERSION:-0.1.0}
build_number=${PASSFS_BUILD_NUMBER:-1}
architectures=${PASSFS_MACOS_ARCHES:-$(uname -m)}

if [ -z "$profile" ] || [ -z "$signing_identity" ] ||
	[ -z "$output" ] || [ -z "$fskit_profile" ]; then
	echo "usage: $0 APP_PROVISIONING_PROFILE SIGNING_IDENTITY OUTPUT_APP FSKIT_PROVISIONING_PROFILE" >&2
	exit 2
fi
if ! printf '%s\n' "$release_version" |
	grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$'; then
	echo "invalid release version: $release_version" >&2
	exit 1
fi
case "$build_number" in
	"" | *[!0-9]*)
		echo "build number must be a positive integer" >&2
		exit 1
		;;
esac
if [ ! -f "$profile" ]; then
	echo "provisioning profile not found: $profile" >&2
	exit 1
fi
if [ ! -f "$fskit_profile" ]; then
	echo "FSKit provisioning profile not found: $fskit_profile" >&2
	exit 1
fi
if [ "$(basename "$output")" != "PassFS.app" ]; then
	echo "refusing unexpected app bundle output: $output" >&2
	exit 1
fi

output_parent=$(dirname "$output")
mkdir -p "$output_parent"
output_parent=$(
	cd "$output_parent" &&
		pwd
)
output="$output_parent/$(basename "$output")"
build_directory=$(mktemp -d "$output_parent/.passfs-macos-build.XXXXXX")
staged_app="$build_directory/PassFS.app"
cli_bundle="$staged_app/Contents/Helpers/PassFSCLI.bundle"
cli_binary="$cli_bundle/Contents/MacOS/passfs-cli"
previous_app="$build_directory/PreviousPassFS.app"
profile_plist="$build_directory/profile.plist"
profile_certificate="$build_directory/profile-certificate.der"
entitlements="$build_directory/passfs.entitlements"
binary_directory="$build_directory/binaries"

cleanup()
{
	rm -rf "$build_directory"
}
trap cleanup EXIT HUP INT TERM

passfs_decode_provisioning_profile "$profile" "$profile_plist"
team_identifier=$(passfs_profile_team_identifier "$profile_plist")
passfs_assert_profile_app_id \
	"$profile_plist" "$team_identifier" "$bundle_id" "profile"
passfs_assert_profile_keychain_group \
	"$profile_plist" "$team_identifier" "$bundle_id" "profile"
passfs_assert_profile_boolean_entitlement \
	"$profile_plist" "com.apple.developer.fskit.mount" "profile"
signing_identity=$(passfs_resolve_signing_identity \
	"$profile_plist" "$signing_identity" "$profile_certificate")

sed "s/__TEAM_IDENTIFIER__/$team_identifier/g" \
	"$project_root/packaging/macos/passfs.entitlements.in" >"$entitlements"
plutil -lint "$project_root/packaging/macos/Info.plist" "$entitlements" >/dev/null

mkdir -p \
	"$staged_app/Contents/Helpers" \
	"$staged_app/Contents/MacOS" \
	"$staged_app/Contents/Extensions" \
	"$staged_app/Contents/Resources" \
	"$cli_bundle/Contents/MacOS" \
	"$binary_directory"
cp "$project_root/packaging/macos/Info.plist" \
	"$staged_app/Contents/Info.plist"
cp "$project_root/packaging/macos/PassFSCLI-Info.plist" \
	"$cli_bundle/Contents/Info.plist"
cp "$project_root/packaging/macos/PassFS.icns" \
	"$staged_app/Contents/Resources/PassFS.icns"
cp \
	"$project_root/packaging/macos/PassFSMenuIcon.png" \
	"$project_root/packaging/macos/PassFSMenuIcon@2x.png" \
	"$staged_app/Contents/Resources/"
cp "$project_root/packaging/macos/uninstall-passfs.sh" \
	"$staged_app/Contents/Resources/uninstall-passfs.sh"
chmod 0755 "$staged_app/Contents/Resources/uninstall-passfs.sh"
for localization in "$project_root"/native/menubar/Resources/*.lproj; do
	cp -R "$localization" "$staged_app/Contents/Resources/"
done
COPYFILE_DISABLE=1 cp "$profile" \
	"$staged_app/Contents/embedded.provisionprofile"
COPYFILE_DISABLE=1 cp "$profile" \
	"$cli_bundle/Contents/embedded.provisionprofile"
/usr/bin/xattr -c "$staged_app/Contents/embedded.provisionprofile"
/usr/bin/xattr -c "$cli_bundle/Contents/embedded.provisionprofile"
chmod 0644 "$staged_app/Contents/embedded.provisionprofile"
chmod 0644 "$cli_bundle/Contents/embedded.provisionprofile"

plist_version=${release_version%%-*}
/usr/libexec/PlistBuddy \
	-c "Set :CFBundleShortVersionString $plist_version" \
	"$staged_app/Contents/Info.plist"
/usr/libexec/PlistBuddy \
	-c "Set :CFBundleVersion $build_number" \
	"$staged_app/Contents/Info.plist"
/usr/libexec/PlistBuddy \
	-c "Set :CFBundleShortVersionString $plist_version" \
	"$cli_bundle/Contents/Info.plist"
/usr/libexec/PlistBuddy \
	-c "Set :CFBundleVersion $build_number" \
	"$cli_bundle/Contents/Info.plist"
binary_count=0
for architecture in $architectures; do
	case "$architecture" in
		arm64)
			go_architecture=arm64
			compiler_architecture=arm64
			;;
		amd64)
			go_architecture=amd64
			compiler_architecture=x86_64
			;;
		x86_64)
			go_architecture=amd64
			compiler_architecture=x86_64
			;;
		*)
			echo "unsupported macOS architecture: $architecture" >&2
			exit 1
			;;
	esac
	binary_count=$((binary_count + 1))
	(
		cd "$project_root"
		CGO_ENABLED=1 \
		GOOS=darwin \
		GOARCH="$go_architecture" \
		CGO_CFLAGS="-arch $compiler_architecture" \
		CGO_LDFLAGS="-arch $compiler_architecture" \
			env -u GOROOT GOWORK=off go build \
			-trimpath \
			-ldflags "-s -w -X main.version=$release_version" \
			-o "$binary_directory/passfs-cli-$architecture" \
			./cmd/passfs
	)
	xcrun swiftc \
		-parse-as-library \
		-O \
		-target "$compiler_architecture-apple-macos13.0" \
		-framework AppKit \
		-framework CoreServices \
		-Xlinker -weak_framework \
		-Xlinker FSKit \
		-framework ServiceManagement \
		-framework SwiftUI \
		-o "$binary_directory/passfs-ui-$architecture" \
		"$project_root/native/menubar/PassFSMenuApp.swift"
done

if [ "$binary_count" -eq 1 ]; then
	cp "$binary_directory"/passfs-cli-* \
		"$binary_directory/passfs-cli-final"
	cp "$binary_directory"/passfs-ui-* \
		"$binary_directory/passfs-ui-final"
else
	lipo -create "$binary_directory"/passfs-cli-* \
		-output "$binary_directory/passfs-cli-final"
	lipo -create "$binary_directory"/passfs-ui-* \
		-output "$binary_directory/passfs-ui-final"
fi
chmod 0755 \
	"$binary_directory/passfs-cli-final" \
	"$binary_directory/passfs-ui-final"

cp "$binary_directory/passfs-cli-final" \
	"$cli_binary"
cp "$binary_directory/passfs-ui-final" \
	"$staged_app/Contents/MacOS/PassFS"

PASSFS_VERSION="$release_version" \
PASSFS_BUILD_NUMBER="$build_number" \
PASSFS_MACOS_ARCHES="$architectures" \
	"$project_root/scripts/build-fskit-extension.sh" \
	"$fskit_profile" \
	"$signing_identity" \
	"$staged_app/Contents/Extensions/PassFSFileSystem.appex"

codesign \
	--force \
	--identifier "$bundle_id" \
	--options runtime \
	--timestamp \
	--entitlements "$entitlements" \
	--sign "$signing_identity" \
	"$cli_bundle"

codesign \
	--force \
	--identifier "$bundle_id" \
	--options runtime \
	--timestamp \
	--entitlements "$entitlements" \
	--sign "$signing_identity" \
	"$staged_app"
codesign --verify --deep --strict --verbose=2 "$staged_app"

had_previous=false
if [ -e "$output" ] || [ -L "$output" ]; then
	mv "$output" "$previous_app"
	had_previous=true
fi
if ! mv "$staged_app" "$output"; then
	if [ "$had_previous" = true ]; then
		mv "$previous_app" "$output"
	fi
	exit 1
fi
printf 'Built signed app bundle: %s\n' "$output"
printf 'Signing identity:        %s\n' "$signing_identity"
printf 'Version:                 %s (%s)\n' "$release_version" "$build_number"
printf 'Architectures:           %s\n' "$architectures"
