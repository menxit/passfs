#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
bundle_id="com.menxit.passfs"
profile=${1-}
signing_identity=${2-}
output=${3-}
release_version=${PASSFS_VERSION:-0.1.0}
build_number=${PASSFS_BUILD_NUMBER:-1}
architectures=${PASSFS_MACOS_ARCHES:-$(uname -m)}

if [ -z "$profile" ] || [ -z "$signing_identity" ] || [ -z "$output" ]; then
	echo "usage: $0 PROVISIONING_PROFILE SIGNING_IDENTITY OUTPUT_APP" >&2
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
if [ "$(basename "$output")" != "PassFS.app" ]; then
	echo "refusing unexpected app bundle output: $output" >&2
	exit 1
fi

output_parent=$(dirname "$output")
mkdir -p "$output_parent"
build_directory=$(mktemp -d "$output_parent/.passfs-macos-build.XXXXXX")
staged_app="$build_directory/PassFS.app"
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

security cms -D -i "$profile" >"$profile_plist"
if [ "$signing_identity" = "auto" ]; then
	plutil -extract DeveloperCertificates.0 raw "$profile_plist" |
		base64 -D >"$profile_certificate"
	signing_identity=$(
		shasum "$profile_certificate" |
			awk '{ print toupper($1) }'
	)
fi
if ! security find-identity -v -p codesigning |
	grep -Fq "$signing_identity"; then
	echo "the profile signing identity is not available in the login Keychain" >&2
	exit 1
fi
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
	echo "profile App ID is $application_identifier, want $team_identifier.$bundle_id" >&2
	exit 1
fi
if ! /usr/libexec/PlistBuddy \
	-c "Print :Entitlements:keychain-access-groups" \
	"$profile_plist" |
	grep -Eq "$team_identifier\\.\\*|$team_identifier\\.$bundle_id"; then
	echo "profile does not authorize the passfs Keychain access group" >&2
	exit 1
fi

sed "s/__TEAM_IDENTIFIER__/$team_identifier/g" \
	"$project_root/packaging/macos/passfs.entitlements.in" >"$entitlements"
plutil -lint "$project_root/packaging/macos/Info.plist" "$entitlements" >/dev/null

mkdir -p \
	"$staged_app/Contents/MacOS" \
	"$staged_app/Contents/Resources" \
	"$binary_directory"
cp "$project_root/packaging/macos/Info.plist" \
	"$staged_app/Contents/Info.plist"
cp "$project_root/packaging/macos/PassFS.icns" \
	"$staged_app/Contents/Resources/PassFS.icns"
cp "$profile" "$staged_app/Contents/embedded.provisionprofile"
chmod 0644 "$staged_app/Contents/embedded.provisionprofile"

plist_version=${release_version%%-*}
/usr/libexec/PlistBuddy \
	-c "Set :CFBundleShortVersionString $plist_version" \
	"$staged_app/Contents/Info.plist"
/usr/libexec/PlistBuddy \
	-c "Set :CFBundleVersion $build_number" \
	"$staged_app/Contents/Info.plist"

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
			-o "$binary_directory/passfs-$architecture" \
			./cmd/passfs
	)
done

if [ "$binary_count" -eq 1 ]; then
	cp "$binary_directory"/passfs-* \
		"$staged_app/Contents/MacOS/passfs"
else
	lipo -create "$binary_directory"/passfs-* \
		-output "$staged_app/Contents/MacOS/passfs"
fi
chmod 0755 "$staged_app/Contents/MacOS/passfs"

codesign \
	--force \
	--identifier "$bundle_id" \
	--options runtime \
	--timestamp \
	--entitlements "$entitlements" \
	--sign "$signing_identity" \
	"$staged_app"
codesign --verify --strict --verbose=2 "$staged_app"

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
