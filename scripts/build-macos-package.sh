#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
source_app=${1-}
installer_identity=${2-}
release_version=${3-}
output=${4-}

if [ -z "$source_app" ] || [ -z "$installer_identity" ] ||
	[ -z "$release_version" ] || [ -z "$output" ]; then
	echo "usage: $0 SIGNED_APP INSTALLER_IDENTITY VERSION OUTPUT_PKG" >&2
	exit 2
fi
if [ "$(basename "$source_app")" != "PassFS.app" ]; then
	echo "refusing unexpected app bundle: $source_app" >&2
	exit 1
fi
if [ "$(basename "$output")" != "PassFS-macos-universal.pkg" ]; then
	echo "refusing unexpected package output: $output" >&2
	exit 1
fi
if ! printf '%s\n' "$release_version" |
	grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$'; then
	echo "invalid release version: $release_version" >&2
	exit 1
fi
if [ ! -d "$source_app" ]; then
	echo "signed app bundle not found: $source_app" >&2
	exit 1
fi

codesign --verify --strict --verbose=2 "$source_app"
if [ "$installer_identity" = "auto" ]; then
	installer_identity=$(
		security find-identity -v |
			sed -n \
				's/.*"\(Developer ID Installer: [^"]*\)".*/\1/p' |
			head -n 1
	)
fi
if [ -z "$installer_identity" ] ||
	! security find-identity -v |
	grep -Fq "$installer_identity"; then
	echo "a Developer ID Installer identity is not available in the Keychain" >&2
	exit 1
fi

output_parent=$(dirname "$output")
mkdir -p "$output_parent"
build_directory=$(mktemp -d "$output_parent/.passfs-package-build.XXXXXX")
payload="$build_directory/payload"
component_plist="$build_directory/components.plist"
staged_package="$build_directory/PassFS-macos-universal.pkg"
previous_package="$build_directory/PreviousPassFS.pkg"

cleanup()
{
	rm -rf "$build_directory"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$payload/Applications" "$payload/usr/local/bin"
ditto "$source_app" "$payload/Applications/PassFS.app"
ln -s /Applications/PassFS.app/Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli \
	"$payload/usr/local/bin/passfs"

package_version=${release_version%%-*}
pkgbuild --analyze \
	--root "$payload" \
	"$component_plist"
plutil -replace 0.BundleIsRelocatable -bool false "$component_plist"
plutil -replace 0.BundleHasStrictIdentifier -bool true "$component_plist"

pkgbuild \
	--root "$payload" \
	--component-plist "$component_plist" \
	--identifier "com.menxit.passfs.pkg" \
	--version "$package_version" \
	--install-location / \
	--scripts "$project_root/packaging/macos/installer-scripts" \
	--sign "$installer_identity" \
	"$staged_package"
pkgutil --check-signature "$staged_package"

had_previous=false
if [ -e "$output" ] || [ -L "$output" ]; then
	mv "$output" "$previous_package"
	had_previous=true
fi
if ! mv "$staged_package" "$output"; then
	if [ "$had_previous" = true ]; then
		mv "$previous_package" "$output"
	fi
	exit 1
fi

printf 'Built signed installer: %s\n' "$output"
printf 'Installer identity:     %s\n' "$installer_identity"
