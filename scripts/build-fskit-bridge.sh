#!/bin/sh

set -eu

project_root=$(
	cd "$(dirname "$0")/.." &&
		pwd
)
output=${1-}
architectures=${2-}

if [ -z "$output" ] || [ -z "$architectures" ]; then
	echo "usage: $0 OUTPUT_ARCHIVE MACOS_ARCHES" >&2
	exit 2
fi

output_parent=$(dirname "$output")
mkdir -p "$output_parent"
output_parent=$(
	cd "$output_parent" &&
		pwd
)
output="$output_parent/$(basename "$output")"
build_directory=$(mktemp -d "$output_parent/.passfs-fskit-bridge.XXXXXX")

cleanup()
{
	rm -rf "$build_directory"
}
trap cleanup EXIT HUP INT TERM

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
			-o "$build_directory/libpassfs_bridge-$xcode_architecture.a" \
			./cmd/passfs-fskit-bridge
	)
done

if [ "$archive_count" -eq 1 ]; then
	cp "$build_directory"/libpassfs_bridge-*.a "$output"
else
	lipo -create "$build_directory"/libpassfs_bridge-*.a -output "$output"
fi

printf '%s\n' "$xcode_architectures"
