#!/bin/sh

set -eu

artifact=${1-}
api_key=${2-}
key_id=${3-}
issuer_id=${4-}

if [ -z "$artifact" ] || [ -z "$api_key" ] || [ -z "$key_id" ] ||
	[ -z "$issuer_id" ]; then
	echo "usage: $0 APP_OR_PKG API_KEY_P8 KEY_ID ISSUER_ID" >&2
	exit 2
fi
if [ ! -e "$artifact" ]; then
	echo "artifact not found: $artifact" >&2
	exit 1
fi
if [ ! -f "$api_key" ]; then
	echo "notarization API key not found: $api_key" >&2
	exit 1
fi

submission=$artifact
temporary_directory=
case "$artifact" in
	*.app)
		codesign --verify --strict --verbose=2 "$artifact"
		temporary_directory=$(mktemp -d)
		submission="$temporary_directory/PassFS.zip"
		ditto -c -k --keepParent "$artifact" "$submission"
		;;
	*.pkg)
		pkgutil --check-signature "$artifact"
		;;
	*)
		echo "only .app bundles and .pkg installers can be notarized" >&2
		exit 1
		;;
esac

cleanup()
{
	if [ -n "$temporary_directory" ]; then
		rm -rf "$temporary_directory"
	fi
}
trap cleanup EXIT HUP INT TERM

xcrun notarytool submit "$submission" \
	--key "$api_key" \
	--key-id "$key_id" \
	--issuer "$issuer_id" \
	--wait
xcrun stapler staple "$artifact"
xcrun stapler validate "$artifact"

case "$artifact" in
	*.app)
		spctl --assess --type execute --verbose=2 "$artifact"
		;;
	*.pkg)
		spctl --assess --type install --verbose=2 "$artifact"
		;;
esac

printf 'Notarized and stapled: %s\n' "$artifact"
