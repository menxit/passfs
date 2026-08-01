#!/usr/bin/env bash

set -euo pipefail

RELEASE_DIRECTORY="${1:-}"
[[ -d "${RELEASE_DIRECTORY}" ]] || {
	echo "usage: $0 RELEASE_DIRECTORY" >&2
	exit 2
}
: "${PASSFS_UPDATE_SIGNING_KEY:?missing PASSFS_UPDATE_SIGNING_KEY}"
command -v openssl >/dev/null 2>&1 || {
	echo "openssl is required to sign a release" >&2
	exit 1
}

VERSION="$(basename "${RELEASE_DIRECTORY}")"
VERSION="${VERSION#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] || {
	echo "release directory does not contain a semantic version" >&2
	exit 1
}
[[ -f "${RELEASE_DIRECTORY}/SHA256SUMS" ]] || {
	echo "missing ${RELEASE_DIRECTORY}/SHA256SUMS" >&2
	exit 1
}

umask 077
MANIFEST="${RELEASE_DIRECTORY}/MANIFEST.json"
SIGNATURE="${RELEASE_DIRECTORY}/MANIFEST.sig"
MANIFEST_TEMP="$(mktemp "${RELEASE_DIRECTORY}/.MANIFEST.XXXXXX")"
SIGNATURE_BINARY="$(mktemp "${RELEASE_DIRECTORY}/.MANIFEST-SIGNATURE.XXXXXX")"
SIGNATURE_TEMP="$(mktemp "${RELEASE_DIRECTORY}/.MANIFEST-SIGNATURE-BASE64.XXXXXX")"
PRIVATE_KEY="$(mktemp "${RELEASE_DIRECTORY}/.UPDATE-SIGNING-KEY.XXXXXX")"
trap 'rm -f "${MANIFEST_TEMP}" "${SIGNATURE_BINARY}" "${SIGNATURE_TEMP}" "${PRIVATE_KEY}"' EXIT

printf '{\n  "version": "%s",\n  "checksums": {\n' "${VERSION}" \
	> "${MANIFEST_TEMP}"
FIRST=true
while read -r CHECKSUM ASSET; do
	ASSET="${ASSET#\*}"
	ASSET="${ASSET#./}"
	[[ "${CHECKSUM}" =~ ^[0-9a-fA-F]{64}$ ]] || {
		echo "invalid checksum for ${ASSET}" >&2
		exit 1
	}
	[[ "${ASSET}" =~ ^[A-Za-z0-9._-]+$ ]] || {
		echo "invalid release asset name: ${ASSET}" >&2
		exit 1
	}
	if [[ "${FIRST}" == true ]]; then
		FIRST=false
	else
		printf ',\n' >> "${MANIFEST_TEMP}"
	fi
	printf '    "%s": "%s"' "${ASSET}" "${CHECKSUM,,}" \
		>> "${MANIFEST_TEMP}"
done < "${RELEASE_DIRECTORY}/SHA256SUMS"
[[ "${FIRST}" == false ]] || {
	echo "checksum file is empty" >&2
	exit 1
}
printf '\n  }\n}\n' >> "${MANIFEST_TEMP}"

printf '%s\n' "${PASSFS_UPDATE_SIGNING_KEY}" > "${PRIVATE_KEY}"
openssl pkeyutl -sign -rawin \
	-inkey "${PRIVATE_KEY}" \
	-in "${MANIFEST_TEMP}" \
	-out "${SIGNATURE_BINARY}"
openssl base64 -A -in "${SIGNATURE_BINARY}" > "${SIGNATURE_TEMP}"
printf '\n' >> "${SIGNATURE_TEMP}"
chmod 0644 "${MANIFEST_TEMP}" "${SIGNATURE_TEMP}"
mv "${MANIFEST_TEMP}" "${MANIFEST}"
mv "${SIGNATURE_TEMP}" "${SIGNATURE}"

echo "Signed ${MANIFEST}"
