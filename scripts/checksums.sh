#!/usr/bin/env bash

set -euo pipefail

RELEASE_DIRECTORY="${1:-}"
[[ -d "${RELEASE_DIRECTORY}" ]] || {
	echo "usage: $0 RELEASE_DIRECTORY" >&2
	exit 2
}

ASSET_LIST="$(
	find "${RELEASE_DIRECTORY}" -maxdepth 1 -type f \
		\( -name '*.gz' -o -name '*.pkg' \) \
		-print |
		sort
)"
[[ -n "${ASSET_LIST}" ]] || {
	echo "no release assets found in ${RELEASE_DIRECTORY}" >&2
	exit 1
}

TEMPORARY="$(mktemp "${RELEASE_DIRECTORY}/.SHA256SUMS.XXXXXX")"
trap 'rm -f "${TEMPORARY}"' EXIT

while IFS= read -r ASSET; do
	NAME="$(basename "${ASSET}")"
	if command -v sha256sum >/dev/null 2>&1; then
		HASH="$(sha256sum "${ASSET}" | awk '{ print $1 }')"
	else
		HASH="$(shasum -a 256 "${ASSET}" | awk '{ print $1 }')"
	fi
	printf '%s  %s\n' "${HASH}" "${NAME}" >> "${TEMPORARY}"
done <<< "${ASSET_LIST}"

mv "${TEMPORARY}" "${RELEASE_DIRECTORY}/SHA256SUMS"
trap - EXIT
echo "Wrote ${RELEASE_DIRECTORY}/SHA256SUMS"
