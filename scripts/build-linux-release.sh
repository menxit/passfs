#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"
OUTPUT="${2:-}"

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] || {
	echo "usage: $0 VERSION OUTPUT_DIRECTORY" >&2
	exit 2
}
[[ -n "${OUTPUT}" ]] || {
	echo "usage: $0 VERSION OUTPUT_DIRECTORY" >&2
	exit 2
}

mkdir -p "${OUTPUT}"
BUILD_DIRECTORY="$(mktemp -d "${OUTPUT}/.passfs-linux-build.XXXXXX")"
trap 'rm -rf "${BUILD_DIRECTORY}"' EXIT

for ARCHITECTURE in amd64 arm64; do
	case "${ARCHITECTURE}" in
		amd64) RELEASE_ARCHITECTURE="x64" ;;
		arm64) RELEASE_ARCHITECTURE="arm64" ;;
	esac

	BINARY="${BUILD_DIRECTORY}/passfs-${ARCHITECTURE}"
	ASSET="${OUTPUT}/passfs-linux-${RELEASE_ARCHITECTURE}.gz"
	(
		cd "${ROOT}"
		CGO_ENABLED=0 GOOS=linux GOARCH="${ARCHITECTURE}" \
			env -u GOROOT GOWORK=off go build \
			-trimpath \
			-ldflags "-s -w -X main.version=${VERSION}" \
			-o "${BINARY}" \
			./cmd/passfs
	)
	gzip -9 -n -c "${BINARY}" > "${BUILD_DIRECTORY}/asset.gz"
	mv "${BUILD_DIRECTORY}/asset.gz" "${ASSET}"
	echo "Built Linux release: ${ASSET}"
done
