#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${PASSFS_VERSION:-}"
RELEASE="${ROOT}/release/v${VERSION}"
OUTPUT="${1:-${ROOT}/.pages}"

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] || {
	echo "PASSFS_VERSION must be a semantic release version." >&2
	exit 2
}
[[ -f "${RELEASE}/SHA256SUMS" ]] || {
	echo "Missing ${RELEASE}/SHA256SUMS." >&2
	exit 1
}
for SIGNED_METADATA in MANIFEST.json MANIFEST.sig; do
	[[ -f "${RELEASE}/${SIGNED_METADATA}" ]] || {
		echo "Missing ${RELEASE}/${SIGNED_METADATA}." >&2
		exit 1
	}
done
case "$(basename "${OUTPUT}")" in
	.pages | .pages-*)
		;;
	*)
		echo "refusing unexpected Pages output: ${OUTPUT}" >&2
		exit 1
		;;
esac

for REQUIRED_ASSET in \
	passfs-linux-x64.gz \
	passfs-linux-arm64.gz \
	PassFS-macos-universal.pkg; do
	[[ -f "${RELEASE}/${REQUIRED_ASSET}" ]] || {
		echo "Missing release asset: ${RELEASE}/${REQUIRED_ASSET}" >&2
		exit 1
	}
done

if command -v sha256sum >/dev/null 2>&1; then
	(cd "${RELEASE}" && sha256sum --check SHA256SUMS)
else
	(cd "${RELEASE}" && shasum -a 256 --check SHA256SUMS)
fi

OUTPUT_PARENT="$(dirname "${OUTPUT}")"
mkdir -p "${OUTPUT_PARENT}"
STAGED_OUTPUT="$(mktemp -d "${OUTPUT_PARENT}/.passfs-pages.XXXXXX")"
PREVIOUS_OUTPUT="${STAGED_OUTPUT}/previous"
trap 'rm -rf "${STAGED_OUTPUT}"' EXIT

mkdir -p \
	"${STAGED_OUTPUT}/site/releases/v${VERSION}" \
	"${STAGED_OUTPUT}/site/releases/latest"
sed "s/__PASSFS_VERSION__/${VERSION}/g" \
	"${ROOT}/site/index.html" > "${STAGED_OUTPUT}/site/index.html"
cp "${ROOT}/site/robots.txt" "${STAGED_OUTPUT}/site/robots.txt"
cp "${ROOT}/site/CNAME" "${STAGED_OUTPUT}/site/CNAME"
cp "${ROOT}/site/llms.txt" "${STAGED_OUTPUT}/site/llms.txt"
cp "${ROOT}/site/og.png" "${STAGED_OUTPUT}/site/og.png"
cp "${ROOT}/site/github.svg" "${STAGED_OUTPUT}/site/github.svg"
cp "${ROOT}/packaging/macos/AppIcon-1024.png" \
	"${STAGED_OUTPUT}/site/icon.png"
cp "${ROOT}/install.sh" "${STAGED_OUTPUT}/site/passfs"
cp "${RELEASE}/SHA256SUMS" \
	"${STAGED_OUTPUT}/site/releases/v${VERSION}/SHA256SUMS"
cp "${RELEASE}/MANIFEST.json" "${RELEASE}/MANIFEST.sig" \
	"${STAGED_OUTPUT}/site/releases/v${VERSION}/"
cp "${RELEASE}"/*.gz "${RELEASE}"/*.pkg \
	"${STAGED_OUTPUT}/site/releases/v${VERSION}/"
cp "${RELEASE}/SHA256SUMS" \
	"${STAGED_OUTPUT}/site/releases/latest/SHA256SUMS"
cp "${RELEASE}/MANIFEST.json" "${RELEASE}/MANIFEST.sig" \
	"${STAGED_OUTPUT}/site/releases/latest/"
cp "${RELEASE}"/*.gz "${RELEASE}"/*.pkg \
	"${STAGED_OUTPUT}/site/releases/latest/"
grep -Fq 'href="releases/latest/PassFS-macos-universal.pkg"' \
	"${STAGED_OUTPUT}/site/index.html" || {
	echo "The macOS download does not use the stable latest URL." >&2
	exit 1
}
grep -Fq 'curl -fsSL https://getpassfs.com/passfs | bash' \
	"${STAGED_OUTPUT}/site/llms.txt" || {
	echo "llms.txt does not contain the canonical Linux installer." >&2
	exit 1
}
grep -Fq 'passfs unprotect /absolute/path/to/.env' \
	"${STAGED_OUTPUT}/site/llms.txt" || {
	echo "llms.txt does not document single-file unprotect." >&2
	exit 1
}
printf '%s\n' "${VERSION}" \
	> "${STAGED_OUTPUT}/site/releases/latest.txt"
touch "${STAGED_OUTPUT}/site/.nojekyll"

if [[ "${PASSFS_FETCH_GITHUB_RELEASES:-0}" == "1" ]]; then
	command -v gh >/dev/null 2>&1 ||
		{ echo "gh is required to fetch historical releases." >&2; exit 1; }
	[[ -n "${GITHUB_REPOSITORY:-}" ]] ||
		{ echo "GITHUB_REPOSITORY is required." >&2; exit 1; }

	while IFS= read -r TAG; do
		[[ "${TAG}" == "v${VERSION}" ]] && continue
		[[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] ||
			continue
		DESTINATION="${STAGED_OUTPUT}/site/releases/${TAG}"
		mkdir -p "${DESTINATION}"
		gh release download "${TAG}" \
			--repo "${GITHUB_REPOSITORY}" \
			--dir "${DESTINATION}" \
			--pattern 'passfs-linux-*.gz' \
			--pattern 'PassFS-macos-universal.pkg' \
			--pattern 'SHA256SUMS'
		gh release download "${TAG}" \
			--repo "${GITHUB_REPOSITORY}" \
			--dir "${DESTINATION}" \
			--pattern 'MANIFEST.*' \
			2>/dev/null || true
	done < <(
		gh api --paginate \
			"repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
			--jq '.[] | select(.draft == false) | .tag_name'
	)
fi

find "${STAGED_OUTPUT}/site/releases" \
	-mindepth 1 -maxdepth 1 -type d -name 'v*' -exec basename {} \; |
	sort -r > "${STAGED_OUTPUT}/site/releases/versions.txt"

if find "${STAGED_OUTPUT}/site" -type f \
	\( -name '*.map' -o -name '*.go' -o -name '*.sh' \) \
	-print -quit |
	grep -q .; then
	echo "Pages artifact contains source code." >&2
	exit 1
fi
if find "${STAGED_OUTPUT}/site" -type l -print -quit | grep -q .; then
	echo "Pages artifact contains a symbolic link." >&2
	exit 1
fi

if [[ -e "${OUTPUT}" || -L "${OUTPUT}" ]]; then
	mv "${OUTPUT}" "${PREVIOUS_OUTPUT}"
fi
if ! mv "${STAGED_OUTPUT}/site" "${OUTPUT}"; then
	if [[ -e "${PREVIOUS_OUTPUT}" ]]; then
		mv "${PREVIOUS_OUTPUT}" "${OUTPUT}"
	fi
	exit 1
fi

echo "GitHub Pages artifact ready: ${OUTPUT}"
