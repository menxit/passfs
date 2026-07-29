#!/usr/bin/env bash

set -euo pipefail

git rev-parse --verify HEAD >/dev/null

is_release_tag() {
	[[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# A workflow rerun for an already released commit must reuse its version.
while IFS= read -r tag; do
	if is_release_tag "${tag}"; then
		printf '%s\n' "${tag#v}"
		exit 0
	fi
done < <(git tag --points-at HEAD --sort=-v:refname)

latest_tag=""
while IFS= read -r tag; do
	if is_release_tag "${tag}"; then
		latest_tag="${tag}"
		break
	fi
done < <(git tag --merged HEAD --sort=-v:refname)

if [[ -z "${latest_tag}" ]]; then
	printf '0.1.0\n'
	exit 0
fi

messages="$(git log "${latest_tag}..HEAD" --format='%s%n%b')"
if [[ -z "${messages}" ]]; then
	echo "no commits found after ${latest_tag}" >&2
	exit 1
fi

bump="patch"
if grep -Eiq \
	'(^[[:alnum:]_-]+(\([^)]*\))?!:)|(^BREAKING[ -]CHANGE:)' \
	<<<"${messages}"; then
	bump="major"
elif grep -Eiq '^feat(\([^)]*\))?:' <<<"${messages}"; then
	bump="minor"
fi

version="${latest_tag#v}"
IFS=. read -r major minor patch <<<"${version}"
case "${bump}" in
	major)
		major=$((major + 1))
		minor=0
		patch=0
		;;
	minor)
		minor=$((minor + 1))
		patch=0
		;;
	patch)
		patch=$((patch + 1))
		;;
esac

printf '%d.%d.%d\n' "${major}" "${minor}" "${patch}"
