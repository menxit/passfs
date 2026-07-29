#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_repository="$(mktemp -d)"
trap 'rm -rf "${test_repository}"' EXIT

git -C "${test_repository}" init --quiet
git -C "${test_repository}" config user.name "passfs tests"
git -C "${test_repository}" config user.email "passfs-tests@example.invalid"

commit() {
	git -C "${test_repository}" commit --quiet --allow-empty -m "$1"
}

assert_version() {
	local expected="$1"
	local actual
	actual="$(cd "${test_repository}" && "${root}/scripts/next-version.sh")"
	if [[ "${actual}" != "${expected}" ]]; then
		printf 'version = %s, want %s\n' "${actual}" "${expected}" >&2
		exit 1
	fi
}

commit "chore: initial source"
assert_version "0.1.0"

git -C "${test_repository}" tag v0.1.0
assert_version "0.1.0"

commit "fix: preserve encrypted metadata"
assert_version "0.1.1"

git -C "${test_repository}" tag v0.1.1
commit "feat(cli): add status output"
assert_version "0.2.0"

git -C "${test_repository}" tag v0.2.0
commit "refactor!: change the vault format"
assert_version "1.0.0"

git -C "${test_repository}" tag v1.0.0
commit $'docs: explain migration\n\nBREAKING CHANGE: remove the old command'
assert_version "2.0.0"

echo "Version tests passed"
