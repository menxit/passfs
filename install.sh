#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${PASSFS_RELEASE_BASE:-https://getpassfs.com/releases}"
INSTALL_DIRECTORY="${PASSFS_INSTALL_DIR:-${HOME}/.local/bin}"
VERSION="${PASSFS_VERSION:-}"
APT_UPDATED=0

say() {
	printf 'passfs: %s\n' "$*"
}

fail() {
	printf 'passfs: error: %s\n' "$*" >&2
	exit 1
}

run_privileged() {
	if [[ "${EUID}" -eq 0 ]]; then
		"$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo "$@"
	else
		fail "a required system package is missing and sudo is unavailable."
	fi
}

fuse_ready() {
	[[ -e /dev/fuse ]] &&
		{ command -v fusermount3 >/dev/null 2>&1 ||
			command -v fusermount >/dev/null 2>&1; }
}

install_fuse() {
	[[ "${PASSFS_NO_INSTALL_FUSE:-0}" != "1" ]] ||
		fail "FUSE is missing; install fuse3 and run the installer again."

	say "FUSE is missing; installing fuse3"
	install_system_package fuse3

	if [[ ! -e /dev/fuse ]] && command -v modprobe >/dev/null 2>&1; then
		run_privileged modprobe fuse || true
	fi
	fuse_ready ||
		fail "fuse3 is installed but /dev/fuse or fusermount is unavailable; check the kernel and container permissions."
}

install_system_package() {
	local package_name="$1"
	if command -v apt-get >/dev/null 2>&1; then
		if [[ "${APT_UPDATED}" -eq 0 ]]; then
			run_privileged apt-get update
			APT_UPDATED=1
		fi
		run_privileged apt-get install -y "${package_name}"
	elif command -v dnf >/dev/null 2>&1; then
		run_privileged dnf install -y "${package_name}"
	elif command -v yum >/dev/null 2>&1; then
		run_privileged yum install -y "${package_name}"
	elif command -v zypper >/dev/null 2>&1; then
		run_privileged zypper --non-interactive install "${package_name}"
	elif command -v pacman >/dev/null 2>&1; then
		run_privileged pacman -S --needed --noconfirm "${package_name}"
	elif command -v apk >/dev/null 2>&1; then
		run_privileged apk add "${package_name}"
	else
		fail "unsupported package manager; install ${package_name} and run the installer again."
	fi
}

graphical_session() {
	[[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]
}

graphical_prompt_ready() {
	command -v zenity >/dev/null 2>&1 ||
		command -v kdialog >/dev/null 2>&1 ||
		command -v yad >/dev/null 2>&1 ||
		command -v qarma >/dev/null 2>&1
}

install_graphical_prompt() {
	[[ "${PASSFS_NO_INSTALL_DIALOG:-0}" != "1" ]] || return 0
	graphical_session || return 0
	if ! graphical_prompt_ready; then
		say "desktop session detected; installing zenity for password dialogs"
		install_system_package zenity
	fi
	graphical_prompt_ready ||
		fail "zenity was installed but no graphical password dialog is available."

	if ! command -v notify-send >/dev/null 2>&1; then
		say "installing desktop update notifications"
		if command -v apt-get >/dev/null 2>&1; then
			install_system_package libnotify-bin
		else
			install_system_package libnotify
		fi
	fi
}

[[ "$(uname -s)" == "Linux" ]] ||
	fail "this installer is for Linux; download the signed macOS package from https://getpassfs.com/"
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v gzip >/dev/null 2>&1 || fail "gzip is required."
command -v systemctl >/dev/null 2>&1 ||
	fail "systemd is required to supervise the passfs user service."
[[ -n "${INSTALL_DIRECTORY}" && "${INSTALL_DIRECTORY}" == /* &&
	"${INSTALL_DIRECTORY}" != *:* &&
	"${INSTALL_DIRECTORY}" != *$'\n'* ]] ||
	fail "PASSFS_INSTALL_DIR must be an absolute path without colons or newlines."

if [[ -z "${VERSION}" ]]; then
	VERSION="$(curl -fsSL "${BASE_URL}/latest.txt")"
	VERSION_URL="${BASE_URL}/latest"
else
	VERSION="${VERSION#v}"
	VERSION_URL="${BASE_URL}/v${VERSION}"
fi
VERSION="${VERSION#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] ||
	fail "invalid release version."

case "$(uname -m)" in
	x86_64 | amd64) ARCHITECTURE="x64" ;;
	arm64 | aarch64) ARCHITECTURE="arm64" ;;
	*) fail "unsupported architecture: $(uname -m)" ;;
esac

ASSET="passfs-linux-${ARCHITECTURE}.gz"
TEMPORARY_DIRECTORY="$(mktemp -d 2>/dev/null || mktemp -d -t passfs)"
STAGED_BINARY=""

cleanup() {
	if [[ -n "${STAGED_BINARY}" &&
		( -e "${STAGED_BINARY}" || -L "${STAGED_BINARY}" ) ]]; then
		unlink "${STAGED_BINARY}" || true
	fi
	rm -rf "${TEMPORARY_DIRECTORY}"
}
trap cleanup EXIT

say "downloading passfs ${VERSION} for linux/${ARCHITECTURE}"
curl -fsSL "${VERSION_URL}/${ASSET}" \
	-o "${TEMPORARY_DIRECTORY}/${ASSET}"
curl -fsSL "${VERSION_URL}/SHA256SUMS" \
	-o "${TEMPORARY_DIRECTORY}/SHA256SUMS"

EXPECTED="$(
	awk -v asset="${ASSET}" \
		'$2 == asset || $2 == ("./" asset) { print $1; exit }' \
		"${TEMPORARY_DIRECTORY}/SHA256SUMS"
)"
[[ -n "${EXPECTED}" ]] || fail "checksum not found for ${ASSET}."

if command -v sha256sum >/dev/null 2>&1; then
	ACTUAL="$(
		sha256sum "${TEMPORARY_DIRECTORY}/${ASSET}" |
			awk '{ print $1 }'
	)"
elif command -v shasum >/dev/null 2>&1; then
	ACTUAL="$(
		shasum -a 256 "${TEMPORARY_DIRECTORY}/${ASSET}" |
			awk '{ print $1 }'
	)"
else
	fail "sha256sum or shasum is required to verify the download."
fi

[[ "${ACTUAL,,}" == "${EXPECTED,,}" ]] ||
	fail "checksum verification failed."

fuse_ready || install_fuse
install_graphical_prompt
[[ -r /dev/fuse && -w /dev/fuse ]] ||
	fail "/dev/fuse is not accessible to the current user; fix its permissions and run the installer again."

mkdir -p "${INSTALL_DIRECTORY}"
STAGED_BINARY="${INSTALL_DIRECTORY}/.passfs-install-$$"
gzip -dc "${TEMPORARY_DIRECTORY}/${ASSET}" > "${STAGED_BINARY}"
chmod 0755 "${STAGED_BINARY}"
mv "${STAGED_BINARY}" "${INSTALL_DIRECTORY}/passfs"
STAGED_BINARY=""

if [[ ":${PATH}:" != *":${INSTALL_DIRECTORY}:"* &&
	"${PASSFS_NO_MODIFY_PATH:-0}" != "1" ]]; then
	PROFILE="${HOME}/.profile"
	if [[ "${SHELL:-}" == */zsh ]]; then
		PROFILE="${HOME}/.zprofile"
	elif [[ "${SHELL:-}" == */bash && -f "${HOME}/.bashrc" ]]; then
		PROFILE="${HOME}/.bashrc"
	fi
	PATH_LINE="export PATH=\"${INSTALL_DIRECTORY}:\$PATH\""
	if [[ ! -f "${PROFILE}" ]] ||
		! grep -Fq -- "${PATH_LINE}" "${PROFILE}"; then
		{
			printf '\n# passfs\n'
			printf '%s\n' "${PATH_LINE}"
		} >> "${PROFILE}"
	fi
fi

say "installed ${INSTALL_DIRECTORY}/passfs"
if [[ -f "${HOME}/.config/passfs/config.json" ]]; then
	if "${INSTALL_DIRECTORY}/passfs" reload; then
		say "reloaded the passfs service"
	else
		say "warning: installation succeeded, but the existing service could not be reloaded"
	fi
fi
if [[ ":${PATH}:" != *":${INSTALL_DIRECTORY}:"* ]]; then
	say "restart your shell, then run: passfs init"
else
	say "run: passfs init"
fi
