#!/usr/bin/env bash

set -euo pipefail

DOCKER="${DOCKER:-docker}"
IMAGE="${1:-passfs-server-test}"
CONTAINER="passfs-server-test-$$"

cleanup() {
	"${DOCKER}" rm --force "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

"${DOCKER}" run \
	--detach \
	--name "${CONTAINER}" \
	--privileged \
	--tmpfs /run \
	--tmpfs /run/lock \
	"${IMAGE}" >/dev/null

for _ in $(seq 1 100); do
	if "${DOCKER}" exec "${CONTAINER}" \
		test -S /run/user/1000/bus; then
		break
	fi
	sleep 0.1
done

if ! "${DOCKER}" exec "${CONTAINER}" \
	test -S /run/user/1000/bus; then
	"${DOCKER}" logs "${CONTAINER}" >&2 || true
	printf '%s\n' \
		"passfs: the container systemd user session did not become ready" >&2
	exit 1
fi

"${DOCKER}" exec \
	--interactive \
	--tty \
	--user tester \
	--env HOME=/home/tester \
	--env USER=tester \
	--env LOGNAME=tester \
	--env XDG_RUNTIME_DIR=/run/user/1000 \
	--env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
	"${CONTAINER}" \
	/bin/bash --login
