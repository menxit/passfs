# Development

## Requirements

- Go 1.26.5 or later
- macOS: macFUSE
- Linux: FUSE

## Test the server password UI

Build and enter the minimal Linux container:

```sh
make docker-server-shell
```

Inside the container, run:

```sh
passfs doctor --test-prompt
```

The image has passfs, FUSE, and a systemd user session installed. The Make
target starts an ephemeral privileged container so systemd and `/dev/fuse` can
run, then opens a shell as the unprivileged `tester` user. It has no graphical
desktop, so the command opens the full-screen terminal authorization UI,
discards the entered value, and reports whether the prompt completed
successfully. Exiting the shell removes the container.

The complete mount flow can also be tested:

```sh
passfs init
passfs mount
passfs status
```

Clone and build:

```sh
git clone https://github.com/menxit/passfs.git passfs
cd passfs
make
```

The default branch is `dev`. Open development pull requests against `dev`;
`main` contains only release-ready changes.

Run the normal verification suite:

```sh
make check
```

`make check` runs the tests, `go vet`, and a build. Use `make test-race`
manually when investigating concurrency changes; it is not part of the release
workflow.

On macOS, `make install` is a maintainer-oriented target because a Touch
ID-capable app must be signed with the passfs Developer ID identity and
provisioning profile. End users should install the published package instead.

For a local passphrase-only build:

```sh
make install-unsigned
```
