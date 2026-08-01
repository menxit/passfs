# Development

## Requirements

- Go 1.26.5 or later
- macOS: Xcode 26 with the macOS 26 SDK for the native FSKit frontend
- macOS: macFUSE only for testing the compatibility frontend
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

`make check` runs the tests, `go vet`, and a build. On macOS it also builds the
macOS app UI, Go-to-Swift bridge, and FSKit extension, then validates the
extension metadata. Use `make test-race` manually when investigating
concurrency changes; it is not part of the release workflow.

The filesystem engine is exposed through `internal/fsapi`. Platform code lives
in independent adapters:

- `internal/fuseadapter` translates `fsapi` to go-fuse;
- `native/fskit` and `cmd/passfs-fskit-bridge` translate the same contract to
  Apple FSKit.

New frontends should implement the neutral `fsapi.FileSystem` boundary and add
their mount lifecycle through `filesystemAdapter`. The adapter also declares
whether caller process sessions are available and owns protected-link
registration. Native types must not leak into `internal/passfs`.

The macOS menu app and FSKit extension are sandboxed. Except for locations the
user explicitly chooses in the backup open/save panels, the menu app never reads
the user's repositories, secrets, or `~/.passfs` directly. It registers the
embedded `com.menxit.passfs.control-agent` with `SMAppService` and requests a
narrow allowlist of typed operations through a Unix socket in the PassFS App
Group. Executable names and CLI flags never cross that boundary. Full scans and
mutations have independent single-operation slots, and the server bounds the
number and size of concurrent clients.
While the manager is visible, known findings are revalidated every 2.5 seconds
so deletions and removed secret values disappear promptly. A complete directory
traversal runs at most every 15 seconds to discover new files without creating
continuous home-directory I/O.
The control agent validates the peer UID, code signature, Team ID, and bundle
identifier before executing a request. It remains unsandboxed because default
secret discovery intentionally spans likely credential and project locations
under the user's home. UI snapshot records contain masked previews and metadata
so the sandboxed app does not need read access to their source files.

The FSKit extension is sandboxed to its path resource. Its adapter therefore
validates project-side links in the CLI and updates vault metadata under
`metadata.lock`; every `Volume` metadata mutation takes the same inter-process
lock and merges the latest on-disk state. When Touch ID is disabled, the
extension forwards passphrase requests to the supervised CLI through a private
Unix socket in the App Group container. Both peers validate UID, code
signature, Team ID, and bundle identifier before exchanging a prompt. No
passphrase is persisted in the shared container.
Continuous project-side link
move/deletion tracking is still FUSE-only because safely coordinating backing
file namespace operations requires a broader companion control channel.

The authoritative security objectives, non-goals, audit status, and component
access table are maintained in `SECURITY.md`. Update them whenever a change
alters a trust boundary or adds data to an IPC message.

On macOS, `make install` is a maintainer-oriented target because a Touch
ID-capable app must be signed with the passfs Developer ID identity and
provisioning profile. End users should install the published package instead.

For a local passphrase-only build:

```sh
make install-unsigned
```
