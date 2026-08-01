# PassFS security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/menxit/passfs/security/advisories/new).
Include the affected PassFS and operating-system versions, adapter, steps to
reproduce, and whether the issue requires code already running as the same OS
user. Do not include real credentials or recovery passphrases.

Security fixes are made on the latest release line. Older releases may be used
to confirm a regression, but users should update before reporting a problem
that is already fixed in the current release.

## Audit status

PassFS has not received an independent security audit. Passing the automated
test suite, Apple notarization, or the signed-app checks is not a substitute for
one. Security-sensitive changes should include a regression test and an
explicit review of the affected trust boundary.

## Security objective

PassFS encrypts protected file contents at rest with `age` and requires the
configured local authorization before serving plaintext. Its primary objective
is to keep copied vaults, backups, and protected files unintelligible without
the recovery passphrase or an authorized device identity. It also reduces the
time credential files remain as ordinary plaintext in project directories.

PassFS does not defend against root, malware or an untrusted process already
running as the same user, an authorized application reading a protected file,
screen or keyboard capture, or an application copying plaintext elsewhere.
Full-disk encryption remains necessary. Original paths, sizes, timestamps,
project names, and detected secret-key names are metadata and are not encrypted.

Passphrases and plaintext exist transiently in process memory. A passphrase may
also exist in bounded local IPC buffers while FSKit requests authorization. It
is not written to the App Group container or PassFS logs.

## macOS trust boundaries

| Component | Sandbox | Files it can access | Exposed interface |
| --- | --- | --- | --- |
| Menu app | App Sandbox | Its container, the PassFS App Group, and locations explicitly selected in backup panels | Typed control-agent requests |
| FSKit extension | App Sandbox | The selected vault resource and App Group authorization socket | FSKit operations and passphrase request protocol |
| Control agent / CLI | Not sandboxed | Files available to the current user | Closed operation allowlist over a mode-0600 Unix socket |
| FUSE service | Not sandboxed | Files available to the current user | Local filesystem adapter |

The unsandboxed control agent is a deliberate limitation, not a claim that the
whole product is sandboxed. Secret discovery needs to inspect likely credential
locations under the user's home. Before reading a request, the agent checks the
socket peer UID, code signature, Team ID, and exact PassFS bundle identifier.
The wire protocol contains named operations and bounded fields; it does not
accept executable names, CLI arguments, arbitrary scan roots, or changes to
the mount path. Backup operations accept only a new non-existing destination
or an existing directory with the PassFS backup structure. Selected paths are
canonicalized, final-component symlinks are rejected, and restore never
overwrites an existing vault. Full scans and mutating operations are separately
serialized, and the agent accepts at most four concurrent clients.

When the manager is open, the agent revalidates known findings every 2.5
seconds and performs a complete discovery pass at most every 15 seconds. This
keeps secret removal responsive without continuously traversing the home
directory.

The UI receives paths and presentation metadata, including masked previews such
as `API_KEY=••••••`. It does not receive detected secret values. The FSKit
passphrase broker uses a separate socket and independently verifies both peers.

## Build and release evidence

`make check` runs the Go tests, static checks, cross-build, Swift compilation,
FSKit build, and packaging invariants. Release builds additionally run
`scripts/verify-macos-app.sh` against the signed application itself. That check
verifies nested signatures, Developer ID team consistency, hardened runtime,
the sandbox and App Group entitlements, and the absence of network-client
entitlements from the UI, helper, and FSKit extension.
CI also runs the Go race detector and `govulncheck`; third-party GitHub Actions
are referenced by immutable commit hashes.

The test suite still cannot prove the absence of vulnerabilities. In
particular, filesystem race behavior and OS integration should be tested on the
macOS versions supported by each release.
