<p align="center">
  <img src="packaging/macos/AppIcon-1024.png" alt="passfs icon" width="144">
</p>

# passfs

`passfs` stores selected files encrypted with
[age](https://age-encryption.org/) and keeps them available at their original
paths through one local virtual filesystem and symbolic links. Decrypted
contents stay in memory and every file open requires authorization by default.
On macOS 26 and later, the default frontend is Apple FSKit; FUSE remains the
compatibility frontend for older systems.

## Supported platforms

- macOS
- Linux

## Requirements

- macOS 26 or later: the native Apple FSKit frontend included in PassFS.app
- macOS 13–15: macFUSE compatibility frontend
- Linux: a systemd user session; the installer configures FUSE automatically
  when supported by the distribution package manager

## Installation

### macOS

Download and open the signed and notarized installer:

[Download passfs for macOS](https://getpassfs.com/)

The package installs `PassFS.app` in `/Applications`, starts its menu bar
control, and installs the `passfs` command in `/usr/local/bin`.

To uninstall PassFS while preserving the encrypted vault:

```sh
/Applications/PassFS.app/Contents/Resources/uninstall-passfs.sh
```

Add `--purge-data` only if the vault should also be moved to the Trash.

Open PassFS after installation. The app initializes and mounts the protected
filesystem automatically. The same operation is available from the terminal:

```sh
passfs init
```

If the native frontend needs one-time approval, PassFS opens a guided window
with the correct system control, waits for approval, and then continues
mounting. This does not require a kernel extension, reduced security, or
macFUSE.

On older macOS releases, `init` reports how to install the macFUSE
compatibility frontend. `setup`, `doctor`, and `mount` remain available as
advanced troubleshooting commands, but are not part of the normal first run.

Installing a newer package also reloads an existing passfs service.

### Linux

```sh
curl -fsSL https://getpassfs.com/passfs | bash
```

The installer selects the `x64` or `arm64` binary, verifies its SHA-256
checksum, installs it in `~/.local/bin`, and installs `fuse3` with the detected
package manager when needed. On a desktop it also installs a graphical
password dialog and update notifications when the distribution does not
provide them. System package installation may request `sudo`.
Set `PASSFS_NO_INSTALL_FUSE=1` to require FUSE to be installed in advance.

## Initial configuration

Run once:

```sh
passfs init
```

This creates one age identity and one encrypted vault shared by every protected
file, prepares the best filesystem adapter for the platform, installs its
background service, and mounts it:

```text
~/.passfs/
├── config.json
├── mnt/
└── vault/
```

`init` returns after mounting at `~/.passfs/mnt`. Existing installations under
`~/.config/passfs` are migrated automatically after the filesystem is safely
stopped. It is idempotent: if
platform approval interrupted the first attempt, enable the extension and run
the same command again. The filesystem
runs as a supervised background service, survives terminal closure, restarts
after a failure, and starts automatically after login. On macOS it is also
shown in Finder as the `passfs` volume.

Only one passfs filesystem is mounted for all protected files.

`passfs init` automatically selects the best available filesystem frontend,
preferring the native macOS implementation.

## Encrypt a file

Given:

```text
/Users/menxit/Development/project/.env
```

run:

```sh
passfs encrypt /Users/menxit/Development/project/.env
```

`passfs` asks for authorization, encrypts the file, and removes its plaintext
contents. The original pathname becomes a symbolic link:

```text
/Users/menxit/Development/project/.env
    -> ~/.passfs/mnt/by-id/8c9dbbe8-9295-4dc4-a7e4-ec40a185c2f2
```

Applications keep using the original path:

```js
fs.readFileSync("/Users/menxit/Development/project/.env", "utf8")
```

Following the link opens the protected file through passfs and requests
authorization. No change is required in the application. The same command
works with any regular file, not only `.env` files:

```sh
passfs encrypt file.md config/settings.json
```

When several files are passed, passfs requests authorization once and keeps
the age identity in memory only for that command. The authorization is scoped
to the `passfs` process and is discarded when the command ends.

## Find unprotected secrets

Scan the current repository and the usual user credential/config locations:

```sh
passfs scan
```

Scan a specific tree, or every relevant user-data root:

```sh
passfs scan ~/Development
passfs scan --all
```

In an interactive terminal, `passfs scan` groups results by Git repository and
shows the filename, project, size, last-opened time, and a masked preview. Select
individual files, ranges, or all results to protect them in one operation.
Files that should not appear again can be ignored from the same prompt.

The scanner skips Git-tracked files, existing PassFS links, the vault,
dependencies, package vendors, build output, caches, examples, tests, and
platform system trees. It recognizes common AWS, Google Cloud, Azure, SSH,
container, Kubernetes, package-manager, and environment credential formats on
macOS and Linux. Secret values are never printed. For scripts and integrations,
`--json`, `-0`, and `--no-interactive` return paths only.

The macOS app provides the same project-grouped view for unprotected, protected,
and ignored files in a dedicated, resizable management window. It includes
masked previews, search, file size, last-opened metadata, one-click protect,
unprotect, ignore and restore actions, and a badge showing the current number
of unprotected files. The menu bar control is intentionally compact: it shows
the filesystem status, starts or stops PassFS, and opens the management window.
The interface defaults to English and is also available in Italian, German,
French, Spanish, and Portuguese. PassFS initializes and mounts automatically
when the app starts. Touch ID is enabled by default, and the default unlock
duration is `0m`.

Running `passfs encrypt FILE` again is safe. If an older passfs version already
encrypted the file but removed its original pathname, the command recreates the
missing link without re-encrypting the data.

Deleting the symbolic link deletes its encrypted file shortly afterward. If the
service observes the deletion, deleting a directory containing protected links
has the same effect. Renaming a protected link, moving it to another directory,
or renaming one of its parent directories is tracked automatically while
passfs is running, as long as the move stays on the same filesystem.

When passfs starts, it reconciles protected links that were renamed, moved, or
deleted while the filesystem was stopped. A moved link keeps its original
contents at the new pathname; a deleted link also removes its encrypted copy,
so the old pathname can immediately be reused and protected again.

Do not replace a protected link with a regular file. Some editors implement
atomic saves by replacing the pathname and can therefore bypass the link.

If a command reports an unavailable mount, recover it with:

```sh
passfs reload
```

## Remove protection

To convert one protected link back into a regular plaintext file while leaving
every other file protected:

```sh
passfs unprotect /absolute/path/to/.env
```

The service is stopped briefly and restored automatically if it was active.
The command requires typing `UNPROTECT`, writes the plaintext atomically, and
permanently deletes that file's encrypted copy only after the write succeeds.

To convert every protected link back into a regular plaintext file:

```sh
passfs unprotect
```

The command displays a security warning and requires typing `UNPROTECT`. It
unmounts passfs, requests authorization once, writes each plaintext file
atomically, and then permanently deletes its encrypted copy. If a pathname has
changed or conflicts with another file, that ciphertext is preserved and the
problem is reported.

After a successful run, passfs remains initialized but is unmounted and
automatic startup is disabled.

## Passphrase frequency

The default is:

```sh
passfs config --unlock-for 0
```

Every open asks for Touch ID on macOS or the passphrase on Linux. To keep the
vault unlocked for five minutes after a successful authorization:

```sh
passfs config --unlock-for 5m
```

The cache applies to the whole vault and exists only in the passfs process
memory. On macOS it is cleared whenever the computer sleeps or wakes, so the
next protected-file open always requires a new authorization. If the filesystem
is running, `passfs config` restarts it automatically so the new duration takes
effect immediately.

Change the global passphrase with:

```sh
passfs passwd
```

This re-encrypts the single age identity; it does not need to re-encrypt every
file.

## Touch ID on macOS

`passfs init` enables Touch ID by default on supported Macs. A device-local copy
of the age identity is protected by the currently enrolled fingerprints.

On a Mac without Touch ID, initialization continues normally and reports that
passphrase authorization will be used instead. FSKit remains the native
frontend; macFUSE is not selected merely because Touch ID is disabled. With
`--unlock-for 0`, every protected file open then asks for the passphrase.

When Touch ID is enabled, the default `--unlock-for 0` requires it for every
file open. `passfs edit FILE` requires it once for the whole edit session.

Check or disable it with:

```sh
passfs touchid status
passfs touchid disable
passfs reload
```

Changing the fingerprints enrolled on the Mac invalidates the protected copy;
use `passfs touchid -h` to restore it with the passphrase. Touch ID does not
replace the backup described below: its copy is tied to this Mac and is not a
recovery key. Linux continues to use the passphrase.

## Service commands

```sh
passfs status
passfs reload
passfs unmount
passfs mount
```

Use `passfs reload` after installing a new passfs version or changing its
configuration. It unmounts and starts the supervised filesystem again without
disabling automatic startup.

`passfs unmount` also disables automatic startup. Running `passfs mount` enables
it again.

## Updates

The background service checks GitHub Pages at most once per day. macOS and
Linux desktops receive a passive notification when a new release is
available; terminal commands also report the cached update.

Check without installing:

```sh
passfs update --check
```

Install the update:

```sh
passfs update
```

On macOS, passfs verifies the package checksum, Developer ID Installer
signature, and Gatekeeper assessment before opening the standard macOS
Installer. On Linux, it verifies the checksum and embedded version, replaces
the user-installed executable atomically, and reloads the service. Updates are
never installed silently.

## Encrypted layout

Each protected file receives an immutable random identifier. Its encrypted
object is stored independently of the original pathname:

```text
~/.passfs/vault/
├── .passfs/
│   ├── config.json
│   ├── identity.age
│   └── metadata.json
└── objects/
    └── 8c9dbbe8-9295-4dc4-a7e4-ec40a185c2f2.age
```

The original pathname is kept only in protected metadata. Renaming or moving
the symbolic link does not rename or move the encrypted object. Existing
vaults using the previous path-based layout are migrated automatically.

## Backup

The age private identity is stored at:

```text
~/.passfs/vault/.passfs/identity.age
```

Copy it to a secure offline location:

```sh
cp ~/.passfs/vault/.passfs/identity.age /path/to/secure-backup/identity.age
```

`identity.age` is encrypted with the passphrase chosen during `passfs init`.
Store that passphrase separately in a password manager. The device-local Touch
ID copy is not a substitute for this backup.

## Security limitations

passfs does not write decrypted protected-file contents to its own backing
storage, but it cannot hide plaintext from the application that opens a file.
Plaintext exists in the passfs process memory and is delivered to the requesting
process.

Applications may copy secrets into logs, caches, crash dumps, or other files.
The initial import removes the live plaintext pathname but cannot securely erase
previous SSD blocks, snapshots, or backups. Software running as the same OS user
may also inspect processes or access a file while it is authorized.
During a `passfs edit` session, this includes other processes running as the
same user that open the file being edited.

A process that can write to the protected file's parent directory can remove its
symbolic link and thereby delete the ciphertext. If it replaces the link with a
new entry, passfs preserves the ciphertext and refuses to overwrite that entry,
but it cannot prevent an unprotected plaintext file from occupying the original
pathname. Use `passfs edit` or software known to preserve symbolic links.

Use full-disk encryption, trusted applications, restricted permissions, and an
appropriate backup policy as additional protections.

## License

MIT. See [LICENSE.md](LICENSE.md).

Development and release procedures are documented in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) and
[docs/RELEASING.md](docs/RELEASING.md).

Machine-readable installation, usage, and safety guidance is available at
[getpassfs.com/llms.txt](https://getpassfs.com/llms.txt).
