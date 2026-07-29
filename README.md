<p align="center">
  <img src="packaging/macos/AppIcon-1024.png" alt="passfs icon" width="144">
</p>

# passfs

`passfs` stores selected files encrypted with
[age](https://age-encryption.org/) and keeps them available at their original
paths through one local FUSE filesystem and symbolic links. Decrypted contents
stay in memory and every file open requires authorization by default.

## Supported platforms

- macOS
- Linux

## Requirements

- macOS 13 or later; `passfs setup` guides the required macFUSE installation
- Linux: a systemd user session; the installer configures FUSE automatically
  when supported by the distribution package manager

## Installation

### macOS

Download and open the signed and notarized installer:

[Download passfs for macOS](https://menxit.github.io/passfs/)

The package installs `PassFS.app` in `/Applications` and the `passfs` command
in `/usr/local/bin`. The application is already signed by the passfs
developer; users do not need an Apple Developer certificate, a provisioning
profile, Go, or Git.

Before the first mount, run:

```sh
passfs setup
```

If macFUSE is missing, passfs opens its official download page and explains
how to finish setup. It never installs a system extension silently. Check the
result at any time with `passfs doctor`.

Installing a newer package also reloads an existing passfs service.

### Linux

```sh
curl -fsSL https://menxit.github.io/passfs/passfs | bash
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
file on the computer:

```text
~/.config/passfs/
├── config.json
├── mnt/
└── vault/
```

Start the filesystem:

```sh
passfs mount
```

The command returns after mounting at `~/.config/passfs/mnt`. The filesystem
runs as a supervised background service, survives terminal closure, restarts
after a failure, and starts automatically after login. On macOS it is also
shown in Finder as the `passfs` volume.

Only one passfs filesystem is mounted for all protected files.

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
    -> ~/.config/passfs/mnt/Users/menxit/Development/project/.env
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

Linux desktops show a password window. On a server or SSH terminal, passfs
uses a full-screen terminal prompt associated with the process opening the
file. Test the selected prompt without opening a protected file:

```sh
passfs doctor --test-prompt
```

Running `passfs encrypt FILE` again is safe. If an older passfs version already
encrypted the file but removed its original pathname, the command recreates the
missing link without re-encrypting the data.

Deleting the symbolic link deletes its encrypted file shortly afterward. If the
service is stopped, the deletion is applied at the next mount. Deleting a
directory containing protected links has the same effect. Moving a protected
link is treated as deleting its old pathname; moving protected links is not
currently supported.

Do not replace a protected link with a regular file. Some editors implement
atomic saves by replacing the pathname and can therefore bypass the link.

If a command reports an unavailable mount, recover it with:

```sh
passfs reload
```

## Remove protection

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

Every open asks for Touch ID on macOS or the passphrase on Linux. To authorize
each opened file for five minutes:

```sh
passfs config --unlock-for 5m
```

The cache is per file and exists only in the passfs process memory. Restart the
service after changing this value:

```sh
passfs reload
```

Change the global passphrase with:

```sh
passfs passwd
```

This re-encrypts the single age identity; it does not need to re-encrypt every
file.

## Touch ID on macOS

`passfs init` attempts to enable Touch ID by default on macOS. A device-local
copy of the age identity is protected by the currently enrolled fingerprints.
The distributed application includes the Developer ID signature, provisioning
profile, and Keychain entitlements required by macOS.

On a Mac without Touch ID, initialization continues normally and reports that
passphrase authorization will be used instead. With `--unlock-for 0`, every
protected file open then asks for the passphrase.

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

The source:

```text
/Users/menxit/Development/project/.env
```

is stored as:

```text
~/.config/passfs/vault/
├── .passfs/
│   ├── config.json
│   ├── identity.age
│   └── metadata.json
└── files/
    └── Users/
        └── menxit/
            └── Development/
                └── project/
                    └── .env.age
```

The absolute path is recreated only to organize encrypted files. passfs does
not maintain a project registry and does not copy other project files.

## Backup

The age private identity is stored at:

```text
~/.config/passfs/vault/.passfs/identity.age
```

Copy it to a secure offline location:

```sh
cp ~/.config/passfs/vault/.passfs/identity.age /path/to/secure-backup/identity.age
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
