# Releasing passfs

The release process signs and notarizes passfs once. End users receive an
already trusted installer and never need access to Apple certificates,
provisioning profiles, or notarization credentials.

## Apple credentials

Create and retain these maintainer-only assets:

1. A **Developer ID Application** certificate with its private key, used to
   sign `PassFS.app`.
2. A **Developer ID Installer** certificate with its private key, used to sign
   `PassFS-macos-universal.pkg`.
3. A Developer ID provisioning profile for `com.menxit.passfs` containing the
   Keychain access group required by Touch ID.
4. A team App Store Connect API key accepted by `notarytool`. Individual API
   keys cannot use the notarization service.

Apple documents the two certificate types in
[Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
and the submission process in
[Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

Export both certificates together with their private keys as one
password-protected `.p12`. Back up that `.p12`, its password, the provisioning
profile, and the notarization key in encrypted maintainer storage. Never commit
them to the repository.

## GitHub configuration

Set GitHub Pages to use **GitHub Actions**. Create a `release` environment,
optionally protect it with required approval, then add these environment
secrets:

| Secret | Value |
| --- | --- |
| `MACOS_SIGNING_CERTIFICATES_P12_BASE64` | Base64-encoded `.p12` containing both Developer ID identities |
| `MACOS_SIGNING_CERTIFICATES_PASSWORD` | Password of the signing `.p12` |
| `MACOS_PROVISIONING_PROFILE_BASE64` | Base64-encoded provisioning profile |
| `MACOS_NOTARY_KEY_P8_BASE64` | Base64-encoded team App Store Connect `.p8` key |
| `MACOS_NOTARY_KEY_ID` | App Store Connect key ID |
| `MACOS_NOTARY_ISSUER_ID` | App Store Connect issuer ID |

Encode a binary secret on macOS with:

```sh
base64 -i /path/to/file | pbcopy
```

Paste the result directly into the corresponding GitHub secret. Base64 is only
an encoding; GitHub Actions secrets provide the protected storage.

Restrict write access to the repository. The macOS job is attached to the
`release` environment, so its protection rules run before Apple credentials
are exposed to the runner.

## Publish a release

The default branch is `dev`. A push to `main` starts a release automatically;
do not create release tags manually. Keep `main` protected and update it only
with reviewed, release-ready changes from `dev`.

The first release is `0.1.0`. Later versions are calculated from every commit
since the previous release:

- `feat:` or `feat(scope):` increments the minor version;
- a conventional commit with `!`, or a `BREAKING CHANGE:` footer, increments
  the major version;
- every other change increments the patch version.

The highest required increment wins when a release contains several commits.
For example, changes after `v0.4.2` produce `0.5.0` when at least one commit is
`feat:`, or `1.0.0` when at least one commit is breaking.

The release workflow:

1. calculates the next semantic version;
2. runs the normal checks on macOS and Linux and the race detector on Linux;
3. builds checksum-verifiable Linux `x64` and `arm64` executables;
4. builds a universal macOS app, signs it with Developer ID Application, and
   notarizes and staples it;
5. packages the app and `/usr/local/bin/passfs` in a Developer ID
   Installer-signed `.pkg`, then notarizes and staples the package;
6. creates the version tag and publishes the assets and `SHA256SUMS` in a
   GitHub Release only after every build succeeds;
7. rebuilds GitHub Pages with the current and historical release assets.

Release runs are serialized, and rerunning a workflow for an already tagged
commit reuses that version. The public layout follows:

```text
https://menxit.github.io/passfs/
https://menxit.github.io/passfs/passfs
https://menxit.github.io/passfs/releases/latest.txt
https://menxit.github.io/passfs/releases/latest/PassFS-macos-universal.pkg
https://menxit.github.io/passfs/releases/latest/passfs-linux-x64.gz
https://menxit.github.io/passfs/releases/latest/passfs-linux-arm64.gz
https://menxit.github.io/passfs/releases/latest/SHA256SUMS
https://menxit.github.io/passfs/releases/vX.Y.Z/SHA256SUMS
https://menxit.github.io/passfs/releases/vX.Y.Z/passfs-linux-x64.gz
https://menxit.github.io/passfs/releases/vX.Y.Z/passfs-linux-arm64.gz
https://menxit.github.io/passfs/releases/vX.Y.Z/PassFS-macos-universal.pkg
```
