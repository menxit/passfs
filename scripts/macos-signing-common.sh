#!/bin/sh

# Shared provisioning-profile checks for the signed macOS app and FSKit
# extension builds. The caller owns temporary files and cleanup.

passfs_decode_provisioning_profile()
(
	profile=$1
	profile_plist=$2
	security cms -D -i "$profile" >"$profile_plist"
)

passfs_profile_team_identifier()
(
	/usr/libexec/PlistBuddy -c "Print :TeamIdentifier:0" "$1"
)

passfs_assert_profile_app_id()
(
	profile_plist=$1
	team_identifier=$2
	bundle_identifier=$3
	description=$4
	application_identifier=$(
		/usr/libexec/PlistBuddy \
			-c "Print :Entitlements:com.apple.application-identifier" \
			"$profile_plist"
	)
	if [ "$application_identifier" != "$team_identifier.$bundle_identifier" ]; then
		echo "$description App ID is $application_identifier, want $team_identifier.$bundle_identifier" >&2
		exit 1
	fi
)

passfs_assert_profile_keychain_group()
(
	profile_plist=$1
	team_identifier=$2
	keychain_group=$3
	description=$4
	if ! /usr/libexec/PlistBuddy \
		-c "Print :Entitlements:keychain-access-groups" \
		"$profile_plist" |
		grep -F \
			-e "$team_identifier.*" \
			-e "$team_identifier.$keychain_group" >/dev/null; then
		echo "$description does not authorize the passfs Keychain access group" >&2
		exit 1
	fi
)

passfs_assert_profile_boolean_entitlement()
(
	profile_plist=$1
	entitlement=$2
	description=$3
	if [ "$(
		/usr/libexec/PlistBuddy \
			-c "Print :Entitlements:$entitlement" \
			"$profile_plist" 2>/dev/null || true
	)" != "true" ]; then
		echo "$description does not authorize $entitlement" >&2
		exit 1
	fi
)

passfs_resolve_signing_identity()
(
	profile_plist=$1
	requested_identity=$2
	profile_certificate=$3
	if [ "$requested_identity" = "auto" ]; then
		plutil -extract DeveloperCertificates.0 raw "$profile_plist" |
			base64 -D >"$profile_certificate"
		requested_identity=$(
			shasum "$profile_certificate" |
				awk '{ print toupper($1) }'
		)
	fi
	if ! security find-identity -v -p codesigning |
		grep -Fq "$requested_identity"; then
		echo "the profile signing identity is not available in the login Keychain" >&2
		exit 1
	fi
	printf '%s\n' "$requested_identity"
)
