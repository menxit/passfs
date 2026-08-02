#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: verify-macos-app.sh PassFS.app" >&2
	exit 2
fi
if [ "$(uname -s)" != "Darwin" ]; then
	echo "PassFS app verification requires macOS" >&2
	exit 2
fi

app=$1
control_service="$app/Contents/Helpers/PassFSControlService.app"
helper="$control_service/Contents/Helpers/PassFSCLI.bundle"
extension="$app/Contents/Extensions/PassFSFileSystem.appex"
agent_plist="$control_service/Contents/Library/LaunchAgents/com.menxit.passfs.control-agent.plist"
temporary=$(
	/usr/bin/mktemp -d "${TMPDIR:-/tmp}/passfs-app-verification.XXXXXX"
)
cleanup()
{
	/bin/rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM

fail()
{
	echo "PassFS app verification failed: $*" >&2
	exit 1
}

for required in \
	"$app" "$control_service" "$helper" "$extension" "$agent_plist"; do
	[ -e "$required" ] || fail "missing $required"
done

/usr/bin/codesign --verify --deep --strict --verbose=2 "$app"

signature_value()
{
	target=$1
	key=$2
	details=$(/usr/bin/codesign -d --verbose=4 "$target" 2>&1) ||
		fail "cannot inspect signature for $target"
	value=$(printf '%s\n' "$details" | /usr/bin/sed -n "s/^${key}=//p" | /usr/bin/head -n 1)
	[ -n "$value" ] || fail "signature for $target has no $key"
	printf '%s\n' "$value"
}

extract_entitlements()
{
	target=$1
	output=$2
	/usr/bin/codesign -d --entitlements :- "$target" >"$output" 2>/dev/null ||
		fail "cannot read entitlements for $target"
	/usr/bin/plutil -lint "$output" >/dev/null ||
		fail "invalid signed entitlements for $target"
}

entitlement_value()
{
	file=$1
	key=$2
	/usr/libexec/PlistBuddy -c "Print :$key" "$file" 2>/dev/null
}

require_entitlement()
{
	file=$1
	key=$2
	expected=$3
	actual=$(entitlement_value "$file" "$key") ||
		fail "missing signed entitlement $key"
	[ "$actual" = "$expected" ] ||
		fail "signed entitlement $key is $actual, expected $expected"
}

reject_entitlement()
{
	file=$1
	key=$2
	if entitlement_value "$file" "$key" >/dev/null 2>&1; then
		fail "unexpected signed entitlement $key"
	fi
}

app_identifier=$(signature_value "$app" Identifier)
control_service_identifier=$(signature_value "$control_service" Identifier)
helper_identifier=$(signature_value "$helper" Identifier)
extension_identifier=$(signature_value "$extension" Identifier)
team_identifier=$(signature_value "$app" TeamIdentifier)

[ "$app_identifier" = "com.menxit.passfs" ] ||
	fail "app identifier is $app_identifier"
[ "$control_service_identifier" = "com.menxit.passfs.control-service" ] ||
	fail "control service identifier is $control_service_identifier"
[ "$helper_identifier" = "com.menxit.passfs" ] ||
	fail "helper identifier is $helper_identifier"
[ "$extension_identifier" = "com.menxit.passfs.filesystem" ] ||
	fail "extension identifier is $extension_identifier"
[ "$team_identifier" != "not set" ] || fail "app has no Developer ID team"
[ "$(signature_value "$control_service" TeamIdentifier)" = "$team_identifier" ] ||
	fail "control service is signed by a different team"
[ "$(signature_value "$helper" TeamIdentifier)" = "$team_identifier" ] ||
	fail "helper is signed by a different team"
[ "$(signature_value "$extension" TeamIdentifier)" = "$team_identifier" ] ||
	fail "extension is signed by a different team"

for target in "$app" "$control_service" "$helper" "$extension"; do
	details=$(/usr/bin/codesign -d --verbose=4 "$target" 2>&1) ||
		fail "cannot inspect hardened runtime for $target"
	case "$details" in
		*flags=*runtime*) ;;
		*) fail "$target does not use the hardened runtime" ;;
	esac
done

app_entitlements="$temporary/app.plist"
helper_entitlements="$temporary/helper.plist"
extension_entitlements="$temporary/extension.plist"
extract_entitlements "$app" "$app_entitlements"
extract_entitlements "$helper" "$helper_entitlements"
extract_entitlements "$extension" "$extension_entitlements"

app_group="$team_identifier.com.menxit.passfs.shared"
require_entitlement "$app_entitlements" \
	"com.apple.application-identifier" \
	"$team_identifier.com.menxit.passfs"
require_entitlement "$app_entitlements" \
	"com.apple.security.app-sandbox" "true"
require_entitlement "$app_entitlements" \
	"com.apple.security.files.user-selected.read-write" "true"
require_entitlement "$app_entitlements" \
	"com.apple.security.application-groups:0" "$app_group"
require_entitlement "$app_entitlements" \
	"com.apple.developer.fskit.mount" "true"
reject_entitlement "$app_entitlements" "com.apple.security.network.client"

require_entitlement "$helper_entitlements" \
	"com.apple.application-identifier" \
	"$team_identifier.com.menxit.passfs"
require_entitlement "$helper_entitlements" \
	"com.apple.security.application-groups:0" "$app_group"
require_entitlement "$helper_entitlements" \
	"com.apple.developer.fskit.mount" "true"
reject_entitlement "$helper_entitlements" "com.apple.security.app-sandbox"
reject_entitlement "$helper_entitlements" "com.apple.security.network.client"

require_entitlement "$extension_entitlements" \
	"com.apple.application-identifier" \
	"$team_identifier.com.menxit.passfs.filesystem"
require_entitlement "$extension_entitlements" \
	"com.apple.security.app-sandbox" "true"
require_entitlement "$extension_entitlements" \
	"com.apple.security.application-groups:0" "$app_group"
reject_entitlement "$extension_entitlements" "com.apple.security.network.client"

require_plist_value()
{
	key=$1
	expected=$2
	actual=$(/usr/libexec/PlistBuddy -c "Print :$key" "$agent_plist" 2>/dev/null) ||
		fail "control agent plist has no $key"
	[ "$actual" = "$expected" ] ||
		fail "control agent plist $key is $actual, expected $expected"
}

require_plist_value "Label" "com.menxit.passfs.control-agent"
require_plist_value \
	"BundleProgram" \
	"Contents/Helpers/PassFSCLI.bundle/Contents/MacOS/passfs-cli"
require_plist_value "ProgramArguments:1" "__app-agent"
require_plist_value "RunAtLoad" "true"
require_plist_value "KeepAlive" "true"

[ -x "$control_service/Contents/MacOS/passfs-control-service" ] ||
	fail "control service executable is missing"
[ ! -e "$app/Contents/Library/LaunchAgents/com.menxit.passfs.control-agent.plist" ] ||
	fail "sandboxed app must not own the control-agent registration plist"

echo "Verified signed PassFS app security boundaries: $app"
