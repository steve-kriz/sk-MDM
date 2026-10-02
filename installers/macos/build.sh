#!/bin/sh
# Builds the signed macOS agent package.
#
#   MDM_SIGN_IDENTITY="Developer ID Installer: OfficeHQ (TEAMID)" \
#     installers/macos/build.sh --version 1.2.3 --arch arm64 \
#       --collection-url https://mdm.example/ --enroll-token t1
#
# pkgbuild, productbuild and productsign ship with Xcode's command line tools
# and exist on no other platform, so this script runs on a Mac only. Every path
# and every decision it makes comes from build-plan.mjs instead, which is
# covered by `node --test` everywhere.
set -e

VERSION=""
ARCH=""
COLLECTION_URL=""
ENROLL_TOKEN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --collection-url) COLLECTION_URL="$2"; shift 2 ;;
    --enroll-token) ENROLL_TOKEN="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

HERE="$(dirname "$0")"
ROOT="$(cd "$HERE/../.." && pwd)"

# The planner prints the four paths, one per line, and refuses the build before
# anything is staged: exit 2 for a collection URL the agent would not load or
# an architecture it is not built for, exit 3 for an unset MDM_SIGN_IDENTITY.
PLAN="$(node "$(dirname "$0")/build-plan.mjs" --version "$VERSION" --arch "$ARCH" --collection-url "$COLLECTION_URL" --enroll-token "$ENROLL_TOKEN")"

STAGED_BINARY="$ROOT/$(printf '%s\n' "$PLAN" | sed -n '1p')"
STAGED_PLIST="$ROOT/$(printf '%s\n' "$PLAN" | sed -n '2p')"
UNSIGNED_PKG="$ROOT/$(printf '%s\n' "$PLAN" | sed -n '3p')"
OUTPUT_PKG="$ROOT/$(printf '%s\n' "$PLAN" | sed -n '4p')"

# A stale staging root would be packaged along with this build, so it goes.
rm -rf "$ROOT/build/root" "$ROOT/build/scripts"
mkdir -p "$(dirname "$STAGED_BINARY")" "$(dirname "$STAGED_PLIST")" "$ROOT/build/scripts" "$(dirname "$UNSIGNED_PKG")" "$(dirname "$OUTPUT_PKG")"

cp "$ROOT/agent/bin/mdmagent-darwin-$ARCH" "$STAGED_BINARY"
chmod 755 "$STAGED_BINARY"

cp "$HERE/uninstall.sh" "$(dirname "$STAGED_BINARY")/mdmagent-uninstall.sh"
chmod 755 "$(dirname "$STAGED_BINARY")/mdmagent-uninstall.sh"

# The LaunchDaemon the package installs. It is the plist
# agent/internal/service/launchd.go renders: same label, same `run` verb, same
# log paths, so an agent installed by this package and one installed by
# `mdmagent install-service` are the same daemon.
cat > "$STAGED_PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>au.com.officehq.mdmagent</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/mdmagent</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/Library/Logs/OfficeHQ/mdmagent.out.log</string>
	<key>StandardErrorPath</key>
	<string>/Library/Logs/OfficeHQ/mdmagent.err.log</string>
</dict>
</plist>
PLIST
chmod 644 "$STAGED_PLIST"

# The enrolment values reach the installed machine as the config postinstall
# writes, so they are substituted into the staged copy of that script and never
# into the one in version control.
sed -e "s|__COLLECTION_URL__|$COLLECTION_URL|g" -e "s|__ENROLL_TOKEN__|$ENROLL_TOKEN|g" "$HERE/scripts/postinstall" > "$ROOT/build/scripts/postinstall"
cp "$HERE/scripts/preinstall" "$ROOT/build/scripts/preinstall"
chmod 755 "$ROOT/build/scripts/postinstall" "$ROOT/build/scripts/preinstall"

pkgbuild \
  --root "$ROOT/build/root" \
  --scripts "$ROOT/build/scripts" \
  --identifier au.com.officehq.mdm.agent \
  --version "$VERSION" \
  --ownership recommended \
  --install-location / \
  "$ROOT/build/component.pkg"

productbuild \
  --distribution "$HERE/distribution.xml" \
  --package-path "$ROOT/build" \
  "$UNSIGNED_PKG"

productsign --sign "$MDM_SIGN_IDENTITY" "$UNSIGNED_PKG" "$OUTPUT_PKG"

# Notarisation is the manual step after this script, on a Mac holding the
# notary credentials:
#
#   xcrun notarytool submit "$OUTPUT_PKG" --keychain-profile officehq --wait
#   xcrun stapler staple "$OUTPUT_PKG"

echo "built $OUTPUT_PKG"
