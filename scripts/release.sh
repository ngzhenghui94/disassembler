#!/bin/sh
# Builds Disassembler.app, signs it with Developer ID (hardened runtime), notarizes and staples it,
# and writes build/Disassembler-<version>.zip. Pass --publish to create the GitHub release too.
# Env: DEVELOPER_ID (certificate SHA-1; default: the latest-expiring Developer ID Application identity),
#      NOTARY_PROFILE (notarytool keychain profile, default "notary").
set -eu
cd "$(dirname "$0")/.."

VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" Info.plist)
APP=build/Disassembler.app
ZIP=build/Disassembler-$VERSION.zip
PROFILE=${NOTARY_PROFILE:-notary}

if [ -z "${DEVELOPER_ID:-}" ]; then
  # The same identity can be installed twice; pick the copy that expires last.
  DEVELOPER_ID=$(security find-certificate -a -Z -p -c "Developer ID Application" | python3 -c '
import re, subprocess, sys
from datetime import datetime
best = None
for pem in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", sys.stdin.read(), re.S):
    out = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha1", "-enddate"], input=pem.encode(), capture_output=True, text=False).stdout.decode()
    sha = re.search(r"Fingerprint=([0-9A-F:]+)", out).group(1).replace(":", "")
    end = datetime.strptime(re.search(r"notAfter=(.*)", out).group(1).strip(), "%b %d %H:%M:%S %Y %Z")
    if best is None or end > best[1]:
        best = (sha, end)
print(best[0] if best else "")')
fi
[ -n "$DEVELOPER_ID" ] || { echo "No Developer ID Application certificate found" >&2; exit 1; }
security find-identity -v -p codesigning | grep -q "$DEVELOPER_ID" || { echo "Certificate $DEVELOPER_ID has no usable private key" >&2; exit 1; }

./build.sh

# Nested executables first, then the bundle; --deep is not used for signing.
for target in "$APP/Contents/MacOS/disasm-mcp" "$APP"; do
  codesign --force --timestamp --options runtime --sign "$DEVELOPER_ID" "$target"
done
codesign --verify --deep --strict --verbose=2 "$APP"

SUBMISSION=build/Disassembler-$VERSION-submission.zip
rm -f "$SUBMISSION" "$ZIP"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$SUBMISSION"
xcrun notarytool submit "$SUBMISSION" --keychain-profile "$PROFILE" --wait
rm -f "$SUBMISSION"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
shasum -a 256 "$ZIP"

if [ "${1:-}" = "--publish" ]; then
  gh release create "v$VERSION" "$ZIP" --title "Disassembler $VERSION" --notes-file - <<EOF
Developer ID signed, Apple-notarized and stapled build for macOS 14+.

Unzip and move **Disassembler.app** to /Applications. Xcode or the Command Line Tools must be installed
(the app uses the system \`otool\`, \`atos\` and LLDB).

SHA-256: \`$(shasum -a 256 "$ZIP" | cut -d' ' -f1)\`
EOF
fi
